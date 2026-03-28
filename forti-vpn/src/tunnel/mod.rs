pub mod codec;

use crate::error::{FortiError, Result};
use codec::{FortinetCodec, FortinetFrame};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

/// A raw TLS tunnel to the FortiGate, carrying Fortinet-framed PPP data.
pub struct TlsTunnel {
    tls_stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    codec: FortinetCodec,
    read_buf: Vec<u8>,
}

impl TlsTunnel {
    pub async fn connect(
        server: &str,
        port: u16,
        svpn_cookie: &str,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Result<Self> {
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        let server_name = rustls::pki_types::ServerName::try_from(server.to_string())
            .map_err(|e| FortiError::TunnelError(format!("invalid server name: {}", e)))?;

        let tcp = tokio::net::TcpStream::connect(format!("{}:{}", server, port)).await?;
        // Set TCP_NODELAY to avoid Nagle buffering
        tcp.set_nodelay(true)?;
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| FortiError::TunnelError(format!("TLS connect failed: {}", e)))?;

        // Use HTTP/1.1 per the spec, with headers matching openfortivpn
        let http_req = format!(
            "GET /remote/sslvpn-tunnel HTTP/1.1\r\n\
             Host: {}:{}\r\n\
             User-Agent: Mozilla/5.0 SV1\r\n\
             Accept: */*\r\n\
             Accept-Encoding: identity\r\n\
             Pragma: no-cache\r\n\
             Cache-Control: no-store, no-cache, must-revalidate\r\n\
             Cookie: SVPNCOOKIE={}\r\n\
             Content-Length: 0\r\n\
             \r\n",
            server, port, svpn_cookie,
        );

        debug!("Tunnel request:\n{}", http_req.trim());
        tls.write_all(http_req.as_bytes()).await?;
        tls.flush().await?;

        info!("Sent tunnel upgrade request");

        // Don't wait for the server to send first — some FortiGates expect the
        // client to initiate PPP. We'll do a short non-blocking check: if the
        // server sends data quickly (HTTP error or LCP packet), read it.
        // Otherwise, assume the tunnel is established and let PPP engine handle it.
        let mut response_buf = vec![0u8; 4096];
        let n = match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tls.read(&mut response_buf),
        ).await {
            Ok(Ok(0)) => {
                return Err(FortiError::TunnelError("connection closed after tunnel request".into()));
            }
            Ok(Ok(n)) => {
                // Got immediate data — check if it's an HTTP error
                if response_buf[..n].starts_with(b"HTTP/") {
                    let response_str = String::from_utf8_lossy(&response_buf[..n]);
                    return Err(FortiError::TunnelError(format!(
                        "tunnel upgrade failed: {}",
                        response_str.lines().next().unwrap_or("empty response"),
                    )));
                }
                debug!("Tunnel active — received {} bytes of initial PPP data", n);
                n
            }
            Ok(Err(e)) => {
                return Err(FortiError::TunnelError(format!("tunnel read error: {}", e)));
            }
            Err(_) => {
                // Timeout — server didn't send anything in 2s.
                // This is OK: tunnel is likely established, server waits for client to speak first.
                info!("Tunnel established (server awaiting client LCP)");
                0
            }
        };

        let leftover = response_buf[..n].to_vec();
        info!("TLS tunnel ready, {} bytes of initial data", leftover.len());

        Ok(Self {
            tls_stream: tls,
            codec: FortinetCodec::new(),
            read_buf: leftover,
        })
    }

    pub async fn send_frame(&mut self, ppp_payload: Vec<u8>) -> Result<()> {
        let frame = FortinetFrame::new(ppp_payload);
        let wire = frame.encode();
        self.tls_stream.write_all(&wire).await?;
        self.tls_stream.flush().await?;
        Ok(())
    }

    pub async fn recv_frame(&mut self) -> Result<FortinetFrame> {
        loop {
            if let Some(frame) = self.codec.try_decode(&mut self.read_buf) {
                return Ok(frame);
            }
            let mut tmp = vec![0u8; 4096];
            let n = self.tls_stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(FortiError::TunnelError("tunnel closed by peer".into()));
            }
            self.read_buf.extend_from_slice(&tmp[..n]);
        }
    }
}
