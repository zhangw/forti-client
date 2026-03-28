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
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| FortiError::TunnelError(format!("TLS connect failed: {}", e)))?;

        let http_req = format!(
            "GET /remote/sslvpn-tunnel HTTP/1.1\r\n\
             Host: {}\r\n\
             Cookie: SVPNCOOKIE={}\r\n\
             \r\n",
            server, svpn_cookie,
        );

        tls.write_all(http_req.as_bytes()).await?;
        tls.flush().await?;

        info!("Sent tunnel upgrade request");

        // After sending the tunnel request, read the first bytes.
        // Per the FortiGate wire protocol spec: on success, the server sends NO
        // HTTP response — the connection silently transitions to raw binary PPP
        // framing. Only on failure does the server send an HTTP error response.
        let mut response_buf = vec![0u8; 4096];
        let n = tls.read(&mut response_buf).await?;
        if n == 0 {
            return Err(FortiError::TunnelError(
                "connection closed after tunnel request".into(),
            ));
        }

        let leftover = if response_buf[..n].starts_with(b"HTTP/") {
            // Error: server sent an HTTP response instead of transitioning to tunnel
            let response_str = String::from_utf8_lossy(&response_buf[..n]);
            return Err(FortiError::TunnelError(format!(
                "tunnel upgrade failed: {}",
                response_str.lines().next().unwrap_or("empty response"),
            )));
        } else {
            // Success: these are the first bytes of binary PPP tunnel data
            debug!(
                "Tunnel active — received {} bytes of initial PPP data",
                n
            );
            response_buf[..n].to_vec()
        };

        info!(
            "TLS tunnel established, {} bytes of initial data",
            leftover.len()
        );

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
