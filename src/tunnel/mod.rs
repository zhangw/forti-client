pub mod codec;

use crate::error::{FortiError, Result};
use codec::{FortinetCodec, FortinetFrame};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

fn post_upgrade_error(error: FortiError) -> FortiError {
    match error {
        FortiError::CookieRejected(_)
        | FortiError::TransportUnavailable(_)
        | FortiError::PostUpgradeNegotiation(_) => error,
        other => FortiError::PostUpgradeNegotiation(other.to_string()),
    }
}
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const INITIAL_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_HTTP_HEADER: usize = 16 * 1024;

/// A raw TLS tunnel to the FortiGate, carrying Fortinet-framed PPP data.
pub struct TlsTunnel {
    tls_stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    codec: FortinetCodec,
    read_buf: Vec<u8>,
    recv_tmp: Vec<u8>,
    /// The server is allowed to send its HTTP upgrade response after connect()
    /// returns. Keep inspecting the prefix until HTTP or Fortinet framing wins.
    upgrade_response_pending: bool,
}

impl TlsTunnel {
    /// Connect the tunnel. When `server_addr` is set the TCP connection goes
    /// straight to that address, bypassing the system resolver; `server` is
    /// still used for SNI and certificate validation.
    pub async fn connect(
        server: &str,
        port: u16,
        server_addr: Option<SocketAddr>,
        svpn_cookie: &str,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Result<Self> {
        tokio::time::timeout(
            CONNECT_TIMEOUT,
            Self::connect_inner(server, port, server_addr, svpn_cookie, tls_config),
        )
        .await
        .map_err(|_| {
            FortiError::TransportUnavailable("TLS tunnel connect timed out after 30s".into())
        })?
    }

    async fn connect_inner(
        server: &str,
        port: u16,
        server_addr: Option<SocketAddr>,
        svpn_cookie: &str,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Result<Self> {
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        let server_name = rustls::pki_types::ServerName::try_from(server.to_string())
            .map_err(|e| FortiError::TransportUnavailable(format!("invalid server name: {}", e)))?;

        let tcp = match server_addr {
            Some(addr) => tokio::net::TcpStream::connect(addr).await,
            None => tokio::net::TcpStream::connect(format!("{}:{}", server, port)).await,
        }
        .map_err(|e| FortiError::TransportUnavailable(format!("TCP connect failed: {}", e)))?;
        tcp.set_nodelay(true).map_err(|e| {
            FortiError::TransportUnavailable(format!("failed to configure TCP socket: {}", e))
        })?;
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| FortiError::TransportUnavailable(format!("TLS connect failed: {}", e)))?;

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

        if tracing::enabled!(tracing::Level::DEBUG) {
            let redacted_req = http_req
                .lines()
                .map(|line| {
                    if line.trim_start().starts_with("Cookie: SVPNCOOKIE=") {
                        "Cookie: SVPNCOOKIE=<redacted>"
                    } else {
                        line
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            debug!("Tunnel request:\n{}", redacted_req.trim());
        }
        tls.write_all(http_req.as_bytes()).await.map_err(|e| {
            FortiError::TransportUnavailable(format!("tunnel request write failed: {}", e))
        })?;
        tls.flush().await.map_err(|e| {
            FortiError::TransportUnavailable(format!("tunnel request flush failed: {}", e))
        })?;
        info!("Sent tunnel upgrade request");

        let mut read_buf = Vec::new();
        let mut response_buf = vec![0u8; 4096];
        let mut upgrade_response_pending = true;
        match tokio::time::timeout(INITIAL_RESPONSE_TIMEOUT, tls.read(&mut response_buf)).await {
            Ok(Ok(0)) => {
                return Err(FortiError::PostUpgradeNegotiation(
                    "connection closed after tunnel request".into(),
                ));
            }
            Ok(Ok(n)) => {
                read_buf.extend_from_slice(&response_buf[..n]);
                upgrade_response_pending =
                    process_upgrade_response(&mut read_buf).map_err(post_upgrade_error)?;
                debug!("Tunnel received {} initial bytes", n);
            }
            Ok(Err(e)) => {
                return Err(FortiError::PostUpgradeNegotiation(format!(
                    "tunnel read error: {}",
                    e
                )));
            }
            Err(_) => {
                // Some FortiGates wait for the first LCP packet. recv_frame() will
                // still recognize a delayed HTTP rejection before decoding PPP.
                info!("Tunnel server awaiting client LCP");
            }
        }

        info!("TLS tunnel ready, {} buffered bytes", read_buf.len());
        Ok(Self {
            tls_stream: tls,
            codec: FortinetCodec::new(),
            read_buf,
            recv_tmp: vec![0u8; 4096],
            upgrade_response_pending,
        })
    }

    pub async fn send_frame(&mut self, ppp_payload: Vec<u8>) -> Result<()> {
        let frame = FortinetFrame::new(ppp_payload);
        let wire = frame.encode();
        tokio::time::timeout(IO_TIMEOUT, async {
            self.tls_stream.write_all(&wire).await?;
            self.tls_stream.flush().await
        })
        .await
        .map_err(|_| FortiError::TunnelError("tunnel write timed out after 10s".into()))??;
        Ok(())
    }

    pub async fn recv_frame(&mut self) -> Result<FortinetFrame> {
        loop {
            if self.upgrade_response_pending {
                self.upgrade_response_pending = process_upgrade_response(&mut self.read_buf)?;
            }
            if !self.upgrade_response_pending {
                if let Some(frame) = self.codec.try_decode(&mut self.read_buf) {
                    return Ok(frame);
                }
            }

            let n = self.tls_stream.read(&mut self.recv_tmp).await?;
            if n == 0 {
                return Err(FortiError::TunnelClosed);
            }
            self.read_buf.extend_from_slice(&self.recv_tmp[..n]);
            if self.read_buf.len() > MAX_HTTP_HEADER && self.upgrade_response_pending {
                return Err(FortiError::ProtocolError(
                    "tunnel HTTP response header exceeds 16 KiB".into(),
                ));
            }
        }
    }
}

/// Inspect and, when complete, remove an HTTP tunnel-upgrade response.
/// Returns true while more bytes are needed to decide.
fn header_points_to_auth(header: &[u8]) -> bool {
    let text = String::from_utf8_lossy(header);
    text.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        if !name.trim().eq_ignore_ascii_case("location") {
            return false;
        }

        let location = value.trim();
        let path = if location.starts_with('/') && !location.starts_with("//") {
            location
        } else if let Some(scheme) = location.find("://") {
            let authority = &location[scheme + 3..];
            authority
                .find('/')
                .map(|slash| &authority[slash..])
                .unwrap_or("/")
        } else if let Some(authority) = location.strip_prefix("//") {
            authority
                .find('/')
                .map(|slash| &authority[slash..])
                .unwrap_or("/")
        } else {
            return false;
        };

        ["/remote/login", "/remote/saml"].iter().any(|prefix| {
            path == *prefix
                || path.strip_prefix(prefix).is_some_and(|rest| {
                    rest.starts_with('/') || rest.starts_with('?') || rest.starts_with('#')
                })
        })
    })
}

fn process_upgrade_response(buf: &mut Vec<u8>) -> Result<bool> {
    if buf.is_empty() {
        return Ok(true);
    }

    const HTTP_PREFIX: &[u8] = b"HTTP/";
    let prefix_len = buf.len().min(HTTP_PREFIX.len());
    if buf[..prefix_len] != HTTP_PREFIX[..prefix_len] {
        return Ok(false); // Fortinet framing, not HTTP
    }
    if buf.len() < HTTP_PREFIX.len() {
        return Ok(true);
    }

    let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        if buf.len() > MAX_HTTP_HEADER {
            return Err(FortiError::ProtocolError(
                "tunnel HTTP response header exceeds 16 KiB".into(),
            ));
        }
        return Ok(true);
    };
    let header_len = header_end + 4;
    if header_len > MAX_HTTP_HEADER {
        return Err(FortiError::ProtocolError(
            "tunnel HTTP response header exceeds 16 KiB".into(),
        ));
    }
    let status_line_end = buf
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| FortiError::ProtocolError("malformed tunnel HTTP response".into()))?;
    let status_line = String::from_utf8_lossy(&buf[..status_line_end]);
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| FortiError::ProtocolError("invalid tunnel HTTP status".into()))?;

    let auth_redirect = (300..400).contains(&status) && header_points_to_auth(&buf[..header_len]);
    if status == 401 || status == 403 || auth_redirect {
        return Err(FortiError::CookieRejected(status));
    }
    if !(200..300).contains(&status) {
        return Err(FortiError::TransportUnavailable(format!(
            "tunnel upgrade failed with HTTP {}",
            status
        )));
    }

    buf.drain(..header_len);
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_http_prefix_needs_more_data() {
        let mut buf = b"HT".to_vec();
        assert!(process_upgrade_response(&mut buf).unwrap());
    }

    #[test]
    fn successful_upgrade_strips_headers_and_keeps_ppp() {
        let mut buf = b"HTTP/1.1 200 OK\r\nX-Test: yes\r\n\r\n\x00\x08PP\x00\x02ab".to_vec();
        assert!(!process_upgrade_response(&mut buf).unwrap());
        assert_eq!(buf, b"\x00\x08PP\x00\x02ab");
    }

    #[test]
    fn forbidden_upgrade_is_typed_cookie_rejection() {
        let mut buf = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec();
        assert!(matches!(
            process_upgrade_response(&mut buf),
            Err(FortiError::CookieRejected(403))
        ));
    }

    #[test]
    fn unauthorized_upgrade_is_typed_cookie_rejection() {
        let mut buf = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n".to_vec();
        assert!(matches!(
            process_upgrade_response(&mut buf),
            Err(FortiError::CookieRejected(401))
        ));
    }

    #[test]
    fn oversized_complete_upgrade_header_is_rejected() {
        let mut buf = b"HTTP/1.1 200 OK\r\nX-Fill: ".to_vec();
        buf.extend(std::iter::repeat_n(b'a', MAX_HTTP_HEADER));
        buf.extend_from_slice(b"\r\n\r\n");
        assert!(matches!(
            process_upgrade_response(&mut buf),
            Err(FortiError::ProtocolError(_))
        ));
    }

    #[test]
    fn auth_redirects_are_typed_cookie_rejections() {
        for location in [
            "/remote/login",
            "/remote/login?lang=en",
            "https://vpn.example/remote/saml/start?redirect=1",
        ] {
            let mut buf =
                format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\n\r\n").into_bytes();
            assert!(matches!(
                process_upgrade_response(&mut buf),
                Err(FortiError::CookieRejected(302))
            ));
        }
    }

    #[test]
    fn non_auth_redirect_is_transport_unavailable() {
        let mut buf = b"HTTP/1.1 302 Found\r\nLocation: /maintenance\r\n\r\n".to_vec();
        assert!(matches!(
            process_upgrade_response(&mut buf),
            Err(FortiError::TransportUnavailable(_))
        ));
    }

    #[test]
    fn lookalike_login_redirect_is_not_cookie_rejection() {
        let mut buf =
            b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /remote/logincheck\r\n\r\n".to_vec();
        assert!(matches!(
            process_upgrade_response(&mut buf),
            Err(FortiError::TransportUnavailable(_))
        ));
    }

    #[test]
    fn throttling_and_server_failures_remain_transport_unavailable() {
        for status in [400, 429, 500, 502, 503] {
            let mut buf =
                format!("HTTP/1.1 {status} Failure\r\nContent-Length: 0\r\n\r\n").into_bytes();
            let error = process_upgrade_response(&mut buf).unwrap_err();
            assert!(matches!(error, FortiError::TransportUnavailable(_)));
            assert!(matches!(
                post_upgrade_error(error),
                FortiError::TransportUnavailable(_)
            ));
        }
    }

    #[test]
    fn binary_prefix_is_not_consumed() {
        let original = b"\x00\x08PP\x00\x02ab".to_vec();
        let mut buf = original.clone();
        assert!(!process_upgrade_response(&mut buf).unwrap());
        assert_eq!(buf, original);
    }
}
