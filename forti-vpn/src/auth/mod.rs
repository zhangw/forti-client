pub mod xml;

use crate::error::{FortiError, Result};
use std::sync::Arc;
use tracing::{info, debug};

#[derive(Debug)]
pub struct AuthResult {
    pub svpn_cookie: String,
    pub tunnel_config: xml::TunnelConfig,
}

pub struct AuthClient {
    server: String,
    port: u16,
    tls_config: Arc<rustls::ClientConfig>,
}

impl AuthClient {
    pub fn new(server: &str, port: u16) -> Result<Self> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Self {
            server: server.to_string(),
            port,
            tls_config: Arc::new(tls_config),
        })
    }

    pub async fn login(&self, username: &str, password: &str, realm: Option<&str>) -> Result<AuthResult> {
        let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone());
        let server_name = rustls::pki_types::ServerName::try_from(self.server.clone())
            .map_err(|e| FortiError::TunnelError(format!("invalid server name: {}", e)))?;

        let tcp = tokio::net::TcpStream::connect(format!("{}:{}", self.server, self.port)).await?;
        let tls = connector.connect(server_name.clone(), tcp).await
            .map_err(|e| FortiError::TunnelError(format!("TLS connect failed: {}", e)))?;

        let io = hyper_util::rt::TokioIo::new(tls);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await
            .map_err(|e| FortiError::TunnelError(format!("HTTP handshake failed: {}", e)))?;

        tokio::spawn(conn);

        // Step 1: POST /remote/logincheck
        let body = if let Some(realm) = realm {
            format!(
                "ajax=1&username={}&credential={}&realm={}&just_logged_in=1",
                urlencoded(username), urlencoded(password), urlencoded(realm),
            )
        } else {
            format!(
                "ajax=1&username={}&credential={}&just_logged_in=1",
                urlencoded(username), urlencoded(password),
            )
        };

        let req = hyper::Request::builder()
            .method("POST")
            .uri("/remote/logincheck")
            .header("Host", &self.server)
            .header("User-Agent", "Mozilla/5.0 SV1")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Content-Length", body.len())
            .body(http_body_util::Full::new(bytes::Bytes::from(body)))
            .map_err(FortiError::Http)?;

        info!("Sending login request");
        let resp = sender.send_request(req).await
            .map_err(|e| FortiError::TunnelError(format!("login request failed: {}", e)))?;

        debug!("Login response status: {}", resp.status());

        let svpn_cookie = resp.headers()
            .get_all("set-cookie")
            .iter()
            .find_map(|v| {
                let s = v.to_str().ok()?;
                if s.starts_with("SVPNCOOKIE=") {
                    let val = s.split(';').next()?;
                    Some(val.trim_start_matches("SVPNCOOKIE=").to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| FortiError::AuthFailed("no SVPNCOOKIE in login response".into()))?;

        info!("Authentication successful, got SVPNCOOKIE");

        // Step 2: GET /remote/fortisslvpn_xml
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/remote/fortisslvpn_xml?dual_stack=1")
            .header("Host", &self.server)
            .header("User-Agent", "Mozilla/5.0 SV1")
            .header("Cookie", format!("SVPNCOOKIE={}", svpn_cookie))
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .map_err(FortiError::Http)?;

        debug!("Fetching tunnel configuration");
        let resp = sender.send_request(req).await
            .map_err(|e| FortiError::TunnelError(format!("XML config request failed: {}", e)))?;

        let body = http_body_util::BodyExt::collect(resp.into_body()).await
            .map_err(|e| FortiError::TunnelError(format!("failed to read XML body: {}", e)))?;
        let body_bytes = body.to_bytes();
        let xml_text = String::from_utf8_lossy(&body_bytes);

        let tunnel_config = xml::TunnelConfig::parse(&xml_text)?;
        info!("Tunnel config: IP={}, DNS={:?}", tunnel_config.ip_address, tunnel_config.dns_servers);

        Ok(AuthResult { svpn_cookie, tunnel_config })
    }

    pub fn server(&self) -> &str { &self.server }
    pub fn port(&self) -> u16 { self.port }
    pub fn tls_config(&self) -> Arc<rustls::ClientConfig> { self.tls_config.clone() }
}

fn urlencoded(s: &str) -> String {
    let mut result = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => { result.push_str(&format!("%{:02X}", b)); }
        }
    }
    result
}
