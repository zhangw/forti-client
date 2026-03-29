pub mod xml;

use crate::error::{FortiError, Result};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, debug, warn};

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

        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Enable SSLKEYLOGFILE for TLS packet analysis (Wireshark)
        tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

        Ok(Self {
            server: server.to_string(),
            port,
            tls_config: Arc::new(tls_config),
        })
    }

    /// Create a new TLS+HTTP connection to the server.
    async fn new_http_connection(&self) -> Result<(
        hyper::client::conn::http1::SendRequest<http_body_util::Full<bytes::Bytes>>,
        tokio_rustls::TlsConnector,
        rustls::pki_types::ServerName<'static>,
    )> {
        let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone());
        let server_name = rustls::pki_types::ServerName::try_from(self.server.clone())
            .map_err(|e| FortiError::TunnelError(format!("invalid server name: {}", e)))?;

        let tcp = tokio::net::TcpStream::connect(format!("{}:{}", self.server, self.port)).await?;
        let tls = connector.connect(server_name.clone(), tcp).await
            .map_err(|e| FortiError::TunnelError(format!("TLS connect failed: {}", e)))?;

        let io = hyper_util::rt::TokioIo::new(tls);
        let (sender, conn) = hyper::client::conn::http1::handshake(io).await
            .map_err(|e| FortiError::TunnelError(format!("HTTP handshake failed: {}", e)))?;

        tokio::spawn(conn);
        Ok((sender, connector, server_name))
    }

    pub async fn login(&self, username: &str, password: &str, realm: Option<&str>) -> Result<AuthResult> {
        // Step 1: POST /remote/logincheck
        let (mut sender, _connector, _server_name) = self.new_http_connection().await?;

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

        let status = resp.status();
        debug!("Login response status: {}", status);

        // Log all Set-Cookie headers for debugging
        for cookie_hdr in resp.headers().get_all("set-cookie").iter() {
            if let Ok(s) = cookie_hdr.to_str() {
                debug!("Set-Cookie: {}", redact_set_cookie(s));
            }
        }

        // Extract SVPNCOOKIE if present
        let svpn_cookie = extract_svpncookie(&resp);

        // Read the response body for 2FA detection
        let resp_body = http_body_util::BodyExt::collect(resp.into_body()).await
            .map_err(|e| FortiError::TunnelError(format!("failed to read login body: {}", e)))?;
        let resp_text = String::from_utf8_lossy(&resp_body.to_bytes()).to_string();

        // Check for 2FA requirement
        let svpn_cookie = if let Some(cookie) = svpn_cookie {
            // Got cookie — but check if 2FA is still needed
            // Some FortiGates return a partial cookie that requires 2FA completion
            if resp_text.contains("tokeninfo=") || resp_text.contains("2fa") {
                debug!("Got SVPNCOOKIE but 2FA appears required, proceeding with 2FA");
                self.handle_2fa_tokeninfo(username, &resp_text, Some(&cookie)).await?
            } else {
                info!("Authentication successful, got SVPNCOOKIE");
                cookie
            }
        } else if status.as_u16() == 401 {
            // HTML form-based 2FA
            debug!("401 response — HTML form 2FA");
            self.handle_2fa_html_form(username, &resp_text).await?
        } else if resp_text.contains("ret=") && resp_text.contains("tokeninfo=") {
            // Tokeninfo-based 2FA (200 OK, no cookie)
            debug!("Tokeninfo 2FA challenge detected");
            self.handle_2fa_tokeninfo(username, &resp_text, None).await?
        } else if status.as_u16() == 405 {
            return Err(FortiError::AuthFailed("invalid credentials (405)".into()));
        } else {
            return Err(FortiError::AuthFailed(format!(
                "login failed: status={}", status
            )));
        };

        // Fetch tunnel config
        let tunnel_config = self.fetch_tunnel_config(&svpn_cookie).await?;

        Ok(AuthResult { svpn_cookie, tunnel_config })
    }

    /// Handle tokeninfo-based 2FA (most common).
    /// Response body format: ret=<status>,tokeninfo=<type>,chal_msg=<prompt>,reqid=<id>,polid=<id>,grp=<group>,portal=<portal>,peer=<peer>,magic=<value>
    async fn handle_2fa_tokeninfo(&self, username: &str, resp_text: &str, _existing_cookie: Option<&str>) -> Result<String> {
        // Parse the tokeninfo fields
        let fields = parse_tokeninfo_fields(resp_text);
        let tokeninfo = fields.get("tokeninfo").map(|s| s.as_str()).unwrap_or("unknown");
        let chal_msg = fields.get("chal_msg").map(|s| s.as_str()).unwrap_or("Enter verification code");
        let reqid = fields.get("reqid").map(|s| s.as_str()).unwrap_or("");
        let polid = fields.get("polid").map(|s| s.as_str()).unwrap_or("");
        let grp = fields.get("grp").map(|s| s.as_str()).unwrap_or("");
        let portal = fields.get("portal").map(|s| s.as_str()).unwrap_or("");
        let peer = fields.get("peer").map(|s| s.as_str()).unwrap_or("");
        let magic = fields.get("magic").map(|s| s.as_str()).unwrap_or("");

        info!("2FA required (type: {})", tokeninfo);

        // Check for FortiToken Mobile push
        if tokeninfo == "ftm_push" {
            info!("FortiToken Mobile push notification sent. Waiting for approval...");
            // For push, send with empty code and ftmpush=1
            let body = format!(
                "username={}&code=&reqid={}&polid={}&grp={}&portal={}&peer={}&ftmpush=1",
                urlencoded(username), urlencoded(reqid), urlencoded(polid),
                urlencoded(grp), urlencoded(portal), urlencoded(peer),
            );
            return self.send_2fa_code(&body).await;
        }

        // Prompt user for OTP code
        eprint!("{}: ", chal_msg);
        std::io::Write::flush(&mut std::io::stderr())?;
        let mut code = String::new();
        std::io::stdin().read_line(&mut code)?;
        let code = code.trim();

        let body = format!(
            "username={}&code={}&reqid={}&polid={}&grp={}&portal={}&peer={}&magic={}",
            urlencoded(username), urlencoded(code), urlencoded(reqid),
            urlencoded(polid), urlencoded(grp), urlencoded(portal),
            urlencoded(peer), urlencoded(magic),
        );

        self.send_2fa_code(&body).await
    }

    /// Handle HTML form-based 2FA (401 response).
    async fn handle_2fa_html_form(&self, username: &str, html: &str) -> Result<String> {
        // Extract hidden fields from the HTML form
        let magic = extract_html_field(html, "magic").unwrap_or_default();
        let reqid = extract_html_field(html, "reqid").unwrap_or_default();
        let grpid = extract_html_field(html, "grpid").unwrap_or_default();

        info!("2FA required (HTML form)");
        eprint!("Enter verification code: ");
        std::io::Write::flush(&mut std::io::stderr())?;
        let mut code = String::new();
        std::io::stdin().read_line(&mut code)?;
        let code = code.trim();

        let body = format!(
            "username={}&code={}&reqid={}&grpid={}&magic={}",
            urlencoded(username), urlencoded(code),
            urlencoded(&reqid), urlencoded(&grpid), urlencoded(&magic),
        );

        self.send_2fa_code(&body).await
    }

    /// Send the 2FA verification code and extract SVPNCOOKIE.
    async fn send_2fa_code(&self, body: &str) -> Result<String> {
        let (mut sender, _, _) = self.new_http_connection().await?;

        let req = hyper::Request::builder()
            .method("POST")
            .uri("/remote/logincheck")
            .header("Host", &self.server)
            .header("User-Agent", "Mozilla/5.0 SV1")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Content-Length", body.len())
            .body(http_body_util::Full::new(bytes::Bytes::from(body.to_string())))
            .map_err(FortiError::Http)?;

        debug!("Sending 2FA verification");
        let resp = sender.send_request(req).await
            .map_err(|e| FortiError::TunnelError(format!("2FA request failed: {}", e)))?;

        debug!("2FA response status: {}", resp.status());

        let cookie = extract_svpncookie(&resp)
            .ok_or_else(|| FortiError::AuthFailed("2FA verification failed — no SVPNCOOKIE in response".into()))?;

        info!("2FA verification successful");
        Ok(cookie)
    }

    /// Authenticate via SAML/SSO: open browser, wait for IdP callback, exchange for SVPNCOOKIE.
    pub async fn login_saml(&self) -> Result<AuthResult> {
        let saml_port: u16 = 8020;

        // Step 1: Start local HTTP server to receive the SAML callback
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", saml_port)).await
            .map_err(|e| FortiError::AuthFailed(format!(
                "failed to bind SAML callback on port {}: {} (is another VPN client running?)",
                saml_port, e
            )))?;

        info!("SAML callback server listening on 127.0.0.1:{}", saml_port);

        // Step 2: Open browser to SAML start URL
        let saml_url = format!(
            "https://{}:{}/remote/saml/start?redirect=1",
            self.server, self.port,
        );
        info!("Opening browser for SAML authentication...");
        info!("If browser doesn't open, navigate to: {}", saml_url);

        // When running as root (sudo), `open` uses root's default browser.
        // Use SUDO_USER to open the real user's preferred browser instead.
        let open_result = if let Ok(user) = std::env::var("SUDO_USER") {
            std::process::Command::new("sudo")
                .args(["-u", &user, "open", &saml_url])
                .spawn()
        } else {
            std::process::Command::new("open").arg(&saml_url).spawn()
        };
        if let Err(e) = open_result {
            debug!("Failed to open browser: {}", e);
            eprintln!("\nPlease open this URL in your browser:\n  {}\n", saml_url);
        }

        // Step 3: Wait for the SAML callback with ?id=<session_id>
        info!("Waiting for SAML authentication (complete login in your browser)...");
        let session_id = wait_for_saml_callback(listener).await?;
        info!("SAML callback received, exchanging for session cookie");

        // Step 4: Exchange session ID for SVPNCOOKIE
        let (mut sender, _, _) = self.new_http_connection().await?;

        let req = hyper::Request::builder()
            .method("GET")
            .uri(format!("/remote/saml/auth_id?id={}", urlencoded(&session_id)))
            .header("Host", &self.server)
            .header("User-Agent", "Mozilla/5.0 SV1")
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .map_err(FortiError::Http)?;

        debug!("Exchanging SAML session ID for SVPNCOOKIE");
        let resp = sender.send_request(req).await
            .map_err(|e| FortiError::TunnelError(format!("SAML auth_id request failed: {}", e)))?;

        debug!("SAML auth_id response status: {}", resp.status());
        for cookie_hdr in resp.headers().get_all("set-cookie").iter() {
            if let Ok(s) = cookie_hdr.to_str() {
                debug!("Set-Cookie: {}", redact_set_cookie(s));
            }
        }

        let svpn_cookie = extract_svpncookie(&resp)
            .ok_or_else(|| FortiError::AuthFailed("SAML auth failed — no SVPNCOOKIE in response".into()))?;

        info!("SAML authentication successful");

        // Step 5: Fetch tunnel configuration (same as credential flow)
        let tunnel_config = self.fetch_tunnel_config(&svpn_cookie).await?;

        Ok(AuthResult { svpn_cookie, tunnel_config })
    }

    /// Fetch tunnel config: GET /remote/fortisslvpn then GET /remote/fortisslvpn_xml
    async fn fetch_tunnel_config(&self, svpn_cookie: &str) -> Result<xml::TunnelConfig> {
        // Resource reservation
        let (mut sender, _, _) = self.new_http_connection().await?;

        let req = hyper::Request::builder()
            .method("GET")
            .uri("/remote/fortisslvpn")
            .header("Host", &self.server)
            .header("User-Agent", "Mozilla/5.0 SV1")
            .header("Cookie", format!("SVPNCOOKIE={}", svpn_cookie))
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .map_err(FortiError::Http)?;

        debug!("Reserving tunnel resources");
        let resp = sender.send_request(req).await
            .map_err(|e| FortiError::TunnelError(format!("resource reservation failed: {}", e)))?;
        debug!("Resource reservation status: {}", resp.status());
        let _ = http_body_util::BodyExt::collect(resp.into_body()).await;

        // XML config
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/remote/fortisslvpn_xml?dual_stack=1")
            .header("Host", &self.server)
            .header("User-Agent", "Mozilla/5.0 SV1")
            .header("Cookie", format!("SVPNCOOKIE={}", svpn_cookie))
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .map_err(FortiError::Http)?;

        debug!("Fetching tunnel configuration");
        let resp = match sender.send_request(req).await {
            Ok(resp) => resp,
            Err(_) => {
                debug!("Reopening connection for XML config fetch");
                let (mut sender2, _, _) = self.new_http_connection().await?;
                let req = hyper::Request::builder()
                    .method("GET")
                    .uri("/remote/fortisslvpn_xml?dual_stack=1")
                    .header("Host", &self.server)
                    .header("User-Agent", "Mozilla/5.0 SV1")
                    .header("Cookie", format!("SVPNCOOKIE={}", svpn_cookie))
                    .body(http_body_util::Full::new(bytes::Bytes::new()))
                    .map_err(FortiError::Http)?;
                sender2.send_request(req).await
                    .map_err(|e| FortiError::TunnelError(format!("XML config request failed: {}", e)))?
            }
        };

        let body = http_body_util::BodyExt::collect(resp.into_body()).await
            .map_err(|e| FortiError::TunnelError(format!("failed to read XML body: {}", e)))?;
        let body_bytes = body.to_bytes();
        let xml_text = String::from_utf8_lossy(&body_bytes);
        debug!("Received XML config ({} bytes)", xml_text.len());

        let tunnel_config = xml::TunnelConfig::parse(&xml_text)?;
        info!("Tunnel config: IP={}, DNS={:?}", tunnel_config.ip_address, tunnel_config.dns_servers);

        Ok(tunnel_config)
    }

    pub fn server(&self) -> &str { &self.server }
    pub fn port(&self) -> u16 { self.port }
    pub fn tls_config(&self) -> Arc<rustls::ClientConfig> { self.tls_config.clone() }
}

/// Extract SVPNCOOKIE from response headers.
fn extract_svpncookie<T>(resp: &hyper::Response<T>) -> Option<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|v| {
            let s = v.to_str().ok()?;
            if s.starts_with("SVPNCOOKIE=") {
                let val = s.split(';').next()?;
                let cookie = val.trim_start_matches("SVPNCOOKIE=").to_string();
                // Some FortiGates set an empty cookie — treat as absent
                if cookie.is_empty() || cookie == "0" {
                    None
                } else {
                    Some(cookie)
                }
            } else {
                None
            }
        })
}

/// Parse tokeninfo response fields: "ret=1,tokeninfo=ftm,chal_msg=Enter code,reqid=123,..."
fn parse_tokeninfo_fields(text: &str) -> std::collections::HashMap<String, String> {
    let mut fields = std::collections::HashMap::new();
    // The tokeninfo response can span multiple lines; look for the line containing "ret="
    for line in text.lines() {
        let line = line.trim();
        if !line.contains("ret=") && !line.contains("tokeninfo=") {
            continue;
        }
        for part in line.split(',') {
            if let Some((key, value)) = part.split_once('=') {
                fields.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }
    fields
}

/// Extract a hidden input field value from HTML: <input type="hidden" name="fieldname" value="...">
fn extract_html_field(html: &str, field_name: &str) -> Option<String> {
    let name_pattern = format!("name=\"{}\"", field_name);
    let pos = html.find(&name_pattern)?;
    // Look for value="..." near this position
    let nearby = &html[pos.saturating_sub(100)..html.len().min(pos + 200)];
    let value_start = nearby.find("value=\"")? + 7;
    let value_end = nearby[value_start..].find('"')?;
    Some(nearby[value_start..value_start + value_end].to_string())
}

/// Wait for the SAML IdP to redirect the browser to our local callback server.
/// Enforces a 5-minute overall timeout for the entire callback phase.
async fn wait_for_saml_callback(listener: tokio::net::TcpListener) -> Result<String> {
    match tokio::time::timeout(
        std::time::Duration::from_secs(300),
        wait_for_saml_callback_inner(listener),
    ).await {
        Ok(inner) => inner,
        Err(_) => Err(FortiError::AuthFailed(
            "SAML authentication timed out after 5 minutes. Please retry.".into()
        )),
    }
}

/// Inner accept loop: extracts the `id` parameter from the browser callback URL.
/// Rejects malformed/invalid requests and continues listening until a valid
/// callback is received. The outer 5-minute timeout controls the overall budget.
async fn wait_for_saml_callback_inner(listener: tokio::net::TcpListener) -> Result<String> {
    loop {
        let (mut stream, addr) = listener.accept().await
            .map_err(|e| FortiError::AuthFailed(format!("failed to accept SAML callback: {}", e)))?;

        debug!("SAML callback connection from {}", addr);

        // Read the HTTP request with a per-connection timeout to prevent slowloris DoS
        let mut buf = vec![0u8; 4096];
        let n = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read(&mut buf),
        ).await {
            Ok(Ok(n)) if n > 0 => n,
            Ok(Ok(_)) => {
                debug!("SAML callback: connection closed without data");
                let _ = stream.shutdown().await;
                continue;
            }
            Ok(Err(e)) => {
                debug!("SAML callback: read error: {}", e);
                let _ = stream.shutdown().await;
                continue;
            }
            Err(_) => {
                debug!("SAML callback: read timeout, rejecting connection");
                let _ = stream.shutdown().await;
                continue;
            }
        };
        let request = String::from_utf8_lossy(&buf[..n]);

        // Log method only — request line contains session ID in the URL
        if let Some(request_line) = request.lines().next() {
            let method = request_line.split_whitespace().next().unwrap_or("?");
            debug!("SAML callback: received {} request", method);
        }

        // Validate: must be GET with ?id= parameter
        let session_id = request.lines()
            .next()
            .and_then(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // Must be "GET <path> HTTP/1.x"
                if parts.len() < 2 || parts[0] != "GET" {
                    return None;
                }
                let path = parts[1];
                let query = path.split('?').nth(1)?;
                for param in query.split('&') {
                    if let Some(value) = param.strip_prefix("id=") {
                        if !value.is_empty() {
                            return Some(value.to_string());
                        }
                    }
                }
                None
            });

        match session_id {
            Some(id) => {
                debug!("SAML session ID received ({} chars)", id.len());

                // Send success response
                let response = "HTTP/1.1 200 OK\r\n\
                    Content-Type: text/html\r\n\
                    Connection: close\r\n\
                    \r\n\
                    <html><body>\
                    <h2>Authentication successful</h2>\
                    <p>This tab will close automatically.</p>\
                    <script>window.close();</script>\
                    <noscript><p>You may close this browser tab and return to the terminal.</p></noscript>\
                    </body></html>";

                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
                return Ok(id);
            }
            None => {
                // Invalid request — reject and continue listening
                warn!("Rejected invalid SAML callback (no valid id parameter), continuing to listen");
                let response = "HTTP/1.1 400 Bad Request\r\n\
                    Content-Type: text/plain\r\n\
                    Connection: close\r\n\
                    \r\n\
                    Invalid callback request";
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
                continue;
            }
        }
    }
}

/// Redact SVPNCOOKIE values from a Set-Cookie header string.
/// Returns the header with the cookie value replaced by "<redacted>".
fn redact_set_cookie(header: &str) -> String {
    if header.starts_with("SVPNCOOKIE=") {
        "SVPNCOOKIE=<redacted>".to_string()
    } else {
        header.to_string()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_svpncookie() {
        let input = "SVPNCOOKIE=abc123secret; path=/; secure; HttpOnly";
        assert_eq!(redact_set_cookie(input), "SVPNCOOKIE=<redacted>");
    }

    #[test]
    fn test_no_redact_other_cookie() {
        let input = "OTHERCOOKIE=value123; path=/";
        assert_eq!(redact_set_cookie(input), "OTHERCOOKIE=value123; path=/");
    }

    #[test]
    fn test_redact_empty_svpncookie() {
        let input = "SVPNCOOKIE=; path=/";
        assert_eq!(redact_set_cookie(input), "SVPNCOOKIE=<redacted>");
    }
}
