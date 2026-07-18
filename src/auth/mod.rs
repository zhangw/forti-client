pub mod xml;

use crate::error::{FortiError, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info, warn};

const HTTP_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const SAML_INTERACTIVE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SAML_CALLBACK_IO_TIMEOUT: Duration = Duration::from_secs(5);
const BROWSER_LAUNCH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SAML_CALLBACK_HEADER: usize = 16 * 1024;
const MAX_AUTH_BODY_SIZE: usize = 4 * 1024 * 1024;

async fn collect_auth_body(body: hyper::body::Incoming, context: &str) -> Result<bytes::Bytes> {
    let limited = http_body_util::Limited::new(body, MAX_AUTH_BODY_SIZE);
    let collected = tokio::time::timeout(
        HTTP_OPERATION_TIMEOUT,
        http_body_util::BodyExt::collect(limited),
    )
    .await
    .map_err(|_| FortiError::TunnelError(format!("{} timed out after 30s", context)))?
    .map_err(|e| FortiError::TunnelError(format!("{}: {}", context, e)))?;
    Ok(collected.to_bytes())
}

/// Read a line from the controlling terminal without blocking a Tokio worker.
/// kill_on_drop makes cancellation (including Ctrl+C) terminate the reader.
async fn prompt_terminal(prompt: &str) -> Result<String> {
    eprint!("{}", prompt);
    std::io::Write::flush(&mut std::io::stderr())?;

    let output = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("IFS= read -r line < /dev/tty && printf '%s' \"$line\"")
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| FortiError::AuthFailed(format!("failed to read verification code: {}", e)))?;
    if !output.status.success() {
        return Err(FortiError::AuthFailed(
            "failed to read verification code from terminal".into(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn send_auth_request(
    sender: &mut hyper::client::conn::http1::SendRequest<http_body_util::Full<bytes::Bytes>>,
    request: hyper::Request<http_body_util::Full<bytes::Bytes>>,
    context: &str,
) -> Result<hyper::Response<hyper::body::Incoming>> {
    tokio::time::timeout(HTTP_OPERATION_TIMEOUT, sender.send_request(request))
        .await
        .map_err(|_| FortiError::TunnelError(format!("{} timed out after 30s", context)))?
        .map_err(|e| FortiError::TunnelError(format!("{}: {}", context, e)))
}

fn saml_browser_command(url: &str) -> tokio::process::Command {
    #[cfg(debug_assertions)]
    if let Some(program) = std::env::var_os("FORTI_CLIENT_TEST_BROWSER_LAUNCHER") {
        let mut command = tokio::process::Command::new(program);
        command.arg(url);
        return command;
    }

    if let Ok(user) = std::env::var("SUDO_USER") {
        let mut command = tokio::process::Command::new("sudo");
        command.args(["-u", &user, "open", url]);
        command
    } else {
        let mut command = tokio::process::Command::new("open");
        command.arg(url);
        command
    }
}

async fn launch_saml_browser(url: &str) -> std::io::Result<()> {
    let mut command = saml_browser_command(url);
    command.kill_on_drop(true);
    let mut child = command.spawn()?;
    match tokio::time::timeout(BROWSER_LAUNCH_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => Err(std::io::Error::other(format!(
            "browser launcher exited with status {status}"
        ))),
        Ok(Err(error)) => Err(error),
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "browser launcher did not exit within 5 seconds",
            ))
        }
    }
}

pub struct AuthResult {
    pub svpn_cookie: String,
    pub tunnel_config: xml::TunnelConfig,
}

impl std::fmt::Debug for AuthResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthResult")
            .field("svpn_cookie", &"<redacted>")
            .field("tunnel_config", &self.tunnel_config)
            .finish()
    }
}

pub struct AuthClient {
    server: String,
    port: u16,
    tls_config: Arc<rustls::ClientConfig>,
}

impl AuthClient {
    pub fn new(server: &str, port: u16, enable_keylog: bool) -> Result<Self> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        if enable_keylog {
            tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        Ok(Self {
            server: server.to_string(),
            port,
            tls_config: Arc::new(tls_config),
        })
    }

    /// Create a new TLS+HTTP connection to the server.
    async fn new_http_connection(
        &self,
    ) -> Result<(
        hyper::client::conn::http1::SendRequest<http_body_util::Full<bytes::Bytes>>,
        tokio_rustls::TlsConnector,
        rustls::pki_types::ServerName<'static>,
    )> {
        tokio::time::timeout(HTTP_OPERATION_TIMEOUT, async {
            let connector = tokio_rustls::TlsConnector::from(self.tls_config.clone());
            let server_name = rustls::pki_types::ServerName::try_from(self.server.clone())
                .map_err(|e| FortiError::TunnelError(format!("invalid server name: {}", e)))?;

            let tcp =
                tokio::net::TcpStream::connect(format!("{}:{}", self.server, self.port)).await?;
            let tls = connector
                .connect(server_name.clone(), tcp)
                .await
                .map_err(|e| FortiError::TunnelError(format!("TLS connect failed: {}", e)))?;

            let io = hyper_util::rt::TokioIo::new(tls);
            let (sender, conn) = hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|e| FortiError::TunnelError(format!("HTTP handshake failed: {}", e)))?;

            tokio::spawn(conn);
            Ok((sender, connector, server_name))
        })
        .await
        .map_err(|_| FortiError::TunnelError("HTTP connection timed out after 30s".into()))?
    }

    pub async fn login(
        &self,
        username: &str,
        password: &str,
        realm: Option<&str>,
    ) -> Result<AuthResult> {
        let svpn_cookie = self
            .authenticate_credentials(username, password, realm)
            .await?;
        let tunnel_config = self.fetch_tunnel_config(&svpn_cookie).await?;
        Ok(AuthResult {
            svpn_cookie,
            tunnel_config,
        })
    }

    /// Authenticate with credentials and return only the session cookie.
    pub async fn authenticate_credentials(
        &self,
        username: &str,
        password: &str,
        realm: Option<&str>,
    ) -> Result<String> {
        // Step 1: POST /remote/logincheck
        let (mut sender, _connector, _server_name) = self.new_http_connection().await?;

        let body = if let Some(realm) = realm {
            format!(
                "ajax=1&username={}&credential={}&realm={}&just_logged_in=1",
                urlencoded(username),
                urlencoded(password),
                urlencoded(realm),
            )
        } else {
            format!(
                "ajax=1&username={}&credential={}&just_logged_in=1",
                urlencoded(username),
                urlencoded(password),
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
        let resp = send_auth_request(&mut sender, req, "login request failed").await?;

        let status = resp.status();
        debug!("Login response status: {}", status);

        log_set_cookie_headers(&resp);
        let svpn_cookie = extract_svpncookie(&resp);

        // Read the response body for 2FA detection, with a time and size bound.
        let resp_body = collect_auth_body(resp.into_body(), "failed to read login body").await?;
        let resp_text = String::from_utf8_lossy(&resp_body).to_string();

        // Check for 2FA requirement
        let svpn_cookie = if let Some(cookie) = svpn_cookie {
            // Got cookie — but check if 2FA is still needed
            // Some FortiGates return a partial cookie that requires 2FA completion
            if resp_text.contains("tokeninfo=") || resp_text.contains("2fa") {
                debug!("Got SVPNCOOKIE but 2FA appears required, proceeding with 2FA");
                self.handle_2fa_tokeninfo(username, &resp_text, Some(&cookie))
                    .await?
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
            self.handle_2fa_tokeninfo(username, &resp_text, None)
                .await?
        } else if status.as_u16() == 405 {
            return Err(FortiError::AuthFailed("invalid credentials (405)".into()));
        } else {
            return Err(FortiError::AuthFailed(format!(
                "login failed: status={}",
                status
            )));
        };

        Ok(svpn_cookie)
    }

    /// Handle tokeninfo-based 2FA (most common).
    /// Response body format: ret=<status>,tokeninfo=<type>,chal_msg=<prompt>,reqid=<id>,polid=<id>,grp=<group>,portal=<portal>,peer=<peer>,magic=<value>
    async fn handle_2fa_tokeninfo(
        &self,
        username: &str,
        resp_text: &str,
        _existing_cookie: Option<&str>,
    ) -> Result<String> {
        // Parse the tokeninfo fields
        let fields = parse_tokeninfo_fields(resp_text);
        let tokeninfo = fields
            .get("tokeninfo")
            .map(|s| s.as_str())
            .unwrap_or("unknown");
        let chal_msg = fields
            .get("chal_msg")
            .map(|s| s.as_str())
            .unwrap_or("Enter verification code");
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
                urlencoded(username),
                urlencoded(reqid),
                urlencoded(polid),
                urlencoded(grp),
                urlencoded(portal),
                urlencoded(peer),
            );
            return self.send_2fa_code(&body).await;
        }

        // Prompt user for OTP code
        let code = prompt_terminal(&format!("{}: ", chal_msg)).await?;

        let body = format!(
            "username={}&code={}&reqid={}&polid={}&grp={}&portal={}&peer={}&magic={}",
            urlencoded(username),
            urlencoded(&code),
            urlencoded(reqid),
            urlencoded(polid),
            urlencoded(grp),
            urlencoded(portal),
            urlencoded(peer),
            urlencoded(magic),
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
        let code = prompt_terminal("Enter verification code: ").await?;

        let body = format!(
            "username={}&code={}&reqid={}&grpid={}&magic={}",
            urlencoded(username),
            urlencoded(&code),
            urlencoded(&reqid),
            urlencoded(&grpid),
            urlencoded(&magic),
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
            .body(http_body_util::Full::new(bytes::Bytes::from(
                body.to_string(),
            )))
            .map_err(FortiError::Http)?;

        debug!("Sending 2FA verification");
        let resp = send_auth_request(&mut sender, req, "2FA request failed").await?;

        debug!("2FA response status: {}", resp.status());

        let cookie = extract_svpncookie(&resp).ok_or_else(|| {
            FortiError::AuthFailed("2FA verification failed — no SVPNCOOKIE in response".into())
        })?;

        info!("2FA verification successful");
        Ok(cookie)
    }

    /// Authenticate via SAML/SSO and fetch tunnel configuration.
    pub async fn login_saml(&self) -> Result<AuthResult> {
        let svpn_cookie = self.authenticate_saml().await?;
        let tunnel_config = self.fetch_tunnel_config(&svpn_cookie).await?;
        Ok(AuthResult {
            svpn_cookie,
            tunnel_config,
        })
    }

    /// Authenticate via SAML/SSO and return only the session cookie.
    pub async fn authenticate_saml(&self) -> Result<String> {
        let saml_port: u16 = 8020;

        // Step 1: Start local HTTP server to receive the SAML callback
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", saml_port))
            .await
            .map_err(|e| {
                FortiError::SamlTerminalConfiguration(format!(
                    "failed to bind callback port {}: {} (is another VPN client running?)",
                    saml_port, e
                ))
            })?;

        info!("SAML callback server listening on 127.0.0.1:{}", saml_port);

        // Step 2: Open browser to SAML start URL
        let saml_url = format!(
            "https://{}:{}/remote/saml/start?redirect=1",
            self.server, self.port,
        );
        info!("Opening browser for SAML authentication...");
        info!("If browser doesn't open, navigate to: {}", saml_url);

        if let Err(error) = launch_saml_browser(&saml_url).await {
            debug!("Browser launcher failed: {}", error);
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
            .uri(format!(
                "/remote/saml/auth_id?id={}",
                urlencoded(&session_id)
            ))
            .header("Host", &self.server)
            .header("User-Agent", "Mozilla/5.0 SV1")
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .map_err(FortiError::Http)?;

        debug!("Exchanging SAML session ID for SVPNCOOKIE");
        let resp = send_auth_request(&mut sender, req, "SAML auth_id request failed").await?;

        debug!("SAML auth_id response status: {}", resp.status());
        log_set_cookie_headers(&resp);

        let svpn_cookie = extract_svpncookie(&resp).ok_or_else(|| {
            FortiError::SamlCallbackInvalid(
                "gateway returned no SVPNCOOKIE after callback exchange".into(),
            )
        })?;

        info!("SAML authentication successful");
        Ok(svpn_cookie)
    }

    /// Fetch tunnel config for an already authenticated session cookie.
    pub async fn fetch_tunnel_config(&self, svpn_cookie: &str) -> Result<xml::TunnelConfig> {
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
        let resp = send_auth_request(&mut sender, req, "resource reservation failed").await?;
        debug!("Resource reservation status: {}", resp.status());
        if matches!(resp.status().as_u16(), 401 | 403) {
            return Err(FortiError::CookieRejected(resp.status().as_u16()));
        }
        let _ = collect_auth_body(resp.into_body(), "resource reservation body").await?;

        // XML config
        let make_xml_request = || {
            hyper::Request::builder()
                .method("GET")
                .uri("/remote/fortisslvpn_xml?dual_stack=1")
                .header("Host", &self.server)
                .header("User-Agent", "Mozilla/5.0 SV1")
                .header("Cookie", format!("SVPNCOOKIE={}", svpn_cookie))
                .body(http_body_util::Full::new(bytes::Bytes::new()))
                .map_err(FortiError::Http)
        };

        debug!("Fetching tunnel configuration");
        let req = make_xml_request()?;
        let resp = match send_auth_request(&mut sender, req, "XML config request failed").await {
            Ok(resp) => resp,
            Err(_) => {
                debug!("Reopening connection for XML config fetch");
                let (mut sender2, _, _) = self.new_http_connection().await?;
                send_auth_request(&mut sender2, make_xml_request()?, "XML config retry failed")
                    .await?
            }
        };
        if matches!(resp.status().as_u16(), 401 | 403) {
            return Err(FortiError::CookieRejected(resp.status().as_u16()));
        }

        let body_bytes = collect_auth_body(resp.into_body(), "failed to read XML body").await?;
        let xml_text = String::from_utf8_lossy(&body_bytes);
        debug!("Received XML config ({} bytes)", xml_text.len());

        let tunnel_config = xml::TunnelConfig::parse(&xml_text)?;
        info!(
            "Tunnel config: IP={}, DNS={:?}",
            tunnel_config.ip_address, tunnel_config.dns_servers
        );

        Ok(tunnel_config)
    }

    pub fn server(&self) -> &str {
        &self.server
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn tls_config(&self) -> Arc<rustls::ClientConfig> {
        self.tls_config.clone()
    }
}

/// Extract SVPNCOOKIE from response headers.
fn extract_svpncookie<T>(resp: &hyper::Response<T>) -> Option<String> {
    resp.headers().get_all("set-cookie").iter().find_map(|v| {
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
    wait_for_saml_callback_with_timeout(listener, SAML_INTERACTIVE_TIMEOUT).await
}

async fn wait_for_saml_callback_with_timeout(
    listener: tokio::net::TcpListener,
    deadline: Duration,
) -> Result<String> {
    match tokio::time::timeout(deadline, wait_for_saml_callback_inner(listener)).await {
        Ok(inner) => inner,
        Err(_) => Err(FortiError::SamlCallbackTimedOut),
    }
}

fn parse_saml_session_id(request_bytes: &[u8]) -> Option<String> {
    let request = std::str::from_utf8(request_bytes).ok()?;
    let request_line = request.lines().next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if method != "GET" || !matches!(version, "HTTP/1.0" | "HTTP/1.1") || parts.next().is_some() {
        return None;
    }

    let (_, query) = target.split_once('?')?;
    let mut session_id = None;
    for parameter in query.split('&') {
        let Some((name, value)) = parameter.split_once('=') else {
            continue;
        };
        if name == "id" {
            if value.is_empty() || session_id.is_some() {
                return None;
            }
            session_id = Some(value.to_string());
        }
    }
    session_id
}

async fn read_saml_request(stream: &mut tokio::net::TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut request = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        request.extend_from_slice(&chunk[..n]);
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_len = header_end + 4;
            if header_len > MAX_SAML_CALLBACK_HEADER {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "SAML callback header exceeds 16 KiB",
                ));
            }
            request.truncate(header_len);
            return Ok(Some(request));
        }
        if request.len() > MAX_SAML_CALLBACK_HEADER {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SAML callback header exceeds 16 KiB",
            ));
        }
    }
}

async fn write_saml_response<Writer>(writer: &mut Writer, response: &[u8])
where
    Writer: AsyncWrite + Unpin,
{
    let _ = tokio::time::timeout(SAML_CALLBACK_IO_TIMEOUT, async {
        writer.write_all(response).await?;
        writer.shutdown().await
    })
    .await;
}

/// Inner accept loop: extracts the `id` parameter from the browser callback URL.
/// Rejects malformed/invalid requests and continues listening until a valid
/// callback is received. The outer 5-minute timeout controls the overall budget.
async fn wait_for_saml_callback_inner(listener: tokio::net::TcpListener) -> Result<String> {
    loop {
        let (mut stream, addr) = listener.accept().await.map_err(|e| {
            FortiError::SamlCallbackInvalid(format!("failed to accept callback: {}", e))
        })?;

        debug!("SAML callback connection from {}", addr);

        // Read through the complete HTTP header. A browser may split the
        // request line or headers across arbitrary TCP packets.
        let request_bytes =
            match tokio::time::timeout(SAML_CALLBACK_IO_TIMEOUT, read_saml_request(&mut stream))
                .await
            {
                Ok(Ok(Some(request))) => request,
                Ok(Ok(None)) => {
                    debug!("SAML callback: connection closed before complete headers");
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
        let request = String::from_utf8_lossy(&request_bytes);

        // Log method only — request line contains session ID in the URL
        if let Some(request_line) = request.lines().next() {
            let method = request_line.split_whitespace().next().unwrap_or("?");
            debug!("SAML callback: received {} request", method);
        }

        // Validate without logging the target because it contains the session ID.
        let session_id = parse_saml_session_id(&request_bytes);

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

                write_saml_response(&mut stream, response.as_bytes()).await;
                return Ok(id);
            }
            None => {
                // Invalid request — reject and continue listening
                warn!(
                    "Rejected invalid SAML callback (no valid id parameter), continuing to listen"
                );
                let response = "HTTP/1.1 400 Bad Request\r\n\
                    Content-Type: text/plain\r\n\
                    Connection: close\r\n\
                    \r\n\
                    Invalid callback request";
                write_saml_response(&mut stream, response.as_bytes()).await;
                continue;
            }
        }
    }
}

fn redact_set_cookie(header: &str) -> String {
    let name = header
        .split_once('=')
        .map(|(name, _)| name)
        .unwrap_or("cookie");
    format!("{}=<redacted>", name.trim())
}

/// Log Set-Cookie headers with SVPNCOOKIE values redacted.
fn log_set_cookie_headers<T>(resp: &hyper::Response<T>) {
    for cookie_hdr in resp.headers().get_all("set-cookie").iter() {
        if let Ok(s) = cookie_hdr.to_str() {
            debug!("Set-Cookie: {}", redact_set_cookie(s));
        }
    }
}

fn urlencoded(s: &str) -> String {
    let mut result = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", b));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn announce_when_pending<F>(
        future: F,
        started: tokio::sync::oneshot::Sender<()>,
    ) -> F::Output
    where
        F: std::future::Future,
    {
        tokio::pin!(future);
        let mut started = Some(started);
        std::future::poll_fn(|context| {
            let poll = future.as_mut().poll(context);
            if poll.is_pending() {
                if let Some(started) = started.take() {
                    let _ = started.send(());
                }
            }
            poll
        })
        .await
    }

    #[test]
    fn test_redact_svpncookie() {
        let input = "SVPNCOOKIE=abc123secret; path=/; secure; HttpOnly";
        assert_eq!(redact_set_cookie(input), "SVPNCOOKIE=<redacted>");
    }

    #[test]
    fn test_redact_other_cookie() {
        let input = "OTHERCOOKIE=value123; path=/";
        assert_eq!(redact_set_cookie(input), "OTHERCOOKIE=<redacted>");
    }

    #[test]
    fn test_redact_empty_svpncookie() {
        let input = "SVPNCOOKIE=; path=/";
        assert_eq!(redact_set_cookie(input), "SVPNCOOKIE=<redacted>");
    }

    #[tokio::test]
    async fn aborting_pending_callback_accept_releases_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(announce_when_pending(
            wait_for_saml_callback_inner(listener),
            started_tx,
        ));
        tokio::time::timeout(Duration::from_secs(1), started_rx)
            .await
            .expect("callback accept must be polled")
            .expect("callback accept pending signal must be sent");

        task.abort();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("aborted accept must finish promptly")
            .expect_err("callback waiter must be cancelled");
        let rebound = tokio::net::TcpListener::bind(address)
            .await
            .expect("aborting accept must release the listener");
        drop(rebound);
    }

    #[tokio::test]
    async fn aborting_pending_callback_read_releases_stream() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        let (mut server_stream, _) = listener.accept().await.unwrap();
        drop(listener);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            announce_when_pending(read_saml_request(&mut server_stream), started_tx).await
        });
        tokio::time::timeout(Duration::from_secs(1), started_rx)
            .await
            .expect("callback read must be polled")
            .expect("callback read pending signal must be sent");

        task.abort();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("aborted read must finish promptly")
            .expect_err("callback read must be cancelled");
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .expect("peer stream must close after read cancellation")
            .unwrap();
        assert_eq!(read, 0);
        let rebound = tokio::net::TcpListener::bind(address)
            .await
            .expect("aborting read must leave the callback address reusable");
        drop(rebound);
    }

    struct PendingWriter {
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for PendingWriter {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl AsyncWrite for PendingWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Pending
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    #[tokio::test]
    async fn aborting_pending_callback_write_drops_writer() {
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task_dropped = dropped.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut writer = PendingWriter {
                dropped: task_dropped,
            };
            announce_when_pending(write_saml_response(&mut writer, b"response"), started_tx).await;
        });
        tokio::time::timeout(Duration::from_secs(1), started_rx)
            .await
            .expect("callback write must be polled")
            .expect("callback write pending signal must be sent");

        task.abort();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("aborted write must finish promptly")
            .expect_err("callback write must be cancelled");
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn fragmented_saml_callback_is_accepted_at_every_split() {
        let request =
            b"GET /callback?next=portal&id=session-123 HTTP/1.1\r\nHost: localhost\r\n\r\n";
        for split in 1..request.len() {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(wait_for_saml_callback_inner(listener));

            let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
            client.write_all(&request[..split]).await.unwrap();
            tokio::task::yield_now().await;
            client.write_all(&request[split..]).await.unwrap();

            let session_id = tokio::time::timeout(Duration::from_secs(1), server)
                .await
                .expect("fragmented callback must complete")
                .unwrap()
                .unwrap();
            assert_eq!(session_id, "session-123", "split position {split}");
        }
    }

    #[test]
    fn saml_request_parser_rejects_invalid_and_duplicate_ids() {
        assert_eq!(
            parse_saml_session_id(b"POST /callback?id=x HTTP/1.1\r\n\r\n"),
            None
        );
        assert_eq!(
            parse_saml_session_id(b"GET /callback?id= HTTP/1.1\r\n\r\n"),
            None
        );
        assert_eq!(
            parse_saml_session_id(b"GET /callback?id=one&id=two HTTP/1.1\r\n\r\n"),
            None
        );
        assert_eq!(
            parse_saml_session_id(
                b"GET /callback?state=ready&id=session-123&source=idp HTTP/1.1\r\n\r\n"
            ),
            Some("session-123".to_string())
        );
    }

    #[tokio::test]
    async fn incomplete_and_oversized_callbacks_are_rejected_before_valid_one() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(wait_for_saml_callback_inner(listener));

        let mut incomplete = tokio::net::TcpStream::connect(address).await.unwrap();
        incomplete
            .write_all(b"GET /callback?id=incomplete HTTP/1.1\r\n")
            .await
            .unwrap();
        drop(incomplete);

        let mut oversized = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut large_request = b"GET /callback?id=oversized HTTP/1.1\r\nX-Fill: ".to_vec();
        large_request.extend(std::iter::repeat_n(b'a', MAX_SAML_CALLBACK_HEADER));
        large_request.extend_from_slice(b"\r\n\r\n");
        oversized.write_all(&large_request).await.unwrap();
        drop(oversized);

        let mut valid = tokio::net::TcpStream::connect(address).await.unwrap();
        valid
            .write_all(b"GET /callback?id=valid HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let session_id = tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("server must continue after invalid connections")
            .unwrap()
            .unwrap();
        assert_eq!(session_id, "valid");
    }

    #[tokio::test(start_paused = true)]
    async fn saml_callback_deadline_is_typed_and_uses_tokio_time() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let waiter = tokio::spawn(wait_for_saml_callback_with_timeout(
            listener,
            Duration::from_secs(300),
        ));
        tokio::time::advance(Duration::from_secs(300)).await;
        let error = waiter.await.unwrap().unwrap_err();
        assert!(matches!(error, FortiError::SamlCallbackTimedOut));
    }

    #[test]
    fn auth_result_debug_redacts_cookie() {
        let result = AuthResult {
            svpn_cookie: "secret-cookie".into(),
            tunnel_config: xml::TunnelConfig::parse(
                r#"<sslvpn-tunnel><assigned-addr ipv4="10.0.0.2" /></sslvpn-tunnel>"#,
            )
            .unwrap(),
        };
        let debug = format!("{result:?}");
        assert!(!debug.contains("secret-cookie"));
        assert!(debug.contains("<redacted>"));
    }
}
