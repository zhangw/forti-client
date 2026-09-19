//! launchd supervisor, user-session browser bridge, and authenticated local control.
//! The existing VPN stays in a child process so monitor threads have its lifetime.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};

pub const DIRECTORY: &str = "/Library/Application Support/FortiClient";
pub const SOCKET: &str = "/var/run/forti-client/control.sock";
const CONFIG: &str = "/Library/Application Support/FortiClient/config.json";
const INTENT: &str = "/Library/Application Support/FortiClient/intent.json";
const LOG: &str = "/Library/Logs/FortiClient/vpn.log";
const WORKER_LOCK: &str = "/var/run/forti-client-vpn.lock";
const MAX_MESSAGE: u64 = 16384;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub uid: u32,
    pub server: String,
    pub port: u16,
    #[serde(default)]
    pub trusted_wifi: Vec<String>,
}

pub fn validate_config(path: &str) -> Result<()> {
    let config: Config = serde_json::from_slice(&std::fs::read(path)?)?;
    config.validate()
}

fn validate_root_file(path: &str) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
        bail!("service configuration must be a root-owned private regular file: {path}");
    }
    Ok(())
}

impl Config {
    fn validate(&self) -> Result<()> {
        if self.uid == 0
            || self.server.is_empty()
            || !self
                .server
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
            || self.port == 0
        {
            bail!("invalid service configuration (non-root UID, DNS hostname, port required)");
        }
        Ok(())
    }
    fn saml_url(&self) -> String {
        format!(
            "https://{}:{}/remote/saml/start?redirect=1",
            self.server, self.port
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Status {},
    Pause {},
    Resume {},
    Reconnect {},
    Authenticate {},
    Logs {},
    Poll {},
    BrowserDone {
        id: u64,
        success: bool,
    },
    State {
        token: String,
        state: String,
    },
    Browser {
        token: String,
        url: String,
        background: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Browser {
    id: u64,
    url: String,
    background: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub desired: String,
    pub state: String,
    pub worker_pid: Option<u32>,
    pub daemon_pid: u32,
    pub agent_present: bool,
    pub last_error: Option<String>,
    pub retry_in_seconds: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<Status>,
    #[serde(skip_serializing_if = "Option::is_none")]
    browser: Option<Browser>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logs: Option<String>,
}

fn error(message: impl ToString) -> Response {
    Response {
        error: Some(message.to_string()),
        ..Response::default()
    }
}

pub fn lock(path: &str) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
        bail!("unsafe lock file: {path}");
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("another forti-client owns {path}");
    }
    Ok(file)
}

pub fn worker_lock() -> Result<Option<File>> {
    // Unprivileged invocations are used by protocol/signal tests; they cannot
    // install routes or DNS. Every privileged VPN invocation takes this lock.
    if unsafe { libc::geteuid() } == 0 {
        Ok(Some(lock(WORKER_LOCK)?))
    } else {
        Ok(None)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    connected: bool,
}

fn read_intent(path: &Path) -> Result<bool> {
    Ok(serde_json::from_slice::<Intent>(&std::fs::read(path)?)?.connected)
}

fn write_intent(path: &Path, connected: bool) -> Result<()> {
    let temporary = path.with_extension("new");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    use std::io::Write;
    file.write_all(&serde_json::to_vec(&Intent { connected })?)?;
    file.sync_all()?;
    std::fs::rename(temporary, path)?;
    File::open(path.parent().context("intent parent")?)?.sync_all()?;
    Ok(())
}

fn console_uid() -> Option<u32> {
    std::fs::metadata("/dev/console").ok().map(|m| m.uid())
}

fn authorized(uid: u32, owner: u32, request: &Request) -> bool {
    match request {
        Request::State { .. } | Request::Browser { .. } => uid == 0,
        Request::Poll {} | Request::BrowserDone { .. } => {
            uid == owner && console_uid() == Some(owner)
        }
        _ => uid == 0 || uid == owner,
    }
}

async fn read_message<T: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> Result<T> {
    let mut bytes = Vec::new();
    let mut reader = BufReader::new(stream.take(MAX_MESSAGE + 1));
    reader.read_until(b'\n', &mut bytes).await?;
    if bytes.len() as u64 > MAX_MESSAGE || bytes.last() != Some(&b'\n') {
        bail!("invalid message length/framing");
    }
    Ok(serde_json::from_slice(&bytes)?)
}

async fn write_message<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    Ok(())
}

async fn request(value: Request) -> Result<Response> {
    tokio::time::timeout(Duration::from_secs(12), async {
        let mut stream = UnixStream::connect(SOCKET)
            .await
            .context("service unavailable")?;
        // A user must not send authentication URLs to an impersonated daemon.
        if stream.peer_cred()?.uid() != 0 {
            bail!("service peer is not root");
        }
        write_message(&mut stream, &value).await?;
        let response: Response = read_message(&mut stream).await?;
        if let Some(ref message) = response.error {
            bail!("{message}");
        }
        Ok(response)
    })
    .await
    .context("service request timed out")?
}

pub async fn report_state(state: &str) {
    if let Ok(token) = std::env::var("FORTI_SERVICE_TOKEN") {
        // A missing supervisor must not delay the VPN shutdown path.
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            request(Request::State {
                token,
                state: state.into(),
            }),
        )
        .await;
    }
}

pub async fn open_browser(url: &str, background: bool) -> std::io::Result<()> {
    let token = std::env::var("FORTI_SERVICE_TOKEN").map_err(std::io::Error::other)?;
    request(Request::Browser {
        token,
        url: url.into(),
        background: background || std::env::var_os("FORTI_SERVICE_FOREGROUND").is_none(),
    })
    .await
    .map(|_| ())
    .map_err(std::io::Error::other)
}

struct Incoming {
    uid: u32,
    request: Request,
    reply: oneshot::Sender<Response>,
}

async fn accept_requests(listener: UnixListener, tx: mpsc::Sender<Incoming>) {
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(32));
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            break;
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let tx = tx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(cred) = stream.peer_cred() else {
                return;
            };
            let Ok(Ok(value)) =
                tokio::time::timeout(Duration::from_secs(2), read_message(&mut stream)).await
            else {
                return;
            };
            let (reply, response) = oneshot::channel();
            if tx
                .send(Incoming {
                    uid: cred.uid(),
                    request: value,
                    reply,
                })
                .await
                .is_err()
            {
                return;
            }
            // Dropping a browser request cancels its pending presentation.
            let mut byte = [0];
            tokio::select! {
                result = response => if let Ok(value) = result { let _ = write_message(&mut stream, &value).await; },
                _ = stream.read(&mut byte) => {},
                _ = tokio::time::sleep(Duration::from_secs(11)) => {},
            }
        });
    }
}

struct PendingBrowser {
    value: Browser,
    reply: oneshot::Sender<Response>,
    expires: Instant,
    delivered: bool,
}

fn rotate_log() -> Result<()> {
    if std::fs::metadata(LOG)
        .map(|m| m.len() > 5 * 1024 * 1024)
        .unwrap_or(false)
    {
        std::fs::rename(LOG, format!("{LOG}.1"))?;
    }
    Ok(())
}

async fn cleanup() -> Result<()> {
    let _guard = lock(WORKER_LOCK)?;
    crate::tun::dns::remove_dns().await?;
    Ok(())
}

fn spawn_worker(config: &Config, token: &str, foreground: bool) -> Result<Child> {
    rotate_log()?;
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.args([
        "--server",
        &config.server,
        "--port",
        &config.port.to_string(),
        "--saml",
        "--log-file",
        "/dev/null",
    ]);
    for ssid in &config.trusted_wifi {
        cmd.args(["--trusted-wifi", ssid]);
    }
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("RUST_LOG", "info")
        .env("FORTI_SERVICE_TOKEN", token)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if foreground {
        cmd.env("FORTI_SERVICE_FOREGROUND", "1");
    }
    let mut child = cmd.spawn()?;
    let mut stderr = child.stderr.take().context("worker stderr")?;
    tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        while let Ok(count) = stderr.read(&mut buffer).await {
            if count == 0 {
                break;
            }
            // Open per chunk, so rotation never leaves a writer on the old file.
            let result = (|| -> Result<()> {
                rotate_log()?;
                let mut log = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(LOG)?;
                std::io::Write::write_all(&mut log, &buffer[..count])?;
                Ok(())
            })();
            if let Err(e) = result {
                eprintln!("VPN log write failed: {e}");
            }
        }
    });
    Ok(child)
}

fn begin_stop(child: &Option<Child>, deadline: &mut Option<Instant>) {
    if deadline.is_none() {
        if let Some(pid) = child.as_ref().and_then(|c| c.id()) {
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            *deadline = Some(Instant::now() + Duration::from_secs(20));
        }
    }
}

pub(crate) fn worker_exit_attention(state: &str) -> Option<String> {
    matches!(state, "NeedsAuthentication" | "ConfigurationError").then(|| state.to_owned())
}

pub async fn daemon() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("service requires root");
    }
    let _lock = lock(&format!("{DIRECTORY}/daemon.lock"))?;
    validate_root_file(CONFIG)?;
    validate_root_file(INTENT)?;
    let config: Config = serde_json::from_slice(&std::fs::read(CONFIG)?)?;
    config.validate()?;
    // Missing/corrupt intent fails closed, never resetting a user's pause.
    let mut connected = read_intent(Path::new(INTENT))?;
    let runtime = Path::new(SOCKET).parent().unwrap();
    std::fs::create_dir_all(runtime)?;
    let meta = std::fs::symlink_metadata(runtime)?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        bail!("unsafe runtime directory");
    }
    std::fs::set_permissions(runtime, std::fs::Permissions::from_mode(0o755))?;
    let _ = std::fs::remove_file(SOCKET);
    let listener = UnixListener::bind(SOCKET)?;
    std::fs::set_permissions(SOCKET, std::fs::Permissions::from_mode(0o666))?;
    let (tx, mut rx) = mpsc::channel(32);
    let accept = tokio::spawn(accept_requests(listener, tx));
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut child: Option<Child> = None;
    let mut stopping = None;
    let mut quitting = false;
    let mut last_agent: Option<Instant> = None;
    let mut pending: Option<PendingBrowser> = None;
    let mut token = String::new();
    let mut next_start = Instant::now();
    let mut cleanup_needed = true;
    let mut needs_attention: Option<String> = None;
    let mut foreground = false;
    let mut status = Status {
        desired: if connected { "connected" } else { "paused" }.into(),
        state: "Starting".into(),
        worker_pid: None,
        daemon_pid: std::process::id(),
        agent_present: false,
        last_error: None,
        retry_in_seconds: 0,
    };
    loop {
        status.agent_present = console_uid() == Some(config.uid)
            && last_agent.is_some_and(|t| t.elapsed() < Duration::from_secs(30));
        status.worker_pid = child.as_ref().and_then(|c| c.id());
        status.retry_in_seconds = next_start
            .saturating_duration_since(Instant::now())
            .as_secs();
        tokio::select! {
            _ = term.recv() => { quitting = true; begin_stop(&child, &mut stopping); },
            _ = interrupt.recv() => { quitting = true; begin_stop(&child, &mut stopping); },
            _ = tick.tick() => {},
            Some(incoming) = rx.recv() => {
                let Incoming { uid, request: req, reply } = incoming;
                if !authorized(uid, config.uid, &req) { let _ = reply.send(error("unauthorized user/session")); continue; }
                let mut response = Response::default();
                match req {
                    Request::Status {} => response.status = Some(status.clone()),
                    Request::Pause {} | Request::Resume {} => {
                        let desired = matches!(req, Request::Resume {});
                        match write_intent(Path::new(INTENT), desired) {
                            Ok(()) => {
                                connected = desired;
                                status.desired = if desired { "connected" } else { "paused" }.into();
                                if !desired { begin_stop(&child, &mut stopping); pending = None; }
                                else { next_start = Instant::now(); needs_attention = None; }
                            },
                            Err(e) => response = error(e),
                        }
                    },
                    Request::Reconnect {} | Request::Authenticate {} => {
                        if !connected { response = error("paused; run forti-client ctl resume first"); }
                        else { begin_stop(&child, &mut stopping); pending = None; next_start = Instant::now(); needs_attention = None; foreground = matches!(req, Request::Authenticate {}); }
                    },
                    Request::Poll {} => {
                        last_agent = Some(Instant::now());
                        if let Some(p) = pending.as_mut() {
                            if !p.delivered && !p.reply.is_closed() && p.expires > Instant::now() && stopping.is_none() && connected {
                                response.browser = Some(p.value.clone()); p.delivered = true;
                            }
                        }
                        response.status = Some(status.clone());
                    },
                    Request::BrowserDone { id, success } => {
                        if pending.as_ref().is_some_and(|p| p.value.id == id && p.expires > Instant::now()) {
                            let p = pending.take().unwrap();
                            let _ = p.reply.send(if success { Response::default() } else { error("user-session browser launch failed") });
                        } else { response = error("expired browser request"); }
                    },
                    Request::State { token: supplied, state } => {
                        if supplied != token || child.is_none() { response = error("stale worker"); }
                        else if stopping.is_none() {
                            if state == "Running" { status.last_error = None; }
                            status.state = state;
                        }
                    },
                    Request::Browser { token: supplied, url, background } => {
                        if supplied != token || child.is_none() || stopping.is_some() || !connected || !status.agent_present || url != config.saml_url() {
                            response = error("browser request has no active authorized session");
                        } else {
                            pending = Some(PendingBrowser { value: Browser { id: rand::random(), url, background }, reply, expires: Instant::now() + Duration::from_secs(8), delivered: false });
                            continue;
                        }
                    },
                    Request::Logs {} => {
                        use std::io::{Read, Seek, SeekFrom};
                        match File::open(LOG) {
                            Ok(mut f) => {
                                let len = f.metadata()?.len(); f.seek(SeekFrom::Start(len.saturating_sub(4096)))?;
                                let mut buf = Vec::new(); f.read_to_end(&mut buf)?;
                                response.logs = Some(String::from_utf8_lossy(&buf).into_owned());
                            },
                            Err(e) => response = error(e),
                        }
                    },
                }
                let _ = reply.send(response);
            },
        }
        if pending
            .as_ref()
            .is_some_and(|p| p.reply.is_closed() || p.expires <= Instant::now())
        {
            pending = None;
        }
        if !connected || !status.agent_present || quitting {
            begin_stop(&child, &mut stopping);
            pending = None;
        }
        if let Some(c) = child.as_mut() {
            if stopping.is_some_and(|d| Instant::now() >= d) {
                let _ = c.start_kill();
            }
            if let Some(exit) = c.try_wait()? {
                let intentional = stopping.take().is_some();
                if !intentional {
                    needs_attention = worker_exit_attention(&status.state);
                    status.last_error = Some(format!(
                        "VPN worker exited: {exit}; {}",
                        if needs_attention.is_some() {
                            "use forti-client ctl authenticate after checking logs"
                        } else {
                            "retry in 30 seconds"
                        }
                    ));
                    next_start = Instant::now() + Duration::from_secs(30);
                }
                child = None;
                status.worker_pid = None;
                pending = None;
                cleanup_needed = true;
            }
        }
        if stopping.is_some() {
            status.state = "CleaningUp".into();
        }
        if child.is_none() {
            if cleanup_needed {
                match cleanup().await {
                    Ok(()) => cleanup_needed = false,
                    Err(e) => {
                        status.state = "CleanupFailed".into();
                        status.last_error = Some(e.to_string());
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                }
            }
            if quitting {
                break;
            }
            if !connected {
                status.state = "Paused".into();
            } else if !status.agent_present {
                status.state = "WaitingForLoginAgent".into();
            } else if let Some(ref state) = needs_attention {
                status.state = state.clone();
                status.retry_in_seconds = 0;
            } else if Instant::now() < next_start {
                status.state = "WaitingToRetry".into();
            } else {
                token = format!("{:032x}", rand::random::<u128>());
                match spawn_worker(&config, &token, foreground) {
                    Ok(c) => {
                        child = Some(c);
                        foreground = false;
                        status.state = "Starting".into();
                    }
                    Err(e) => {
                        status.last_error = Some(e.to_string());
                        next_start = Instant::now() + Duration::from_secs(30);
                    }
                }
            }
        }
    }
    accept.abort();
    let _ = std::fs::remove_file(SOCKET);
    Ok(())
}

pub async fn agent() -> Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        bail!("agent must run as the logged-in user");
    }
    loop {
        if let Ok(response) = request(Request::Poll {}).await {
            if let Some(browser) = response.browser {
                let mut cmd = Command::new("/usr/bin/open");
                if browser.background {
                    cmd.arg("-g");
                }
                let result = tokio::time::timeout(
                    Duration::from_secs(5),
                    cmd.arg(&browser.url).kill_on_drop(true).status(),
                )
                .await;
                let success = matches!(result, Ok(Ok(s)) if s.success());
                let _ = request(Request::BrowserDone {
                    id: browser.id,
                    success,
                })
                .await;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub async fn control(args: &[String]) -> Result<()> {
    const USAGE: &str = "usage: forti-client ctl status [--json] | pause | resume | reconnect | authenticate | logs";
    let command = args.first().map(String::as_str).unwrap_or("status");
    if args.len() == 1 && matches!(command, "--help" | "-h" | "help") {
        println!("{USAGE}");
        return Ok(());
    }
    if args.len() > 2 || (args.len() == 2 && (command != "status" || args[1] != "--json")) {
        bail!("invalid control arguments");
    }
    let value = match command {
        "status" => Request::Status {},
        "pause" => Request::Pause {},
        "resume" => Request::Resume {},
        "reconnect" => Request::Reconnect {},
        "authenticate" => Request::Authenticate {},
        "logs" => Request::Logs {},
        _ => bail!("{USAGE}"),
    };
    let response = request(value).await?;
    if let Some(logs) = response.logs {
        print!("{logs}");
    } else if let Some(status) = response.status {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else if command == "pause" {
        tokio::time::timeout(Duration::from_secs(28), async {
            loop {
                let status = request(Request::Status {})
                    .await?
                    .status
                    .context("missing status")?;
                if status.state == "Paused" {
                    println!("Paused; VPN cleanup complete.");
                    return Ok::<(), anyhow::Error>(());
                }
                if status.state == "CleanupFailed" {
                    bail!("cleanup failed: {:?}", status.last_error);
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .context("pause saved, but cleanup has not completed; inspect forti-client ctl status")??;
    } else {
        println!("Request accepted; use forti-client ctl status to check progress.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_rejects_unknown_fields_and_commands() {
        assert!(serde_json::from_str::<Request>(r#"{"command":"pause","shell":"bad"}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"command":"exec"}"#).is_err());
    }
    #[test]
    fn worker_events_require_root() {
        let req = Request::State {
            token: "x".into(),
            state: "Running".into(),
        };
        assert!(!authorized(501, 501, &req));
        assert!(authorized(0, 501, &req));
        assert!(!authorized(502, 501, &Request::Pause {}));
        assert!(authorized(501, 501, &Request::Pause {}));
    }
    #[test]
    fn pause_persists_and_corruption_does_not_resume() {
        let dir = std::env::temp_dir().join(format!("forti-intent-{}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("intent.json");
        assert!(read_intent(&path).is_err());
        write_intent(&path, false).unwrap();
        assert!(!read_intent(&path).unwrap());
        write_intent(&path, true).unwrap();
        assert!(read_intent(&path).unwrap());
        std::fs::write(&path, b"broken").unwrap();
        assert!(read_intent(&path).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn exclusive_lock_rejects_second_owner() {
        let path = std::env::temp_dir().join(format!("forti-lock-{}", rand::random::<u64>()));
        let first = lock(path.to_str().unwrap()).unwrap();
        assert!(lock(path.to_str().unwrap()).is_err());
        drop(first);
        assert!(lock(path.to_str().unwrap()).is_ok());
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn protocol_bounds_and_frames_messages() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(b"{\"command\":\"pause\"}\n").await.unwrap();
        assert!(matches!(
            read_message::<Request>(&mut b).await.unwrap(),
            Request::Pause {}
        ));
        let writer = tokio::spawn(async move {
            a.write_all(&vec![b'x'; MAX_MESSAGE as usize + 1])
                .await
                .unwrap();
        });
        assert!(read_message::<Request>(&mut b).await.is_err());
        writer.await.unwrap();
    }
}
