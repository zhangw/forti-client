//! Low-frequency, process-local diagnostics. No environment secrets are collected.
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(60);
const LOG_LIMIT: u64 = 5 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdLimits {
    // None inside a known limit means RLIM_INFINITY, not a failed measurement.
    pub soft: Option<u64>,
    pub hard: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resources {
    pub pid: u32,
    pub sampled_at: u64,
    pub fd_count: Option<u32>,
    pub fd_error: Option<String>,
    pub limits: Option<FdLimits>,
    pub limits_error: Option<String>,
}

pub fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn fd_limits() -> io::Result<FdLimits> {
    let mut value = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, value.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let value = unsafe { value.assume_init() };
    Ok(FdLimits {
        soft: (value.rlim_cur != libc::RLIM_INFINITY).then_some(value.rlim_cur),
        hard: (value.rlim_max != libc::RLIM_INFINITY).then_some(value.rlim_max),
    })
}

fn fd_count(pid: u32) -> io::Result<u32> {
    let size = std::mem::size_of::<libc::proc_fdinfo>();
    let required = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDLISTFDS,
            0,
            std::ptr::null_mut(),
            0,
        )
    };
    if required <= 0 {
        return Err(io::Error::last_os_error());
    }
    let mut capacity = required as usize / size + 32;
    // Allow concurrent descriptor churn without reporting a truncated list.
    for _ in 0..3 {
        let mut entries: Vec<libc::proc_fdinfo> = Vec::with_capacity(capacity);
        let bytes = i32::try_from(capacity * size).map_err(io::Error::other)?;
        let used = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDLISTFDS,
                0,
                entries.as_mut_ptr().cast(),
                bytes,
            )
        };
        if used <= 0 {
            return Err(io::Error::last_os_error());
        }
        if used < bytes && (used as usize).is_multiple_of(size) {
            return Ok((used as usize / size) as u32);
        }
        capacity *= 2;
    }
    Err(io::Error::other("FD list changed during sampling"))
}

impl Resources {
    fn from_results(pid: u32, count: io::Result<u32>, limits: io::Result<FdLimits>) -> Self {
        let (fd_count, fd_error) = match count {
            Ok(n) => (Some(n), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let (limits, limits_error) = match limits {
            Ok(n) => (Some(n), None),
            Err(e) => (None, Some(e.to_string())),
        };
        Self {
            pid,
            sampled_at: unix_time(),
            fd_count,
            fd_error,
            limits,
            limits_error,
        }
    }

    pub fn current() -> Self {
        let pid = std::process::id();
        Self::from_results(pid, fd_count(pid), fd_limits())
    }

    pub fn condition(&self) -> &'static str {
        if self.fd_error.is_some() || self.limits_error.is_some() {
            return "unknown";
        }
        match (self.fd_count, self.limits.as_ref().and_then(|l| l.soft)) {
            (Some(count), Some(limit)) if u64::from(count) * 100 >= limit.saturating_mul(80) => {
                "high"
            }
            _ => "normal",
        }
    }
}

pub fn log_startup(role: &str) -> Resources {
    let resources = Resources::current();
    let proxy_present: Vec<_> = [
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    ]
    .into_iter()
    .filter(|name| std::env::var_os(name).is_some())
    .collect();
    tracing::info!(role, version = env!("CARGO_PKG_VERSION"), pid = resources.pid,
        ppid = unsafe { libc::getppid() }, uid = unsafe { libc::getuid() },
        euid = unsafe { libc::geteuid() }, cwd = ?std::env::current_dir().ok(),
        path = ?std::env::var_os("PATH"), ?proxy_present,
        resources = %serde_json::to_string(&resources).unwrap_or_default(), "Process started");
    resources
}

pub fn log_resource_change(previous: &Resources, current: &Resources) {
    if previous.condition() != current.condition() {
        tracing::info!(condition = current.condition(),
            resources = %serde_json::to_string(current).unwrap_or_default(), "Resource condition changed");
    }
}

/// First event, then at most one repeated error per interval. Recovery resets it.
#[derive(Default)]
pub struct ErrorThrottle {
    last: Option<Instant>,
}

impl ErrorThrottle {
    pub fn allow(&mut self) -> bool {
        if self
            .last
            .is_some_and(|t| t.elapsed() < Duration::from_secs(30))
        {
            return false;
        }
        self.last = Some(Instant::now());
        true
    }
    pub fn reset(&mut self) {
        self.last = None;
    }
}

struct RollingFile {
    path: PathBuf,
    file: File,
    size: u64,
    limit: u64,
}

impl RollingFile {
    fn open(path: &Path, limit: u64) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err(io::Error::other(
                "diagnostic log must be a private owned regular file",
            ));
        }
        Ok(Self {
            path: path.into(),
            file,
            size: meta.len(),
            limit,
        })
    }

    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() as u64 > self.limit {
            return Err(io::Error::other("diagnostic event exceeds log size limit"));
        }
        if self.size + bytes.len() as u64 > self.limit {
            // Keep the current FD open until replacement succeeds. EMFILE must
            // not prevent recording the error on an already-open descriptor.
            let temporary = self.path.with_extension("next");
            let replacement = Self::open(&temporary, self.limit)?;
            replacement.file.set_len(0)?;
            std::fs::rename(&self.path, self.path.with_extension("log.1"))?;
            std::fs::rename(&temporary, &self.path)?;
            self.file = replacement.file;
            self.size = 0;
        }
        self.file.write_all(bytes)?;
        self.size += bytes.len() as u64;
        Ok(())
    }
}

#[derive(Clone)]
struct LogWriter(Arc<Mutex<(Option<RollingFile>, ErrorThrottle)>>);

fn syslog(message: &[u8]) {
    let text = String::from_utf8_lossy(message).replace('\0', "?");
    if let Ok(text) = std::ffi::CString::new(text) {
        unsafe {
            libc::syslog(libc::LOG_ERR, c"forti-client: %s".as_ptr(), text.as_ptr());
        }
    }
}

impl Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        match &mut guard.0 {
            Some(log) => {
                if let Err(e) = log.append(bytes) {
                    // Do not grow past the rotation limit if disk/FD exhaustion
                    // prevents rotation. Emit a rate-limited system-log fallback.
                    if guard.1.allow() {
                        syslog(
                            format!(
                                "diagnostic log write failed: {e}; {}",
                                String::from_utf8_lossy(bytes)
                            )
                            .as_bytes(),
                        );
                    }
                }
            }
            None => {
                if guard.1.allow() {
                    syslog(bytes);
                }
            }
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn init_logging(role: &str) {
    let path = if role == "daemon" {
        PathBuf::from("/Library/Logs/FortiClient/daemon.log")
    } else {
        // Agent runs as the user; it cannot write the daemon's root-owned log.
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("Library/Logs/FortiClient/agent.log")
    };
    let opened = (|| {
        let parent = path.parent().unwrap();
        std::fs::create_dir_all(parent)?;
        RollingFile::open(&path, LOG_LIMIT)
    })();
    let log = match opened {
        Ok(log) => Some(log),
        Err(e) => {
            syslog(format!("{role} log initialization failed: {e}").as_bytes());
            None
        }
    };
    let writer = LogWriter(Arc::new(Mutex::new((log, ErrorThrottle::default()))));
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter("info")
        .with_writer(move || writer.clone())
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_measurement_is_unknown_not_zero() {
        let snapshot = Resources::from_results(
            1,
            Err(io::Error::from_raw_os_error(libc::EPERM)),
            Err(io::Error::from_raw_os_error(libc::EINVAL)),
        );
        assert_eq!(snapshot.fd_count, None);
        assert!(snapshot.limits.is_none());
        assert_eq!(snapshot.condition(), "unknown");
    }
    #[test]
    fn rotation_preserves_latest_files_and_rejects_symlinks() {
        let dir = std::env::temp_dir().join(format!("forti-log-{}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("daemon.log");
        let mut log = RollingFile::open(&path, 6).unwrap();
        log.append(b"first").unwrap();
        log.append(b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert_eq!(std::fs::read(dir.join("daemon.log.1")).unwrap(), b"first");
        log.append(b"third").unwrap();
        assert_eq!(std::fs::read(dir.join("daemon.log.1")).unwrap(), b"second");
        let link = dir.join("link.log");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(RollingFile::open(&link, 6).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn self_sampling_observes_open_descriptors() {
        let files: Vec<_> = (0..64).map(|_| File::open("/dev/null").unwrap()).collect();
        assert!(fd_count(std::process::id()).unwrap() >= files.len() as u32);
        assert!(fd_limits().is_ok());
        drop(files);
    }
}
