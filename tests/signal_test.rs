#![cfg(target_os = "macos")]

use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

static SIGNAL_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn ctrl_c_during_initial_saml_wait_exits_within_one_second() {
    let _guard = SIGNAL_TEST_LOCK.lock().unwrap();
    let binary = env!("CARGO_BIN_EXE_forti-client");
    let mut child = Command::new(binary)
        .args(["--server", "127.0.0.1", "--port", "1", "--saml"])
        .env("FORTI_CLIENT_TEST_BROWSER_LAUNCHER", "/usr/bin/true")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn forti-client");

    thread::sleep(Duration::from_millis(150));
    let signal_status = Command::new("/bin/kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("send SIGINT");
    assert!(
        signal_status.success(),
        "child exited before SIGINT was sent"
    );

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            assert!(
                status.success(),
                "first Ctrl+C should exit gracefully: {status}"
            );
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("forti-client did not exit within one second of Ctrl+C");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn second_ctrl_c_forces_exit_130_within_one_second() {
    let _guard = SIGNAL_TEST_LOCK.lock().unwrap();
    let binary = env!("CARGO_BIN_EXE_forti-client");
    let mut child = Command::new(binary)
        .args(["--server", "127.0.0.1", "--port", "1", "--saml"])
        .env("FORTI_CLIENT_TEST_BROWSER_LAUNCHER", "/usr/bin/true")
        .env("FORTI_CLIENT_TEST_STALL_ON_SHUTDOWN", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn forti-client");

    thread::sleep(Duration::from_millis(150));
    let pid = child.id().to_string();
    assert!(Command::new("/bin/kill")
        .args(["-INT", &pid])
        .status()
        .expect("send first SIGINT")
        .success());
    thread::sleep(Duration::from_millis(100));
    assert!(child.try_wait().expect("poll after first SIGINT").is_none());

    assert!(Command::new("/bin/kill")
        .args(["-INT", &pid])
        .status()
        .expect("send second SIGINT")
        .success());

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            assert_eq!(status.code(), Some(130));
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("second Ctrl+C did not force exit within one second");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// SIGTERM must take the same graceful path as SIGINT.
///
/// `kill`, launchd, and system shutdown all send SIGTERM. Before it was
/// handled, those paths terminated the process via the default disposition
/// without running cleanup, leaving the VPN DNS key installed and breaking
/// name resolution machine-wide.
#[test]
fn sigterm_exits_gracefully_like_ctrl_c() {
    let _guard = SIGNAL_TEST_LOCK.lock().unwrap();
    let binary = env!("CARGO_BIN_EXE_forti-client");
    let mut child = Command::new(binary)
        .args(["--server", "127.0.0.1", "--port", "1", "--saml"])
        .env("FORTI_CLIENT_TEST_BROWSER_LAUNCHER", "/usr/bin/true")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn forti-client");

    thread::sleep(Duration::from_millis(150));
    let signal_status = Command::new("/bin/kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(
        signal_status.success(),
        "child exited before SIGTERM was sent"
    );

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            assert!(
                status.success(),
                "SIGTERM must exit gracefully instead of falling through to \
                 the default disposition: {status}"
            );
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("forti-client did not exit within one second of SIGTERM");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// A second SIGTERM forces exit, matching the SIGINT override semantics.
#[test]
fn second_sigterm_forces_exit_130() {
    let _guard = SIGNAL_TEST_LOCK.lock().unwrap();
    let binary = env!("CARGO_BIN_EXE_forti-client");
    let mut child = Command::new(binary)
        .args(["--server", "127.0.0.1", "--port", "1", "--saml"])
        .env("FORTI_CLIENT_TEST_BROWSER_LAUNCHER", "/usr/bin/true")
        .env("FORTI_CLIENT_TEST_STALL_ON_SHUTDOWN", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn forti-client");

    thread::sleep(Duration::from_millis(150));
    let pid = child.id().to_string();
    assert!(Command::new("/bin/kill")
        .args(["-TERM", &pid])
        .status()
        .expect("send first SIGTERM")
        .success());
    thread::sleep(Duration::from_millis(100));
    assert!(child
        .try_wait()
        .expect("poll after first SIGTERM")
        .is_none());

    assert!(Command::new("/bin/kill")
        .args(["-TERM", &pid])
        .status()
        .expect("send second SIGTERM")
        .success());

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            assert_eq!(status.code(), Some(130));
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("second SIGTERM did not force exit within one second");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Mixed signal types must share one counter, so SIGINT-then-SIGTERM forces
/// exit rather than restarting the graceful sequence.
#[test]
fn sigint_then_sigterm_forces_exit_130() {
    let _guard = SIGNAL_TEST_LOCK.lock().unwrap();
    let binary = env!("CARGO_BIN_EXE_forti-client");
    let mut child = Command::new(binary)
        .args(["--server", "127.0.0.1", "--port", "1", "--saml"])
        .env("FORTI_CLIENT_TEST_BROWSER_LAUNCHER", "/usr/bin/true")
        .env("FORTI_CLIENT_TEST_STALL_ON_SHUTDOWN", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn forti-client");

    thread::sleep(Duration::from_millis(150));
    let pid = child.id().to_string();
    assert!(Command::new("/bin/kill")
        .args(["-INT", &pid])
        .status()
        .expect("send SIGINT")
        .success());
    thread::sleep(Duration::from_millis(100));
    assert!(child.try_wait().expect("poll after SIGINT").is_none());

    assert!(Command::new("/bin/kill")
        .args(["-TERM", &pid])
        .status()
        .expect("send SIGTERM")
        .success());

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            assert_eq!(status.code(), Some(130));
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("SIGTERM after SIGINT did not force exit within one second");
        }
        thread::sleep(Duration::from_millis(20));
    }
}
