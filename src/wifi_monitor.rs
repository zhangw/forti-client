use core_foundation::array::CFArray;
use core_foundation::runloop::{kCFRunLoopCommonModes, CFRunLoop};
use core_foundation::string::CFString;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use system_configuration::dynamic_store::{
    SCDynamicStore, SCDynamicStoreBuilder, SCDynamicStoreCallBackContext,
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Wi-Fi association change event.
///
/// `ssid` is `None` when no Wi-Fi is associated — or when the SSID could not
/// be determined (query failure). Consumers treat `None` as untrusted, so a
/// broken query fails open toward establishing the VPN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiEvent {
    pub ssid: Option<String>,
}

/// How long to wait for the AirPort state to settle before querying the SSID.
/// The dynamic store key fires several times during a single association.
const DEBOUNCE_QUIET: Duration = Duration::from_millis(500);
/// Hard deadline for one `system_profiler` invocation.
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Watches Wi-Fi association changes and reports the current SSID via channel.
///
/// Modern macOS redacts the SSID from the usual unprivileged sources
/// (`SSID_STR` in the dynamic store is empty, `ipconfig` prints `<redacted>`),
/// so change *detection* and SSID *retrieval* are split: an SCDynamicStore
/// watch on the AirPort state keys detects that something changed, and a
/// dedicated query thread resolves the actual SSID with `system_profiler`
/// (~1-2s). The slow query never runs on the run-loop callback or any
/// consumer path — consumers only ever receive already-resolved events.
pub struct WifiMonitor {
    _watch_thread: std::thread::JoinHandle<()>,
    _query_thread: std::thread::JoinHandle<()>,
}

impl WifiMonitor {
    /// Start monitoring Wi-Fi association changes.
    /// Returns the monitor handle and a receiver for Wi-Fi events. The
    /// current state is queried immediately and always emitted as the first
    /// event, so consumers learn the starting SSID without racing.
    pub fn start() -> Result<(Self, mpsc::UnboundedReceiver<WifiEvent>), String> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (tick_tx, tick_rx) = std::sync::mpsc::channel::<()>();

        let watch_thread = std::thread::Builder::new()
            .name("wifi-monitor".into())
            .spawn(move || run_airport_watch(tick_tx))
            .map_err(|e| format!("failed to spawn wifi monitor thread: {}", e))?;

        let query_thread = std::thread::Builder::new()
            .name("wifi-ssid-query".into())
            .spawn(move || run_ssid_queries(tick_rx, event_tx))
            .map_err(|e| format!("failed to spawn wifi ssid query thread: {}", e))?;

        Ok((
            Self {
                _watch_thread: watch_thread,
                _query_thread: query_thread,
            },
            event_rx,
        ))
    }
}

/// Run-loop thread: watches the AirPort dynamic-store keys and forwards a
/// bare tick per change. No I/O happens here — the callback must return
/// quickly, and the SSID is redacted in the store anyway.
fn run_airport_watch(tick_tx: std::sync::mpsc::Sender<()>) {
    fn callback(
        _store: SCDynamicStore,
        changed_keys: CFArray<CFString>,
        tick_tx: &mut std::sync::mpsc::Sender<()>,
    ) {
        debug!("AirPort state changed ({} keys)", changed_keys.len());
        if tick_tx.send(()).is_err() {
            debug!("Wi-Fi monitor channel closed, stopping");
            CFRunLoop::get_current().stop();
        }
    }

    let store = SCDynamicStoreBuilder::new("forti-client-wifi")
        .callback_context(SCDynamicStoreCallBackContext {
            callout: callback,
            info: tick_tx,
        })
        .build();

    let keys = CFArray::<CFString>::from_CFTypes(&[]);
    let patterns = CFArray::from_CFTypes(&[CFString::new("State:/Network/Interface/.*/AirPort")]);
    if !store.set_notification_keys(&keys, &patterns) {
        warn!("Failed to register AirPort state notification keys");
        return;
    }

    let source = store.create_run_loop_source();
    let run_loop = CFRunLoop::get_current();
    run_loop.add_source(&source, unsafe { kCFRunLoopCommonModes });

    info!("Wi-Fi monitor started");
    CFRunLoop::run_current();
    debug!("Wi-Fi monitor thread exiting");
}

/// Query thread: debounces ticks from the watch thread, resolves the SSID via
/// `system_profiler` (slow, so isolated here), and emits transition events.
fn run_ssid_queries(
    tick_rx: std::sync::mpsc::Receiver<()>,
    event_tx: mpsc::UnboundedSender<WifiEvent>,
) {
    // Always report the starting state, even before any change fires.
    let mut last_ssid = query_current_ssid();
    if event_tx
        .send(WifiEvent {
            ssid: last_ssid.clone(),
        })
        .is_err()
    {
        return;
    }

    loop {
        if tick_rx.recv().is_err() {
            debug!("Wi-Fi watch thread gone, stopping SSID queries");
            return;
        }
        // Drain further ticks until the AirPort state has been quiet for the
        // debounce window — association fires the key several times.
        while tick_rx.recv_timeout(DEBOUNCE_QUIET).is_ok() {}

        let ssid = query_current_ssid();
        if ssid != last_ssid {
            debug!(?ssid, "Wi-Fi association changed");
            last_ssid = ssid.clone();
            // Exiting drops tick_rx, which stops the watch thread on its
            // next tick.
            if event_tx.send(WifiEvent { ssid }).is_err() {
                return;
            }
        }
    }
}

/// Resolve the currently associated SSID, or `None` when not on Wi-Fi or the
/// query fails. `system_profiler` is the only unprivileged source that still
/// reveals the SSID on modern macOS; `-detailLevel mini` is *not* used
/// because it intermittently omits the current-network section entirely.
fn query_current_ssid() -> Option<String> {
    let mut child = match Command::new("/usr/sbin/system_profiler")
        .args(["SPAirPortDataType", "-json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            warn!(%error, "Failed to spawn system_profiler for SSID query");
            return None;
        }
    };

    // Drain stdout on its own thread while waiting: the full report lists
    // every nearby network and can exceed the pipe buffer, and a child
    // blocked on a full pipe never exits — turning the timeout below into a
    // spurious kill (and a spurious "untrusted" result). The reader hits EOF
    // when the child exits or is killed.
    let mut stdout = child.stdout.take()?;
    let reader = match std::thread::Builder::new()
        .name("wifi-ssid-read".into())
        .spawn(move || {
            let mut json = String::new();
            let _ = stdout.read_to_string(&mut json);
            json
        }) {
        Ok(handle) => handle,
        Err(error) => {
            warn!(%error, "Failed to spawn system_profiler reader thread");
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
    };

    let deadline = Instant::now() + QUERY_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    warn!(%status, "system_profiler SSID query failed");
                    let _ = reader.join();
                    return None;
                }
                break;
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    warn!("system_profiler SSID query timed out, killing it");
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                warn!(%error, "Failed to wait for system_profiler");
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return None;
            }
        }
    }

    let json = reader.join().ok()?;
    parse_system_profiler_ssid(&json)
}

/// Extract the associated SSID from `system_profiler SPAirPortDataType -json`
/// output: the `_name` of the first interface carrying
/// `spairport_current_network_information`. Any missing key means no
/// association (or an output-format change) and yields `None`.
pub fn parse_system_profiler_ssid(json: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let interfaces = value
        .get("SPAirPortDataType")?
        .get(0)?
        .get("spairport_airport_interfaces")?
        .as_array()?;
    interfaces
        .iter()
        .filter_map(|iface| iface.get("spairport_current_network_information"))
        .filter_map(|network| network.get("_name")?.as_str())
        .map(str::to_owned)
        .next()
}

#[cfg(test)]
mod tests {
    use super::parse_system_profiler_ssid;

    fn wrap(interfaces_json: &str) -> String {
        format!(
            r#"{{"SPAirPortDataType": [{{"_name": "spairport_information",
                "spairport_airport_interfaces": {interfaces_json}}}]}}"#
        )
    }

    #[test]
    fn parses_associated_interface_ssid() {
        let json = wrap(
            r#"[{"_name": "en0",
                 "spairport_current_network_information": {"_name": "OfficeNet",
                     "spairport_network_phymode": "802.11ax"}}]"#,
        );
        assert_eq!(
            parse_system_profiler_ssid(&json).as_deref(),
            Some("OfficeNet")
        );
    }

    #[test]
    fn returns_none_when_no_interface_is_associated() {
        let json = wrap(r#"[{"_name": "en0", "spairport_status_information": "off"}]"#);
        assert_eq!(parse_system_profiler_ssid(&json), None);
    }

    #[test]
    fn returns_none_on_malformed_json() {
        assert_eq!(parse_system_profiler_ssid("not json"), None);
        assert_eq!(parse_system_profiler_ssid("{}"), None);
        assert_eq!(
            parse_system_profiler_ssid(r#"{"SPAirPortDataType": []}"#),
            None
        );
    }

    #[test]
    fn skips_unassociated_interfaces() {
        let json = wrap(
            r#"[{"_name": "awdl0"},
                {"_name": "en0",
                 "spairport_current_network_information": {"_name": "HomeNet"}}]"#,
        );
        assert_eq!(
            parse_system_profiler_ssid(&json).as_deref(),
            Some("HomeNet")
        );
    }
}
