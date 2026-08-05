use core_foundation::runloop::{kCFRunLoopCommonModes, CFRunLoop};
use std::ffi::CString;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use system_configuration::network_reachability::{ReachabilityFlags, SCNetworkReachability};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Network reachability events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkEvent {
    /// Network path to VPN server is available.
    Reachable,
    /// Network path to VPN server is unavailable.
    Unreachable,
}

/// The target whose reachability the monitor watches.
///
/// A resolved [`SocketAddr`] is preferred: it is watched directly and never
/// resolved through the system DNS, which a live tunnel may have redirected to
/// VPN-internal servers. Watching the hostname instead resolves it once through
/// whatever resolver is active when the monitor starts — if that is VPN DNS,
/// the monitor can end up watching a VPN-internal address that goes unreachable
/// the moment the tunnel drops, stalling every reconnect. The hostname variant
/// is retained only as a fallback for when no address was pinned at startup.
#[derive(Debug)]
pub enum ReachabilityTarget {
    /// Watch a specific resolved address (no DNS lookup).
    Address(SocketAddr),
    /// Resolve and monitor by hostname (fallback when no address is pinned).
    Host(String),
}

/// Watches network reachability to the VPN server and sends events via channel.
pub struct NetworkMonitor {
    _thread: std::thread::JoinHandle<()>,
}

impl NetworkMonitor {
    /// Start monitoring reachability to the given target.
    /// Returns the monitor handle and a receiver for network events.
    pub fn start(
        target: ReachabilityTarget,
    ) -> Result<(Self, mpsc::UnboundedReceiver<NetworkEvent>), String> {
        let (tx, rx) = mpsc::unbounded_channel();

        let thread = std::thread::Builder::new()
            .name("network-monitor".into())
            .spawn(move || {
                Self::run_reachability(target, tx);
            })
            .map_err(|e| format!("failed to spawn network monitor thread: {}", e))?;

        Ok((Self { _thread: thread }, rx))
    }

    fn run_reachability(target: ReachabilityTarget, tx: mpsc::UnboundedSender<NetworkEvent>) {
        // Build the reachability reference from the pinned address when we have
        // one. SCNetworkReachabilityCreateWithAddress watches the IP directly
        // and never consults the system resolver, so a tunnel that installs
        // VPN-internal DNS cannot poison it.
        let (mut reachability, label) = match target {
            ReachabilityTarget::Address(addr) => {
                let r = SCNetworkReachability::from(addr);
                (r, addr.to_string())
            }
            ReachabilityTarget::Host(host) => {
                let c_host = match CString::new(host.as_str()) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("Invalid hostname for reachability: {}", e);
                        return;
                    }
                };
                match SCNetworkReachability::from_host(&c_host) {
                    Some(r) => (r, host),
                    None => {
                        warn!("Failed to create SCNetworkReachability for {host}");
                        return;
                    }
                }
            }
        };

        // Track last known state to only send events on transitions.
        // Using AtomicBool because the callback is Fn (not FnMut).
        let last_reachable: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let first_callback = Arc::new(AtomicBool::new(true));
        let last_reachable_clone = last_reachable.clone();
        let first_callback_clone = first_callback.clone();
        let tx_clone = tx.clone();

        let callback = move |flags: ReachabilityFlags| {
            let reachable = flags.contains(ReachabilityFlags::REACHABLE)
                && !flags.contains(ReachabilityFlags::CONNECTION_REQUIRED);

            debug!(
                "Network reachability changed: flags={:?}, reachable={}",
                flags, reachable
            );

            // Only send events on actual transitions (or first callback)
            let is_first = first_callback_clone.swap(false, Ordering::Relaxed);
            let was_reachable = last_reachable_clone.swap(reachable, Ordering::Relaxed);

            if is_first || was_reachable != reachable {
                let event = if reachable {
                    NetworkEvent::Reachable
                } else {
                    NetworkEvent::Unreachable
                };
                if tx_clone.send(event).is_err() {
                    debug!("Network monitor channel closed, stopping");
                    CFRunLoop::get_current().stop();
                }
            }
        };

        if reachability.set_callback(callback).is_err() {
            warn!("Failed to set reachability callback");
            return;
        }

        // SAFETY: kCFRunLoopCommonModes is a valid Apple-provided run loop mode
        if unsafe {
            reachability.schedule_with_runloop(&CFRunLoop::get_current(), kCFRunLoopCommonModes)
        }
        .is_err()
        {
            warn!("Failed to schedule reachability with run loop");
            return;
        }

        info!("Network monitor started for {}", label);
        CFRunLoop::run_current();
        debug!("Network monitor thread exiting");
    }
}
