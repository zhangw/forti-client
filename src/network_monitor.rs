use core_foundation::runloop::{kCFRunLoopCommonModes, CFRunLoop};
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

/// Watches network reachability to the VPN server and sends events via channel.
pub struct NetworkMonitor {
    _thread: std::thread::JoinHandle<()>,
}

impl NetworkMonitor {
    /// Start monitoring reachability to the given address.
    /// Returns the monitor handle and a receiver for network events.
    pub fn start(server_addr: SocketAddr) -> Result<(Self, mpsc::Receiver<NetworkEvent>), String> {
        let (tx, rx) = mpsc::channel(16);

        let thread = std::thread::Builder::new()
            .name("network-monitor".into())
            .spawn(move || {
                Self::run_reachability(server_addr, tx);
            })
            .map_err(|e| format!("failed to spawn network monitor thread: {}", e))?;

        Ok((Self { _thread: thread }, rx))
    }

    fn run_reachability(addr: SocketAddr, tx: mpsc::Sender<NetworkEvent>) {
        let mut reachability = SCNetworkReachability::from(addr);

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
                if tx_clone.blocking_send(event).is_err() {
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
            reachability
                .schedule_with_runloop(&CFRunLoop::get_current(), kCFRunLoopCommonModes)
        }
        .is_err()
        {
            warn!("Failed to schedule reachability with run loop");
            return;
        }

        info!("Network monitor started for {}", addr);
        CFRunLoop::run_current();
        debug!("Network monitor thread exiting");
    }
}
