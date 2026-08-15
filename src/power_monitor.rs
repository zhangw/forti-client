use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// How long `PowerMonitor::start` waits for the monitor thread to finish its
/// IOKit registration before giving up on it.
const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(5);

/// System capabilities published by the macOS power-management root domain.
///
/// `known == false` is the initial level: IOKit has not delivered a capability
/// notification yet, so the boolean fields must not be treated as authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerCapabilities {
    pub known: bool,
    pub cpu: bool,
    pub network: bool,
    pub graphics: bool,
}

impl PowerCapabilities {
    pub const UNKNOWN: Self = Self {
        known: false,
        cpu: false,
        network: false,
        graphics: false,
    };

    fn from_bits(bits: u32) -> Self {
        Self {
            known: true,
            cpu: bits & ffi::kIOPMSystemCapabilityCPU != 0,
            network: bits & ffi::kIOPMSystemCapabilityNetwork != 0,
            graphics: bits & ffi::kIOPMSystemCapabilityGraphics != 0,
        }
    }
}

impl Default for PowerCapabilities {
    fn default() -> Self {
        Self::UNKNOWN
    }
}

/// Power state events from macOS IOKit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerEvent {
    /// System is about to sleep. Acknowledge promptly.
    WillSleep,
    /// System has woken up. Network may not be ready yet.
    HasPoweredOn,
    /// Effective CPU, network, and graphics availability changed.
    Capabilities(PowerCapabilities),
}

/// Monitors macOS system power state changes via IOKit.
pub struct PowerMonitor {
    _thread: std::thread::JoinHandle<()>,
}

// IOKit FFI bindings (minimal subset for power management)
#[allow(non_upper_case_globals, dead_code)]
mod ffi {
    use std::os::raw::{c_char, c_int, c_uint, c_void};

    pub type IONotificationPortRef = *mut c_void;
    pub type IOReturn = c_int;
    pub type IOObject = c_uint;
    pub type CFDictionaryRef = *const c_void;

    pub const kIOMessageSystemWillSleep: u32 = 0xe0000280;
    pub const kIOMessageSystemHasPoweredOn: u32 = 0xe0000300;
    pub const kIOMessageCanSystemSleep: u32 = 0xe0000270;
    pub const kIOMessageSystemCapabilityChange: u32 = 0xe0000340;

    pub const kIOPMSystemCapabilityWillChange: u32 = 0x01;
    pub const kIOPMSystemCapabilityDidChange: u32 = 0x02;
    pub const kIOPMSystemCapabilityCPU: u32 = 0x01;
    pub const kIOPMSystemCapabilityGraphics: u32 = 0x02;
    pub const kIOPMSystemCapabilityNetwork: u32 = 0x08;

    pub const kIOReturnSuccess: IOReturn = 0;

    #[repr(C)]
    pub struct IOPMSystemCapabilityChangeParameters {
        pub notify_ref: u32,
        pub max_wait_for_reply: u32,
        pub change_flags: u32,
        pub reserved1: u32,
        pub from_capabilities: u32,
        pub to_capabilities: u32,
        pub reserved2: [u32; 4],
    }

    pub type IOServiceInterestCallback = extern "C" fn(
        refcon: *mut c_void,
        service: IOObject,
        message_type: u32,
        message_argument: *mut c_void,
    );

    extern "C" {
        pub fn IORegisterForSystemPower(
            refcon: *mut c_void,
            notify_port_ref: *mut IONotificationPortRef,
            callback: IOServiceInterestCallback,
            notifier: *mut IOObject,
        ) -> IOObject;

        pub fn IODeregisterForSystemPower(notifier: *mut IOObject) -> IOReturn;

        pub fn IOAllowPowerChange(kernel_port: IOObject, notification_id: isize) -> IOReturn;

        pub fn IOServiceClose(connect: IOObject) -> IOReturn;

        pub fn IOServiceMatching(name: *const c_char) -> CFDictionaryRef;

        pub fn IOServiceGetMatchingService(
            main_port: IOObject,
            matching: CFDictionaryRef,
        ) -> IOObject;

        pub fn IOServiceAddInterestNotification(
            notify_port: IONotificationPortRef,
            service: IOObject,
            interest_type: *const c_char,
            callback: IOServiceInterestCallback,
            refcon: *mut c_void,
            notification: *mut IOObject,
        ) -> IOReturn;

        pub fn IOObjectRelease(object: IOObject) -> IOReturn;

        pub fn IONotificationPortGetRunLoopSource(notify: IONotificationPortRef) -> *const c_void; // CFRunLoopSourceRef

        pub fn IONotificationPortDestroy(notify: IONotificationPortRef);
    }

    // CoreFoundation run loop bindings
    extern "C" {
        pub fn CFRunLoopGetCurrent() -> *const c_void;
        pub fn CFRunLoopAddSource(rl: *const c_void, source: *const c_void, mode: *const c_void);
        pub fn CFRunLoopRun();
        pub fn CFRunLoopStop(rl: *const c_void);
    }

    // kCFRunLoopDefaultMode
    extern "C" {
        pub static kCFRunLoopDefaultMode: *const c_void;
    }
}

struct PowerCallbackContext {
    tx: mpsc::UnboundedSender<PowerEvent>,
    root_port: ffi::IOObject,
    last_capabilities: PowerCapabilities,
}

fn effective_capabilities(
    parameters: &ffi::IOPMSystemCapabilityChangeParameters,
) -> Option<PowerCapabilities> {
    let bits = if parameters.change_flags & ffi::kIOPMSystemCapabilityDidChange != 0 {
        parameters.to_capabilities
    } else if parameters.change_flags & ffi::kIOPMSystemCapabilityWillChange != 0 {
        // Stop using capabilities before they disappear, but do not expose a
        // capability being added until IOKit confirms the transition completed.
        parameters.from_capabilities & parameters.to_capabilities
    } else if parameters.change_flags == 0 {
        // The root domain publishes the current level to a newly registered
        // client with neither transition flag set. It is the only authoritative
        // snapshot we ever get, so adopt it instead of staying at UNKNOWN.
        parameters.to_capabilities
    } else {
        return None;
    };
    Some(PowerCapabilities::from_bits(bits))
}

extern "C" fn power_callback(
    refcon: *mut std::os::raw::c_void,
    _service: ffi::IOObject,
    message_type: u32,
    message_argument: *mut std::os::raw::c_void,
) {
    // Read-only here: `capability_callback` owns the only `&mut` to this
    // context, so taking one we do not need would alias it for no reason.
    let ctx = unsafe { &*(refcon as *const PowerCallbackContext) };

    match message_type {
        ffi::kIOMessageSystemWillSleep => {
            debug!("IOKit: WillSleep");
            // Acknowledge sleep first to avoid delaying the system if channel is full
            unsafe {
                ffi::IOAllowPowerChange(ctx.root_port, message_argument as isize);
            }
            let _ = ctx.tx.send(PowerEvent::WillSleep);
        }
        ffi::kIOMessageCanSystemSleep => {
            // Allow system to sleep (don't veto)
            unsafe {
                ffi::IOAllowPowerChange(ctx.root_port, message_argument as isize);
            }
        }
        ffi::kIOMessageSystemHasPoweredOn => {
            debug!("IOKit: HasPoweredOn");
            let _ = ctx.tx.send(PowerEvent::HasPoweredOn);
        }
        _ => {
            debug!("IOKit: unknown power message 0x{:08x}", message_type);
        }
    }
}

extern "C" fn capability_callback(
    refcon: *mut std::os::raw::c_void,
    _service: ffi::IOObject,
    message_type: u32,
    message_argument: *mut std::os::raw::c_void,
) {
    if message_type != ffi::kIOMessageSystemCapabilityChange {
        return;
    }
    let ctx = unsafe { &mut *(refcon as *mut PowerCallbackContext) };
    let Some(parameters) = (unsafe {
        (message_argument as *const ffi::IOPMSystemCapabilityChangeParameters).as_ref()
    }) else {
        warn!("IOKit: capability change without parameters");
        return;
    };
    let Some(capabilities) = effective_capabilities(parameters) else {
        debug!(
            flags = parameters.change_flags,
            "IOKit: capability change with unknown flags"
        );
        return;
    };
    // A downgrade is published at WillChange so consumers stop work early.
    // Publish DidChange again even when the bitset is identical: a classic
    // WillSleep edge may have arrived between the two notifications and must
    // be cleared when CPU+network really remain available (for example under
    // a system sleep assertion / Dark Wake).
    let did_change = parameters.change_flags & ffi::kIOPMSystemCapabilityDidChange != 0;
    if did_change || capabilities != ctx.last_capabilities {
        ctx.last_capabilities = capabilities;
        debug!(?capabilities, "IOKit: system capabilities changed");
        let _ = ctx.tx.send(PowerEvent::Capabilities(capabilities));
    }
}

impl PowerMonitor {
    /// Start monitoring power state changes.
    /// Returns the monitor handle and a receiver for power events.
    pub fn start() -> Result<(Self, mpsc::UnboundedReceiver<PowerEvent>), String> {
        let (tx, rx) = mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);

        let thread = std::thread::Builder::new()
            .name("power-monitor".into())
            .spawn(move || {
                Self::run_power_loop(tx, ready_tx);
            })
            .map_err(|e| format!("failed to spawn power monitor thread: {}", e))?;

        // Bounded: this runs on an async worker, and an IOKit registration that
        // never returns must not make the process unkillable by Ctrl-C.
        match ready_rx.recv_timeout(REGISTRATION_TIMEOUT) {
            Ok(Ok(())) => Ok((Self { _thread: thread }, rx)),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // The thread is still blocked in IOKit; joining would inherit
                // that block, so leave it detached and fail startup.
                Err("power monitor registration did not complete within 5s".into())
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let _ = thread.join();
                Err("power monitor thread exited during initialization".into())
            }
        }
    }

    fn run_power_loop(
        tx: mpsc::UnboundedSender<PowerEvent>,
        ready_tx: std::sync::mpsc::SyncSender<Result<(), String>>,
    ) {
        unsafe {
            let mut notify_port: ffi::IONotificationPortRef = std::ptr::null_mut();
            let mut notifier: ffi::IOObject = 0;
            let mut capability_notifier: ffi::IOObject = 0;

            // Allocate context on the heap so it lives as long as the callback needs it
            let ctx = Box::new(PowerCallbackContext {
                tx,
                root_port: 0, // Will be set after registration
                last_capabilities: PowerCapabilities::UNKNOWN,
            });
            let ctx_ptr = Box::into_raw(ctx);

            // Classic registration owns sleep acknowledgement messages.
            let root_port = ffi::IORegisterForSystemPower(
                ctx_ptr as *mut std::os::raw::c_void,
                &mut notify_port,
                power_callback,
                &mut notifier,
            );

            if root_port == 0 {
                let error = "IORegisterForSystemPower failed".to_string();
                warn!(error);
                let _ = ready_tx.send(Err(error));
                let _ = Box::from_raw(ctx_ptr); // Clean up
                return;
            }

            // Set root_port in context so callback can use it for IOAllowPowerChange
            (*ctx_ptr).root_port = root_port;

            let matching = ffi::IOServiceMatching(c"IOPMrootDomain".as_ptr());
            if matching.is_null() {
                let error = "IOServiceMatching(IOPMrootDomain) failed".to_string();
                warn!(error);
                let _ = ready_tx.send(Err(error));
                ffi::IODeregisterForSystemPower(&mut notifier);
                ffi::IOServiceClose(root_port);
                ffi::IONotificationPortDestroy(notify_port);
                let _ = Box::from_raw(ctx_ptr);
                return;
            }

            let root_service = ffi::IOServiceGetMatchingService(0, matching);
            if root_service == 0 {
                let error = "IOPMrootDomain service not found".to_string();
                warn!(error);
                let _ = ready_tx.send(Err(error));
                ffi::IODeregisterForSystemPower(&mut notifier);
                ffi::IOServiceClose(root_port);
                ffi::IONotificationPortDestroy(notify_port);
                let _ = Box::from_raw(ctx_ptr);
                return;
            }

            // Priority root-domain interest owns capability level changes.
            let capability_result = ffi::IOServiceAddInterestNotification(
                notify_port,
                root_service,
                c"IOPriorityPowerStateInterest".as_ptr(),
                capability_callback,
                ctx_ptr.cast(),
                &mut capability_notifier,
            );
            ffi::IOObjectRelease(root_service);
            if capability_result != ffi::kIOReturnSuccess {
                let error = format!(
                    "IOServiceAddInterestNotification failed: 0x{:08x}",
                    capability_result as u32
                );
                warn!(error);
                let _ = ready_tx.send(Err(error));
                ffi::IODeregisterForSystemPower(&mut notifier);
                ffi::IOServiceClose(root_port);
                ffi::IONotificationPortDestroy(notify_port);
                let _ = Box::from_raw(ctx_ptr);
                return;
            }

            let run_loop_source = ffi::IONotificationPortGetRunLoopSource(notify_port);
            if run_loop_source.is_null() {
                let error = "IONotificationPortGetRunLoopSource returned null".to_string();
                warn!(error);
                let _ = ready_tx.send(Err(error));
                ffi::IOObjectRelease(capability_notifier);
                ffi::IODeregisterForSystemPower(&mut notifier);
                ffi::IOServiceClose(root_port);
                ffi::IONotificationPortDestroy(notify_port);
                let _ = Box::from_raw(ctx_ptr);
                return;
            }

            let run_loop = ffi::CFRunLoopGetCurrent();
            ffi::CFRunLoopAddSource(run_loop, run_loop_source, ffi::kCFRunLoopDefaultMode);

            // There is no public synchronous getter for this capability level.
            // Publish an explicit unknown value until the first root-domain
            // capability notification establishes the authoritative state.
            let _ = (*ctx_ptr)
                .tx
                .send(PowerEvent::Capabilities(PowerCapabilities::UNKNOWN));
            if ready_tx.send(Ok(())).is_err() {
                ffi::IOObjectRelease(capability_notifier);
                ffi::IODeregisterForSystemPower(&mut notifier);
                ffi::IOServiceClose(root_port);
                ffi::IONotificationPortDestroy(notify_port);
                let _ = Box::from_raw(ctx_ptr);
                return;
            }

            info!("Power monitor started");
            ffi::CFRunLoopRun();

            // Cleanup (reached if run loop is stopped)
            ffi::IOObjectRelease(capability_notifier);
            ffi::IODeregisterForSystemPower(&mut notifier);
            ffi::IOServiceClose(root_port);
            ffi::IONotificationPortDestroy(notify_port);
            let _ = Box::from_raw(ctx_ptr);
            debug!("Power monitor thread exiting");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parameters(
        change_flags: u32,
        from_capabilities: u32,
        to_capabilities: u32,
    ) -> ffi::IOPMSystemCapabilityChangeParameters {
        ffi::IOPMSystemCapabilityChangeParameters {
            notify_ref: 0,
            max_wait_for_reply: 0,
            change_flags,
            reserved1: 0,
            from_capabilities,
            to_capabilities,
            reserved2: [0; 4],
        }
    }

    #[test]
    fn capability_downgrade_takes_effect_before_transition() {
        let full = ffi::kIOPMSystemCapabilityCPU
            | ffi::kIOPMSystemCapabilityNetwork
            | ffi::kIOPMSystemCapabilityGraphics;
        let background = ffi::kIOPMSystemCapabilityCPU | ffi::kIOPMSystemCapabilityNetwork;
        let capabilities = effective_capabilities(&parameters(
            ffi::kIOPMSystemCapabilityWillChange,
            full,
            background,
        ))
        .unwrap();

        assert_eq!(
            capabilities,
            PowerCapabilities {
                known: true,
                cpu: true,
                network: true,
                graphics: false,
            }
        );
    }

    #[test]
    fn capability_upgrade_waits_for_completed_transition() {
        let background = ffi::kIOPMSystemCapabilityCPU | ffi::kIOPMSystemCapabilityNetwork;
        let full = background | ffi::kIOPMSystemCapabilityGraphics;

        assert_eq!(
            effective_capabilities(&parameters(
                ffi::kIOPMSystemCapabilityWillChange,
                background,
                full,
            )),
            Some(PowerCapabilities::from_bits(background))
        );
        assert_eq!(
            effective_capabilities(&parameters(
                ffi::kIOPMSystemCapabilityDidChange,
                background,
                full,
            )),
            Some(PowerCapabilities::from_bits(full))
        );
    }

    #[test]
    fn registration_snapshot_without_transition_flags_is_authoritative() {
        // The root domain answers a fresh registration with the current level
        // and no transition flag. Discarding it would leave the tracker at
        // UNKNOWN until the machine happened to sleep.
        let full = ffi::kIOPMSystemCapabilityCPU
            | ffi::kIOPMSystemCapabilityNetwork
            | ffi::kIOPMSystemCapabilityGraphics;

        assert_eq!(
            effective_capabilities(&parameters(0, 0, full)),
            Some(PowerCapabilities {
                known: true,
                cpu: true,
                network: true,
                graphics: true,
            })
        );
        // An unrecognised transition flag is still not a level we can trust.
        assert_eq!(effective_capabilities(&parameters(0x80, 0, full)), None);
    }

    #[test]
    fn completed_transition_republishes_an_unchanged_bitset() {
        let background = ffi::kIOPMSystemCapabilityCPU | ffi::kIOPMSystemCapabilityNetwork;
        let capabilities = PowerCapabilities::from_bits(background);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut context = PowerCallbackContext {
            tx,
            root_port: 0,
            last_capabilities: capabilities,
        };
        let mut parameters =
            parameters(ffi::kIOPMSystemCapabilityDidChange, background, background);

        capability_callback(
            (&mut context as *mut PowerCallbackContext).cast(),
            0,
            ffi::kIOMessageSystemCapabilityChange,
            (&mut parameters as *mut ffi::IOPMSystemCapabilityChangeParameters).cast(),
        );

        assert_eq!(
            rx.try_recv().expect("DidChange must restore the level"),
            PowerEvent::Capabilities(capabilities)
        );
    }
}
