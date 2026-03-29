use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Power state events from macOS IOKit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerEvent {
    /// System is about to sleep. Acknowledge promptly.
    WillSleep,
    /// System has woken up. Network may not be ready yet.
    HasPoweredOn,
}

/// Monitors macOS system power state changes via IOKit.
pub struct PowerMonitor {
    _thread: std::thread::JoinHandle<()>,
}

// IOKit FFI bindings (minimal subset for power management)
#[allow(non_upper_case_globals, dead_code)]
mod ffi {
    use std::os::raw::{c_int, c_uint, c_void};

    pub type IONotificationPortRef = *mut c_void;
    pub type IOReturn = c_int;
    pub type IOObject = c_uint;

    pub const kIOMessageSystemWillSleep: u32 = 0xe0000280;
    pub const kIOMessageSystemHasPoweredOn: u32 = 0xe0000300;
    pub const kIOMessageCanSystemSleep: u32 = 0xe0000270;

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

        pub fn IOAllowPowerChange(
            kernel_port: IOObject,
            notification_id: isize,
        ) -> IOReturn;

        pub fn IONotificationPortGetRunLoopSource(
            notify: IONotificationPortRef,
        ) -> *const c_void; // CFRunLoopSourceRef

        pub fn IONotificationPortDestroy(notify: IONotificationPortRef);
    }

    // CoreFoundation run loop bindings
    extern "C" {
        pub fn CFRunLoopGetCurrent() -> *const c_void;
        pub fn CFRunLoopAddSource(
            rl: *const c_void,
            source: *const c_void,
            mode: *const c_void,
        );
        pub fn CFRunLoopRun();
        pub fn CFRunLoopStop(rl: *const c_void);
    }

    // kCFRunLoopDefaultMode
    extern "C" {
        pub static kCFRunLoopDefaultMode: *const c_void;
    }
}

struct PowerCallbackContext {
    tx: mpsc::Sender<PowerEvent>,
    root_port: ffi::IOObject,
}

extern "C" fn power_callback(
    refcon: *mut std::os::raw::c_void,
    _service: ffi::IOObject,
    message_type: u32,
    message_argument: *mut std::os::raw::c_void,
) {
    let ctx = unsafe { &*(refcon as *const PowerCallbackContext) };

    match message_type {
        ffi::kIOMessageSystemWillSleep => {
            debug!("IOKit: WillSleep");
            // Acknowledge sleep first to avoid delaying the system if channel is full
            unsafe {
                ffi::IOAllowPowerChange(ctx.root_port, message_argument as isize);
            }
            let _ = ctx.tx.blocking_send(PowerEvent::WillSleep);
        }
        ffi::kIOMessageCanSystemSleep => {
            // Allow system to sleep (don't veto)
            unsafe {
                ffi::IOAllowPowerChange(ctx.root_port, message_argument as isize);
            }
        }
        ffi::kIOMessageSystemHasPoweredOn => {
            debug!("IOKit: HasPoweredOn");
            let _ = ctx.tx.blocking_send(PowerEvent::HasPoweredOn);
        }
        _ => {
            debug!("IOKit: unknown power message 0x{:08x}", message_type);
        }
    }
}

impl PowerMonitor {
    /// Start monitoring power state changes.
    /// Returns the monitor handle and a receiver for power events.
    pub fn start() -> Result<(Self, mpsc::Receiver<PowerEvent>), String> {
        let (tx, rx) = mpsc::channel(8);

        let thread = std::thread::Builder::new()
            .name("power-monitor".into())
            .spawn(move || {
                Self::run_power_loop(tx);
            })
            .map_err(|e| format!("failed to spawn power monitor thread: {}", e))?;

        Ok((Self { _thread: thread }, rx))
    }

    fn run_power_loop(tx: mpsc::Sender<PowerEvent>) {
        unsafe {
            let mut notify_port: ffi::IONotificationPortRef = std::ptr::null_mut();
            let mut notifier: ffi::IOObject = 0;

            // Allocate context on the heap so it lives as long as the callback needs it
            let ctx = Box::new(PowerCallbackContext {
                tx,
                root_port: 0, // Will be set after registration
            });
            let ctx_ptr = Box::into_raw(ctx);

            let root_port = ffi::IORegisterForSystemPower(
                ctx_ptr as *mut std::os::raw::c_void,
                &mut notify_port,
                power_callback,
                &mut notifier,
            );

            if root_port == 0 {
                warn!("IORegisterForSystemPower failed");
                let _ = Box::from_raw(ctx_ptr); // Clean up
                return;
            }

            // Set root_port in context so callback can use it for IOAllowPowerChange
            (*ctx_ptr).root_port = root_port;

            let run_loop_source = ffi::IONotificationPortGetRunLoopSource(notify_port);
            if run_loop_source.is_null() {
                warn!("IONotificationPortGetRunLoopSource returned null");
                let _ = Box::from_raw(ctx_ptr);
                return;
            }

            let run_loop = ffi::CFRunLoopGetCurrent();
            ffi::CFRunLoopAddSource(run_loop, run_loop_source, ffi::kCFRunLoopDefaultMode);

            info!("Power monitor started");
            ffi::CFRunLoopRun();

            // Cleanup (reached if run loop is stopped)
            ffi::IODeregisterForSystemPower(&mut notifier);
            ffi::IONotificationPortDestroy(notify_port);
            let _ = Box::from_raw(ctx_ptr);
            debug!("Power monitor thread exiting");
        }
    }
}
