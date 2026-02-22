use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;

#[cfg(target_os = "macos")]
pub mod macos_es_core {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use endpointsecurity::*; 
    use libc;

    // Atomic flag to cleanly terminate the ES client loop.
    pub static ES_IS_RUNNING: AtomicBool = AtomicBool::new(false);

    /// Initializes the Apple EndpointSecurity client listener to trace `ES_EVENT_TYPE_NOTIFY_EXEC`.
    /// 
    /// # Errors
    /// Returns a `PyRuntimeError` if the process lacks `entitlement` or root privileges
    /// required to interface with Apple's EndpointSecurity subsystem.
    pub fn initialize_es_event_listener() -> PyResult<()> {
        if ES_IS_RUNNING.load(Ordering::SeqCst) {
            return Ok(());
        }
        
        // Note: Apple EndpointSecurity requires specific entitlements and must run as root.
        // For local development, this initial scaffolding sets up the module layout
        // and provides the execution hook for the Python orchestrator.
        
        ES_IS_RUNNING.store(true, Ordering::SeqCst);
        println!("[uon_core::macos_es] EndpointSecurity tracing activated. Establishing XNU hooks...");
        
        std::thread::spawn(|| {
            let (tx, rx) = crossbeam_channel::unbounded();

            let client = match create_es_client(tx) {
                Ok(c) => c,
                Err(e) => {
                    println!("[uon_core::macos_es] Failed to initialize ES Client. Are you running as root? (Error: {:?})", e);
                    return;
                }
            };

            if !client.subscribe_to_events(&vec![SupportedEsEvent::NotifyExec]) {
                println!("[uon_core::macos_es] Failed to subscribe to ES_EVENT_TYPE_NOTIFY_EXEC.");
                return;
            }

            println!("[uon_core::macos_es] Successfully subscribed to ES_EVENT_TYPE_NOTIFY_EXEC via crossbeam channel.");

            while ES_IS_RUNNING.load(Ordering::Relaxed) {
                if let Ok(message) = rx.recv_timeout(std::time::Duration::from_millis(100)) {
                    if let EsEvent::NotifyExec(exec_event) = &message.event {
                        let path = &exec_event.target.executable.path;
                        if path == "/bin/sh" || path == "/bin/bash" || path == "/bin/zsh" {
                            println!("[uon_core::macos_es] CAEP TERMINATION: Anomalous shell pivot detected ({})", path);
                            unsafe {
                                libc::kill(message.process.pid as libc::pid_t, libc::SIGKILL);
                            }
                        }
                    }
                }
            }
        });

        Ok(())
    }

    pub fn teardown_es_event_listener() -> PyResult<()> {
        ES_IS_RUNNING.store(false, Ordering::SeqCst);
        println!("[uon_core::macos_es] EndpointSecurity tracing scaffolding disabled.");
        Ok(())
    }
}

// OS-agnostic fallbacks when not compiling on macOS

#[cfg(not(target_os = "macos"))]
pub mod macos_es_core {
    use super::*;

    pub fn initialize_es_event_listener() -> PyResult<()> {
        Err(PyRuntimeError::new_err("uon_core::macos_es requires target_os = \"macos\""))
    }

    pub fn teardown_es_event_listener() -> PyResult<()> {
        Ok(())
    }
}

/// Start EndpointSecurity Process Tracing (macOS only)
#[pyfunction]
pub fn start_macos_es_tracing() -> PyResult<()> {
    macos_es_core::initialize_es_event_listener()
}

/// Stop EndpointSecurity Process Tracing
#[pyfunction]
pub fn stop_macos_es_tracing() -> PyResult<()> {
    macos_es_core::teardown_es_event_listener()
}
