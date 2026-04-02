// Copyright (c) 2026 Sebastien Rousseau
//
// This file is part of uon.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core execution and cryptographic enforcement bounds for `uon`.
//!
//! This crate acts as the monolithic Rust bedrock for the Python UI orchestrator. 
//! It abstracts complex, highly-sensitive native integrations (eBPF telemetry, 
//! `mlock` memory pinning, and SSH TOFU traversal) behind safe C-FFI \[`PyO3`\] bindings.
//! 
//! # Architecture
//! 
//! The `uon_core` library relies heavily on conditional target compilation `#[cfg]` macros.
//! * For standard targets (macOS natively, Linux/WSL), it generates a `CDYLib` (`.so` / `.dylib`)
//!   that Python imports natively at runtime as `uon.core`.
//! * For WebAssembly targets (`wasm32-unknown-unknown`), it fundamentally strips out `PyO3`, 
//!   POSIX sockets, and `libc` threads, replacing them natively with `wasm-bindgen` and `js-sys`.
//! 
//! # Platform Constraints
//! 
//! Ensure the target deployment aligns with the dependencies:
//! * **macOS**: Evaluates the local SSH agent via macOS Keychain natively.
//! * **Linux/WSL**: Negotiates standard POSIX `ssh-agent` `AF_UNIX` sockets.
//! * **Browser (Wasm)**: Negotiates explicitly via HTML5 `navigator.credentials.get()`.

#[cfg(not(target_arch = "wasm32"))]
use pyo3::prelude::*;

#[cfg(not(target_arch = "wasm32"))]
mod amdns_core;
#[cfg(not(target_arch = "wasm32"))]
mod caep_intervention;
#[cfg(not(target_arch = "wasm32"))]
mod fido2_core;
#[cfg(not(target_arch = "wasm32"))]
mod ssf_core;
#[cfg(not(target_arch = "wasm32"))]
mod ssh_core;
#[cfg(not(target_arch = "wasm32"))]
pub mod zsp_broker;
#[cfg(target_arch = "wasm32")]
mod wasm_bridge;
#[cfg(not(target_arch = "wasm32"))]
mod zsp_core;
#[cfg(not(target_arch = "wasm32"))]
mod macos_es;

/// A Python module implemented in Rust.
#[cfg(not(target_arch = "wasm32"))]
#[pymodule]
fn core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Phase 1 Bindings
    m.add_class::<fido2_core::SecureEnvelope>()?;
    m.add_function(wrap_pyfunction!(fido2_core::secure_envelope_memory, m)?)?;
    m.add_function(wrap_pyfunction!(ssh_core::execute_session, m)?)?;
    m.add_function(wrap_pyfunction!(ssh_core::generate_challenge, m)?)?;

    // Phase 7 Bindings
    m.add_function(wrap_pyfunction!(amdns_core::compute_amdns_hmac, m)?)?;
    m.add_function(wrap_pyfunction!(amdns_core::verify_discovery_beacon, m)?)?;
    m.add_function(wrap_pyfunction!(ssf_core::parse_ssf_event, m)?)?;
    m.add_function(wrap_pyfunction!(zsp_core::spawn_zsp_process, m)?)?;
    m.add_function(wrap_pyfunction!(zsp_broker::run_zsp_broker, m)?)?;

    // Phase 8 Bindings (UX Interventions)
    m.add_function(wrap_pyfunction!(caep_intervention::freeze_execution, m)?)?;
    m.add_function(wrap_pyfunction!(caep_intervention::resume_execution, m)?)?;

    // Phase 14 Bindings (v1.0.0 Hardware Integrations)
    m.add_function(wrap_pyfunction!(macos_es::start_macos_es_tracing, m)?)?;
    m.add_function(wrap_pyfunction!(macos_es::stop_macos_es_tracing, m)?)?;

    Ok(())
}
