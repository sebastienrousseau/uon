// Copyright (c) 2026 Sebastien Rousseau
// Licensed under the GNU AGPLv3 License.

//! Clientless WebAssembly (Wasm) fallback bindings for browser-terminal execution.
//!
//! Enables the `uon` framework to compile its core cryptographic envelopes
//! and WebAuthn parsing logic directly into a browser-executable module, bypassing
//! the need for a local desktop agent or Python Orchestrator entirely.
//!
//! The envelope is base64-encoded to match the format expected by `uon_verifier.py`.
//! Note: The Wasm path does not include PQC AES-256-GCM encryption since the
//! Web Crypto API would be needed for that. The envelope is marked with
//! `"pqc_wrapped": false` so the verifier can detect and handle it accordingly.

#![cfg(target_arch = "wasm32")]

use base64::{engine::general_purpose, Engine as _};
use wasm_bindgen::prelude::*;

/// Registers the console error panic hook exclusively for the browser context.
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Constructs the FIDO2 structural envelope natively inside the browser context.
///
/// In clientless scenarios, the browser invokes the WebAuthn API natively. This Wasm
/// boundary accepts the raw JSON authentication tokens, wraps the inner execution
/// `command` payload, and encodes it to base64 for transmission.
///
/// The output format is `__UON_EXEC__ <base64>` matching the desktop path, but
/// without PQC encryption (marked via `pqc_wrapped: false`).
///
/// # Errors
///
/// Returns a `JsValue` exception if the JSON is structurally invalid.
#[wasm_bindgen]
pub fn encapsulate_payload_wasm(command: &str, assertion_json: &str) -> Result<String, JsValue> {
    let assertion: serde_json::Value = serde_json::from_str(assertion_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid assertion structure: {}", e)))?;

    let envelope = serde_json::json!({
        "version": 1,
        "command": command,
        "assertion": assertion,
        "pqc_wrapped": false
    });

    let payload_str = serde_json::to_string(&envelope)
        .map_err(|err| JsValue::from_str(&format!("Envelope serialization failed: {}", err)))?;

    let b64 = general_purpose::STANDARD.encode(payload_str);
    Ok(format!("__UON_EXEC__ {}", b64))
}
