// Copyright (c) 2026 Sebastien Rousseau
// Licensed under the MIT License.

//! Clientless WebAssembly (Wasm) fallback bindings for browser-terminal execution.
//!
//! Enables the `uon` framework to compile its core cryptographic envelopes
//! and WebAuthn parsing logic directly into a browser-executable module, bypassing 
//! the need for a local desktop agent or Python Orchestrator entirely.

#![cfg(target_arch = "wasm32")]

use base64::{engine::general_purpose, Engine as _};
use wasm_bindgen::prelude::*;

/// Registers the console error panic hook exclusively for the browser context.
/// 
/// This is forcibly executed immediately upon Wasm instantiation.
/// 
/// # Architecture
/// 
/// Intercepts native Rust thread `panic!` macros and elegantly pipes the debug 
/// backtrace into the HTML5 `console.error` stream instead of failing silently.
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/// Constructs the FIDO2 structural envelope natively inside the browser context,
/// avoiding dependencies on Python or local desktop agents.
/// 
/// # Architecture
/// 
/// In clientless scenarios, the browser invokes the WebAuthn API natively. This Wasm 
/// boundary accepts the raw JSON authentication tokens, parses them safely, wraps the 
/// inner execution `command` payload, and encodes the matrix out to `base64` for transmission.
///
/// # Errors
///
/// Returns a `JsValue` exception string directly to the Javascript Promise if:
/// * The inbound `assertion_json` is not structurally valid JSON.
/// * The monolithic `serde_json` serializer fails to allocate or parse the final envelope matrix.
/// 
/// # Panics
/// 
/// Does not panic dynamically; all deserialization errors yield soft JavaScript exceptions 
/// returning gracefully over the bindings edge.
/// 
/// # Examples
/// 
/// ```javascript
/// import { encapsulate_payload_wasm } from './uon_core_bg.js';
/// 
/// // Injected by navigator.credentials.get(...)
/// const assertionRaw = "{ id: 'xyz', rawId: 'xyz' }"; 
/// const wrapped = encapsulate_payload_wasm("whoami", assertionRaw);
/// console.log(wrapped); // Yields "__UON_EXEC__ base64..."
/// ```
#[wasm_bindgen]
#[doc(alias = "js_sys")]
pub fn encapsulate_payload_wasm(command: &str, assertion_json: &str) -> Result<String, JsValue> {
    // Deserialize the WebAuthn token
    let assertion: serde_json::Value = serde_json::from_str(assertion_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid assertion structure: {}", e)))?;

    // Create the UON protocol envelope
    let envelope = serde_json::json!({
        "version": 1,
        "command": command,
        "assertion": assertion,
        "wasm_fallback": true
    });

    let payload_str = serde_json::to_string(&envelope)
        .map_err(|err| JsValue::from_str(&format!("Envelope serialization failed: {}", err)))?;

    // Return the base64 encoded token compatible with `uon_verifier.py`
    let b64 = general_purpose::STANDARD.encode(payload_str);
    Ok(format!("__UON_EXEC__ {}", b64))
}
