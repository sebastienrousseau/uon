use pyo3::prelude::*;
use serde_json::Value;

/// The official OpenID Shared Signals Framework identifier for disabled accounts.
#[doc(alias = "OIDF")]
#[doc(alias = "RISC")]
const RISC_ACCOUNT_DISABLED: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-disabled";

/// The official OpenID Shared Signals Framework identifier for credential rotations.
const RISC_CREDENTIAL_CHANGE: &str =
    "https://schemas.openid.net/secevent/risc/event-type/credential-change";

/// Extracts the terminating subject (email or sub-ID) from a raw SSF Webhook payload.
///
/// Under Zero-Trust orchestration, Identity Providers (IdP) continuously transmit
/// lifecycle events. This parser targets high-risk signals (e.g., Account Disabled, 
/// Credential Rotations) and strips away extraneous JSON wrapping to isolate the 
/// target user.
///
/// # Architecture
/// 
/// The parser explicitly fails fast on malformed schemas. If the payload matches 
/// a supported RISC event, it traverses the `subject` tree prioritizing the provider 
/// `sub` UUID, before gracefully falling back to a raw `email` string.
/// 
/// # Errors
/// 
/// Returns a `PyValueError` if:
/// * The inbound payload string cannot be deserialized cleanly via `serde_json`.
/// 
/// # Examples
/// 
/// ```rust
/// use uon_core::ssf_core::parse_ssf_event;
/// let payload = r#"{
///     "events": {
///         "https://schemas.openid.net/secevent/risc/event-type/account-disabled": {
///             "subject": { "email": "admin@uon.local" }
///         }
///     }
/// }"#;
/// let subject = parse_ssf_event(payload).unwrap();
/// assert_eq!(subject, Some("admin@uon.local".to_string()));
/// ```
#[pyfunction]
pub fn parse_ssf_event(payload: &str) -> PyResult<Option<String>> {
    // Drop invalid payloads instantly
    let v: Value = match serde_json::from_str(payload) {
        Ok(v) => v,
        Err(_) => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Invalid JSON payload",
            ))
        },
    };

    if let Some(events) = v.get("events") {
        let event_data = if let Some(data) = events.get(RISC_ACCOUNT_DISABLED) {
            Some(data)
        } else {
            events.get(RISC_CREDENTIAL_CHANGE).map(|data| data)
        };

        if let Some(data) = event_data {
            if let Some(subject) = data.get("subject") {
                if let Some(sub) = subject.get("sub").and_then(|s| s.as_str()) {
                    return Ok(Some(sub.to_string()));
                }
                if let Some(email) = subject.get("email").and_then(|e| e.as_str()) {
                    return Ok(Some(email.to_string()));
                }
                return Ok(Some("unknown".to_string()));
            }
        }
    }

    Ok(None)
}
