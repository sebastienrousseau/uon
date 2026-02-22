use pyo3::prelude::*;
use serde_json::Value;

const RISC_ACCOUNT_DISABLED: &str = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
const RISC_CREDENTIAL_CHANGE: &str = "https://schemas.openid.net/secevent/risc/event-type/credential-change";

#[pyfunction]
pub fn parse_ssf_event(payload: &str) -> PyResult<Option<String>> {
    // Drop invalid payloads instantly
    let v: Value = match serde_json::from_str(payload) {
        Ok(v) => v,
        Err(_) => return Err(pyo3::exceptions::PyValueError::new_err("Invalid JSON payload")),
    };

    if let Some(events) = v.get("events") {
        let event_data = if let Some(data) = events.get(RISC_ACCOUNT_DISABLED) {
            Some(data)
        } else if let Some(data) = events.get(RISC_CREDENTIAL_CHANGE) {
            Some(data)
        } else {
            None
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
