use hmac::{Hmac, Mac};
use pyo3::prelude::*;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Computes an AmDNS High-Assurance MAC using SHA-256 for network discovery beacons.
///
/// The timestamp is divided by 30-second windows (TOTP-style) before being
/// included in the HMAC message. This ensures that `compute_amdns_hmac` and
/// `verify_discovery_beacon` use the same message format.
///
/// # Errors
///
/// Returns a `PyValueError` if the BLE secret byte array has an invalid length.
#[pyfunction]
pub fn compute_amdns_hmac(
    ble_secret: &[u8],
    target_alias: &str,
    timestamp: u64,
) -> PyResult<String> {
    // Divide by 30-second window to match verification logic.
    let window = timestamp / 30;
    let message = format!("{}:{}", target_alias, window);
    let mut mac = HmacSha256::new_from_slice(ble_secret).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Invalid key length: {}", e))
    })?;

    mac.update(message.as_bytes());
    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

/// Verifies an incoming AmDNS High-Assurance MAC against a predefined time-tolerance window.
///
/// Executes a rolling three-pane window check (Past, Present, Future)
/// compensating for slight system clock desynchronization.
///
/// # Safety
///
/// The validation relies on the `hmac` crate's `verify_slice` implementation
/// which executes **Constant-Time Memory Comparisons** to eliminate side-channel
/// timing threats.
///
/// # Errors
///
/// Returns a `PyRuntimeError` if the system clock cannot resolve `UNIX_EPOCH`.
#[pyfunction]
#[pyo3(signature = (ble_secret, target_alias, reported_hmac, time_tolerance_seconds=30))]
pub fn verify_discovery_beacon(
    ble_secret: &[u8],
    target_alias: &str,
    reported_hmac: &str,
    time_tolerance_seconds: u64,
) -> PyResult<bool> {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("SystemTime error: {}", e)))?
        .as_secs();

    let reported_hmac_bytes = match hex::decode(reported_hmac) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(false), // Invalid hex string cannot be a valid signature
    };

    let offsets: [i64; 3] = [
        0,
        -(time_tolerance_seconds as i64),
        time_tolerance_seconds as i64,
    ];

    for offset in offsets {
        let window = ((current_time as i64 + offset) as u64) / time_tolerance_seconds;
        let message = format!("{}:{}", target_alias, window);

        let mut mac = HmacSha256::new_from_slice(ble_secret).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid key length: {}", e))
        })?;
        mac.update(message.as_bytes());

        // Constant time comparison natively implemented by the HMAC crate
        if mac.verify_slice(&reported_hmac_bytes).is_ok() {
            return Ok(true);
        }
    }

    Ok(false)
}
