use hmac::{Hmac, Mac};
use pyo3::prelude::*;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Computes an AmDNS High-Assurance MAC using SHA-256 for network discovery beacons.
///
/// Under Zero-Trust orchestration, initial UDP/TCP discovery requests cannot be trusted.
/// The AmDNS (Ambient Discovery Node System) calculates a time-bound HMAC payload locally,
/// allowing the receiving host to gracefully silently drop unauthenticated pings prior 
/// to executing costly TCP or SSH subsystem handshakes.
/// 
/// # Architecture
/// 
/// The `compute_amdns_hmac` generates a string representation derived from the target 
/// machine alias, concatenated with a precise UNIX epoch timestamp.
/// 
/// # Errors
/// 
/// Returns a `PyValueError` if:
/// * The inbound Bluetooth Low Energy (`ble_secret`) byte array is inherently invalid.
/// 
/// # Examples
/// 
/// ```rust
/// use uon_core::amdns_core::compute_amdns_hmac;
/// let mac = compute_amdns_hmac(b"shared_ble_key", "bastion-1", 1700000000).unwrap();
/// ```
#[pyfunction]
pub fn compute_amdns_hmac(
    ble_secret: &[u8],
    target_alias: &str,
    timestamp: u64,
) -> PyResult<String> {
    let message = format!("{}:{}", target_alias, timestamp);
    let mut mac = HmacSha256::new_from_slice(ble_secret).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Invalid key length: {}", e))
    })?;

    mac.update(message.as_bytes());
    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

/// Verifies an incoming AmDNS High-Assurance MAC against a predefined time-tolerance window.
///
/// Acts as the internal validation layer for ambient node discovery. By defaulting the 
/// acceptance range to 30 seconds (`time_tolerance_seconds`), this function absorbs standard 
/// network transit delays without sacrificing strict replay-attack resistance.
/// 
/// # Architecture
/// 
/// `verify_discovery_beacon` executes a rolling three-pane window check (Past, Present, Future)
/// compensating for slight system clock desynchronization between disparate enterprise domains.
/// 
/// # Safety
/// 
/// The validation relies definitively on the `hmac` crate's `verify_slice` implementation 
/// which executes **Constant-Time Memory Comparisons** to eliminate side-channel timing threats.
/// 
/// # Errors
/// 
/// Returns a `PyRuntimeError` if:
/// * The local host machine's system clock (`SystemTime::now`) is catastrophically distorted 
///   and cannot resolve the `UNIX_EPOCH`.
/// 
/// # Examples
/// 
/// ```rust
/// use uon_core::amdns_core::verify_discovery_beacon;
/// // Fails if the hex is structurally invalid or explicitly maliciously timed.
/// let valid = verify_discovery_beacon(b"key", "alias", "bad_hex_mac", 30).unwrap();
/// assert_eq!(valid, false);
/// ```
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
