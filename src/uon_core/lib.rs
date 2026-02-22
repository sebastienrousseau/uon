use pyo3::prelude::*;

mod amdns_core;
mod fido2_core;
mod ssf_core;
mod ssh_core;
mod zsp_core;

/// A Python module implemented in Rust.
#[pymodule]
fn core(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Phase 1 Bindings
    m.add_class::<fido2_core::SecureEnvelope>()?;
    m.add_function(wrap_pyfunction!(fido2_core::secure_envelope_memory, m)?)?;
    m.add_function(wrap_pyfunction!(ssh_core::execute_signed_rust, m)?)?;
    
    // Phase 7 Bindings
    m.add_function(wrap_pyfunction!(amdns_core::compute_amdns_hmac, m)?)?;
    m.add_function(wrap_pyfunction!(amdns_core::verify_discovery_beacon, m)?)?;
    m.add_function(wrap_pyfunction!(ssf_core::parse_ssf_event, m)?)?;
    m.add_function(wrap_pyfunction!(zsp_core::spawn_zsp_process, m)?)?;
    
    Ok(())
}
