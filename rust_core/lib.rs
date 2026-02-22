use pyo3::prelude::*;

mod fido2_core;
mod ssh_core;

/// A Python module implemented in Rust.
#[pymodule]
fn core(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<fido2_core::SecureEnvelope>()?;
    m.add_function(wrap_pyfunction!(fido2_core::secure_envelope_memory, m)?)?;
    m.add_function(wrap_pyfunction!(ssh_core::execute_signed_rust, m)?)?;
    Ok(())
}
