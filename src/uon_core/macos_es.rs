use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;

pub mod macos_es_core {
    use super::*;

    pub fn initialize_es_event_listener() -> PyResult<()> {
        Err(PyRuntimeError::new_err(
            "uon_core::macos_es EndpointSecurity integration is not available in this build",
        ))
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
