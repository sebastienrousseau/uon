use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::{Zeroize, ZeroizeOnDrop};



#[pyclass]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureEnvelope {
    data: Vec<u8>,
}

#[pymethods]
impl SecureEnvelope {
    #[new]
    pub fn new(data: &[u8]) -> Self {
        let mut vec = data.to_vec();
        #[cfg(unix)]
        unsafe {
            let ptr = vec.as_mut_ptr() as *mut libc::c_void;
            let len = vec.capacity();
            // Lock memory to avoid swapping out to disk
            libc::mlock(ptr, len);
            
            #[cfg(target_os = "linux")]
            libc::madvise(ptr, len, libc::MADV_DONTDUMP);
            
            #[cfg(target_os = "macos")]
            libc::madvise(ptr, len, libc::MADV_ZERO_WIRED_PAGES);
        }
        SecureEnvelope { data: vec }
    }

    pub fn get_data<'p>(&self, py: Python<'p>) -> Bound<'p, PyBytes> {
        PyBytes::new_bound(py, &self.data)
    }
}

#[pyfunction]
pub fn secure_envelope_memory(data: &[u8]) -> SecureEnvelope {
    SecureEnvelope::new(data)
}
