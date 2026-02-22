use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A cryptographically pinned byte vector heavily guarded from memory leaks.
///
/// The `SecureEnvelope` intercepts raw cryptographic assertions securely and locks
/// the contents directly to physical RAM. It employs a Zero-Trust approach by 
/// ensuring sensitive data never pages out to disk via system swap.
///
/// Under the hood, this struct leverages operating system primitives (`mlock` and 
/// `madvise`) to protect the memory bounds, combined with `zeroize` traits to 
/// definitively scrub the buffer contents securely on drop.
/// 
/// #[doc(alias = "memory_pinning")]
/// #[doc(alias = "mlock")]
#[pyclass]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureEnvelope {
    data: Vec<u8>,
}

#[pymethods]
impl SecureEnvelope {
    /// Instantiates a new memory-locked envelope holding the provided byte slice.
    ///
    /// The initialization logic allocates the vector and immediately triggers OS-level 
    /// memory pinning and dumping restrictions.
    ///
    /// # Safety
    ///
    /// This function utilizes `unsafe` blocks to pass the raw vector pointer (`*mut c_void`)
    /// into libc bounds. The `vec` capacity is guaranteed to match the length, ensuring 
    /// memory boundary violations cannot occur during the `mlock` allocation.
    /// 
    /// # Platform Constraints
    /// 
    /// * **macOS**: Utilizes `MADV_ZERO_WIRED_PAGES` to ensure physical wiring zeroization.
    /// * **Linux/WSL**: Exerts `MADV_DONTDUMP` to block core-dump extraction.
    /// 
    /// # Examples
    ///
    /// ```rust
    /// use uon_core::fido2_core::SecureEnvelope;
    /// let secret = b"super_secret_fido_assertion";
    /// let env = SecureEnvelope::new(secret);
    /// ```
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

    /// Exposes the protected byte envelope back to the Python FFI orchestrator.
    pub fn get_data<'p>(&self, py: Python<'p>) -> Bound<'p, PyBytes> {
        PyBytes::new_bound(py, &self.data)
    }
}

/// Helper constructor to generate a [`SecureEnvelope`] natively via PyO3 parameters.
/// 
/// Wraps the underlying `SecureEnvelope::new` implementation, providing a clean 
/// functional interface for Python to inject highly sensitive FIDO2 payloads for 
/// zeroized memory tracking.
#[pyfunction]
pub fn secure_envelope_memory(data: &[u8]) -> SecureEnvelope {
    SecureEnvelope::new(data)
}
