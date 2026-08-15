// Copyright (c) 2026 Sebastien Rousseau
//
// This file is part of uon.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::Zeroize;

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
    #[new]
    pub fn new(data: &[u8]) -> Self {
        let mut vec = data.to_vec();
        #[cfg(unix)]
        unsafe {
            let ptr = vec.as_mut_ptr() as *mut libc::c_void;
            let len = vec.capacity();
            if libc::mlock(ptr, len) != 0 {
                eprintln!(
                    "[uon] WARNING: mlock failed (errno {}); secrets may page to swap",
                    std::io::Error::last_os_error(),
                );
            }

            #[cfg(target_os = "linux")]
            if libc::madvise(ptr, len, libc::MADV_DONTDUMP) != 0 {
                eprintln!(
                    "[uon] WARNING: madvise(MADV_DONTDUMP) failed (errno {})",
                    std::io::Error::last_os_error(),
                );
            }

            #[cfg(target_os = "macos")]
            if libc::madvise(ptr, len, libc::MADV_ZERO_WIRED_PAGES) != 0 {
                eprintln!("[uon] WARNING: madvise(MADV_ZERO_WIRED_PAGES) failed");
            }
        }
        SecureEnvelope { data: vec }
    }

    /// Exposes the protected byte envelope back to the Python FFI orchestrator.
    pub fn get_data<'p>(&self, py: Python<'p>) -> Bound<'p, PyBytes> {
        PyBytes::new(py, &self.data)
    }
}

impl Drop for SecureEnvelope {
    fn drop(&mut self) {
        // Zeroize FIRST while memory is still locked to physical RAM,
        // preventing secrets from paging to swap between munlock and zeroize.
        self.data.zeroize();

        #[cfg(unix)]
        unsafe {
            let ptr = self.data.as_mut_ptr() as *mut libc::c_void;
            let len = self.data.capacity();
            libc::munlock(ptr, len);
        }
    }
}

/// Helper constructor to generate a [`SecureEnvelope`] natively via PyO3 parameters.
#[pyfunction]
pub fn secure_envelope_memory(data: &[u8]) -> SecureEnvelope {
    SecureEnvelope::new(data)
}
