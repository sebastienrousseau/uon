# Cryptographic Hardening & Post-Quantum Readiness
# Security & PQC Documentation

This document officially outlines the Zero-Trust cryptographic model, memory safety hygiene, and Post-Quantum Cryptography (PQC) readiness for the `uon` platform, strictly adhering to 2026 NIST and CNSA 2.0 standards.

## 1. Security Assumptions

The Zero-Trust execution capability of this platform operates under the following adversarial threat model:

* **Assume Compromised Networks:** All local discovery (mDNS), IP traffic, and SSH loopbacks (VM VSOCKs) are susceptible to interception and spoofing.
* **Assume Compromised OS Space:** The parent Python execution environment may be probed or dumped by malicious rootkits, requiring heavy delegation to hardware enclaves and memory-pinned C-FFI partitions.
* **No Physical Fallback:** We assume the adversary DOES NOT have physical possession of the target's FIDO2 hardware authenticator, minimizing physical extraction vectors.
* **Store No Secrets:** The device holds no long-lived asymmetric private keys on disk.

## 2. Cryptographic Inventory

| Subsystem | Operation | Primitive | Standard | Hardening Status |
| --- | --- | --- | --- | --- |
| **Transport Envelope** | Payload Encapsulation | `AES-256-GCM` | FIPS 197 / SP 800-38D | ✅ Modern Default. Avoids CBC modes. |
| **Key Derivation** | KEM Secret Hashing | `SHA-256` | FIPS 180-4 | ✅ Secure. Used to hash the local RNG seeds. |
| **Authentication** | Hardware Assertions | `CTAP2 / WebAuthn` | FIDO Alliance | ✅ Hardware Enclave Bound via `fido2`. |
| **Zero-Trust Discovery** | AmDNS Beacons | `HMAC-SHA256` | FIPS 198-1 | ✅ Native Rust validation wrapper. |
| **Transport Security** | SSH Handshake | `CURVE25519` | RFC 7748 | ⚠️ Legacy Fallback. PQC wrapper handles primary defense. |

---

## 3. Post-Quantum Cryptography (PQC) Roadmap

> [!WARNING]
> **PQC Protocol Degradation Notice**
> The underlying Rust SSH transport (`russh`) currently lacks native parsing for ML-KEM standards (`sntrup761x25519-sha512@openssh.com`). 

To force CNSA 2.0 compliance, `uon` implements a **Hybrid PQC Wrapper Model**:

1. **Inner Envelope (PQC Ready):** All FIDO2 execution assertions are encrypted utilizing `AES-256-GCM` (using Rust's `ring` crate) before touching outer transport. AES-256 is mathematically considered quantum-resistant to Grover's Algorithm.
2. **Outer Envelope (Classical):** The SSH traversal utilizes `CURVE25519`. 
3. **Future Patches:** Once `tokio`/`russh` formalizes FIPS 204 ML-DSA and ML-KEM key exchange parameters in 2026 upstream, the secondary `CURVE25519` shell will be aggressively rotated to native PQC bindings.

---

## 4. Side-Channel & Memory Mitigations

### Memory Zeroing & Pinning
All sensitive FIDO2 payloads handled natively are locked to physical RAM.
* **Rust `zeroize` Crate:** Implements `ZeroizeOnDrop` allowing definitive scrubber sweeps of cryptographic credentials as soon as the `SecureEnvelope` drops out of scope.
* **OS Pinning (`mlock`):** Memory is pinned (`libc::mlock`) preventing sensitive structures from being paged to disk via SWAP.
* **Core-Dump Prevention:** Linux utilizes `MADV_DONTDUMP` and macOS utilizes `MADV_ZERO_WIRED_PAGES` to block memory extraction via unauthorized process dumps.

### Constant-Time Execution
* **AmDNS Validation:** `amdns_core.rs` calculates incoming HMAC signatures and validates them using the `hmac::verify_slice` generic. This enforces a **Constant-Time Comparison** at the CPU level, mathematically nullifying timing attacks.

---

> [!CAUTION]
> **Rust Ring RNG Constraints**
> The `AES-256-GCM` encapsulation layer relies on `ring::rand::SystemRandom`. This securely maps to the OS-level CSPRNG (e.g., `/dev/urandom` or `getrandom`). Ensure underlying Host OS Entropy pools are not starved in highly-virtualized minimal containers.
