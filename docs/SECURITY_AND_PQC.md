# Security and PQC Status

`uon` signs every remote command with FIDO2 and verifies that signature on the target before execution. This document explains the current security model, what is implemented today, and where the PQC story is still transitional.

## Current Security Model

### What `uon` protects well

| Area | Current behavior |
|---|---|
| Private key handling | Private keys stay inside the authenticator and are not written to disk. |
| Remote execution gate | OpenSSH `ForceCommand` routes configured sessions through `uon_verifier.py`. |
| Replay protection | The target records used `session_id` values and rejects reuse. |
| Execution isolation | Approved commands go through a persistent broker that drops to the target UID plus the fixed `uon-exec` group. |
| Host verification | The controller uses Trust On First Use and then pins host keys locally. |

### Threat model assumptions

- The network may be observed or tampered with.
- The controller may be less trusted than the authenticator itself.
- The target must verify every command independently.
- Physical possession of the authenticator is out of scope for this model.

## Cryptographic Inventory

| Subsystem | Primitive | Status | Notes |
|---|---|---|---|
| Envelope encryption | `AES-256-GCM` | Current | Used inside the wrapped execution payload. |
| Key derivation | `SHA-256` | Current | Used in the envelope path. |
| User authentication | WebAuthn / CTAP2 | Current | Hardware-backed assertion verification. |
| Discovery beacons | `HMAC-SHA256` | Current | Used in the AmDNS path. |
| SSH key exchange | `CURVE25519` | Transitional | Still used because the Rust SSH layer does not yet expose native ML-KEM support. |

## PQC Status

### What is true today

- `uon` does not provide end-to-end native post-quantum SSH key exchange today.
- `uon` does wrap the inner execution envelope before it reaches the target verifier.
- The SSH transport itself still depends on classical primitives in the current `russh` stack.

### What this means in practice

The current design is a hybrid posture, not a fully PQC-native transport. That is stronger than plaintext command transit inside SSH alone, but weaker than a transport with native ML-KEM support from the SSH layer outward.

## Memory and Side-Channel Notes

### Implemented controls

- Rust-side sensitive paths use crates and patterns intended to reduce lingering secret material.
- The codebase includes support for zeroing and memory-handling hardening in native paths.
- HMAC validation is designed around constant-time comparison helpers.

### Important limitation

This repo does not currently present a formal third-party validation package, benchmark-backed side-channel report, or external compliance certification. Treat the security model as implemented engineering, not certified assurance.

## Operator Checklist

1. Use the documented Linux target deployment flow with `install_target.sh`.
2. Keep `authorized_passkeys.json` synchronized with the passkeys you intend to trust.
3. Review `known_hosts` entries on first connection and after target rebuilds.
4. Treat QR bridge usage as a fallback path, not the primary operator flow.
5. Track upstream SSH library progress before claiming PQC-complete transport.

## Related Docs

- [README](../README.md)
- [Release Notes](releases/)
