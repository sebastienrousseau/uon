# uon_core

Welcome to `uon_core`. This is the resilient Rust execution monolith powering your `uon` ecosystem.

Use this crate to compute memory-safe cryptographic primitives. Expose hyper-concurrent network tunnels directly to Python via [PyO3].

## Architecture Details

- **FFI (Foreign Function Interface):** Pass strict byte arrays or serialized JSON across the procedural boundary. 
- **SSH Multiplexing:** Maintain persistent connection tunnels to your remote `TargetHost`. Inject FIDO2 hardware assertions directly across the wire.
- **Panic Bounds:** Never crash the user's host shell. `uon_core` natively intercepts all execution panics. It seamlessly maps any internal memory corruption or network failure back into a graceful Python `RuntimeError`.
