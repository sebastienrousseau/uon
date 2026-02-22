# uon.transport

## Overview
The `uon.transport` package handles the secure tunneling of Zero-Trust payloads (Commands + Signatures) directly into the monolithic Rust backend for SSH execution.

## Responsibilities
- Maps the Python `FidoAssertionDto` directly onto the Rust `uon.core` boundary.
- Resolves transient network connectivity issues (timeouts, dropped connections) locally before failing hard to the terminal user interface.

## Constraints
To guarantee the strictest security environment, this module must never cache ephemeral data, host telemetry, or unencrypted credential IDs in active memory longer than the immediate function's execution lifecycle.
