# uon.auth

## Overview
The `uon.auth` module encapsulates the Zero-Trust cryptographic pathways for the Python CLI. It bridges the gap between the `click` terminal router and the physical FIDO2 authenticator hardware (e.g., YubiKeys, Touch ID, Windows Hello).

## Key Components

- **`fido_local.py`**: The primary interaction layer for platform authenticators. Exposes the `register` and `authenticate` primitives to seamlessly wrap the `fido2` library constraints and mint Resident Keys (Passkeys) directly inside the Secure Enclave.
- **`qr_bridge.py`**: The Tier-2 fallback mechanism. If no local platform authenticator is available (e.g., inside an isolated Docker container or WSL environment), the CLI degrades to displaying an animated ASCII QR code, tunneling the WebAuthn challenge directly to a mobile companion device.

## Dependencies
This module strictly requires the external `fido2>=1.1` and `qrcode[pil]` pip packages.
