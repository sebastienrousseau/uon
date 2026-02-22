# Copyright (c) 2024 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Authentication subsystem -- FIDO2 local biometric + QR bridge fallback.

This package owns the entire FIDO2 signing lifecycle.  You interact with
it through two public entry points:

* ``fido_local.register()`` -- one-time enrollment of a resident-key
  credential on your platform authenticator.
* ``fido_local.authenticate()`` -- signs a server-issued challenge with
  the enrolled credential.

When no local authenticator is detected (lid closed, headless Linux, WSL
without a Windows Hello bridge), the CLI transparently degrades to
``qr_bridge.request_signature_via_qr()``, which spawns an ephemeral,
LAN-only FastAPI server and displays an ASCII QR code so your phone can
sign the challenge via its own Secure Enclave.

Security invariants:

* Private key material never leaves the hardware enclave.
* The QR bridge server is restricted to RFC 1918 source IPs and a
  one-time bearer token.
* The bridge self-terminates after one assertion or a 120-second timeout.
"""
