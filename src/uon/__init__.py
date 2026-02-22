# Copyright (c) 2024 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""uon -- FIDO2-signed remote terminal execution.

You use uon to run shell commands on remote machines where every invocation
is cryptographically signed by your device's hardware Secure Enclave (Touch
ID, Windows Hello, or a USB security key).  No private key material ever
touches disk.

Package layout:

=============  =============================================================
Sub-package    Responsibility
=============  =============================================================
``auth``       FIDO2 credential enrollment, challenge signing (local
               biometric + ephemeral QR bridge fallback).
``transport``  Legacy FIDO2 DTO wrappers. (Core logic migrated to `uon.core`)
``utils``      Platform-aware configuration store and ``Target`` data model.
=============  =============================================================

Critical path (per-command lifecycle):

1. ``cli`` obtains a 32-byte nonce via ``core.generate_challenge()``.
2. ``auth.fido_local`` signs the nonce inside the hardware enclave
   (graceful degradation to ``auth.qr_bridge`` if no local authenticator
   is detected).
3. ``cli`` passes the signed assertion to ``core.execute_session()``, 
   which dynamically wraps a PQC envelope and transmits it natively via 
   Tokio/Russh.

Security boundary: the private key **never** leaves the hardware enclave.
The target machine independently verifies the FIDO2 signature before
executing any command.
"""
