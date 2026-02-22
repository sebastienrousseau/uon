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
``transport``  Paramiko-based SSH transport, challenge generation, envelope
               construction, and target-side signature verification.
``utils``      Platform-aware configuration store and ``Target`` data model.
=============  =============================================================

Critical path (per-command lifecycle):

1. ``cli`` obtains a 32-byte nonce via ``transport.ssh_client``.
2. ``auth.fido_local`` signs the nonce inside the hardware enclave
   (graceful degradation to ``auth.qr_bridge`` if no local authenticator
   is detected).
3. ``transport.ssh_client`` wraps the signed assertion and the original
   command into a ``__UON_EXEC__`` envelope, sends it over SSH, and
   streams the result back.

Security boundary: the private key **never** leaves the hardware enclave.
The target machine independently verifies the FIDO2 signature before
executing any command.
"""
