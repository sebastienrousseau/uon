# Copyright (c) 2024 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Post-Quantum Cryptography hybrid wrapper for envelope decapsulation.

This module implements the target-side decapsulation logic for the PQC
hybrid envelope produced by `uon_core::ssh_core::pqc_encapsulate`. The
envelope format is:

    base64( kem_secret[32] || nonce[12] || ciphertext+tag )

The KEM secret is SHA-256 hashed to derive the AES-256-GCM key, matching
the encapsulation logic in the Rust core. This is a placeholder for real
ML-KEM (Kyber) encapsulation; the SSH channel provides transport security,
and this inner layer adds defense-in-depth.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Must match `PQC_AAD` in ssh_core.rs
_PQC_AAD = b"uon-pqc-v1"

# Envelope layout constants
_KEM_SECRET_LEN = 32
_NONCE_LEN = 12


class PQCHybridWrapper:
    """Decapsulates the PQC hybrid envelope on the target side."""

    def decapsulate_envelope(self, encoded_payload: str) -> str:
        """Decode a PQC-wrapped envelope and return the plaintext JSON.

        Args:
            encoded_payload: Base64-encoded string containing
                ``kem_secret || nonce || ciphertext+tag``.

        Returns:
            The decrypted JSON envelope string.

        Raises:
            ValueError: If the payload is structurally invalid or
                decryption fails (wrong key, tampered data).
        """
        try:
            raw = base64.b64decode(encoded_payload)
        except Exception as exc:
            raise ValueError("Invalid base64 in PQC envelope") from exc

        if len(raw) < _KEM_SECRET_LEN + _NONCE_LEN + 1:
            raise ValueError("PQC envelope too short")

        kem_secret = raw[:_KEM_SECRET_LEN]
        nonce = raw[_KEM_SECRET_LEN : _KEM_SECRET_LEN + _NONCE_LEN]
        ciphertext = raw[_KEM_SECRET_LEN + _NONCE_LEN :]

        # Derive AES-256-GCM key identically to Rust: SHA-256(kem_secret)
        shared_secret = hashlib.sha256(kem_secret).digest()

        try:
            aesgcm = AESGCM(shared_secret)
            plaintext = aesgcm.decrypt(nonce, ciphertext, _PQC_AAD)
        except Exception as exc:
            raise ValueError("PQC decapsulation failed: decryption error") from exc

        return plaintext.decode("utf-8")
