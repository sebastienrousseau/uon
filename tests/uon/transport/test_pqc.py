# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Tests for the PQC hybrid wrapper decapsulation."""

from __future__ import annotations

import base64
import hashlib
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from uon.transport.pqc import PQCHybridWrapper

_PQC_AAD = b"uon-pqc-v1"


def _encapsulate(plaintext: str) -> str:
    """Replicate the Rust pqc_encapsulate logic in Python for testing."""
    kem_secret = os.urandom(32)
    shared_secret = hashlib.sha256(kem_secret).digest()
    nonce = os.urandom(12)

    aesgcm = AESGCM(shared_secret)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), _PQC_AAD)

    composite = kem_secret + nonce + ciphertext
    return base64.b64encode(composite).decode()


class TestPQCHybridWrapper:
    def test_round_trip(self) -> None:
        wrapper = PQCHybridWrapper()
        original = '{"session_id":"abc","command":["uptime"]}'
        encoded = _encapsulate(original)
        result = wrapper.decapsulate_envelope(encoded)
        assert result == original

    def test_invalid_base64(self) -> None:
        wrapper = PQCHybridWrapper()
        with pytest.raises(ValueError, match="Invalid base64"):
            wrapper.decapsulate_envelope("!!!not-base64!!!")

    def test_too_short(self) -> None:
        wrapper = PQCHybridWrapper()
        short = base64.b64encode(b"x" * 10).decode()
        with pytest.raises(ValueError, match="too short"):
            wrapper.decapsulate_envelope(short)

    def test_tampered_ciphertext(self) -> None:
        wrapper = PQCHybridWrapper()
        original = '{"test": true}'
        encoded = _encapsulate(original)
        raw = bytearray(base64.b64decode(encoded))
        # Flip a byte in the ciphertext portion
        raw[-5] ^= 0xFF
        tampered = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(ValueError, match="decryption error"):
            wrapper.decapsulate_envelope(tampered)

    def test_wrong_kem_secret(self) -> None:
        wrapper = PQCHybridWrapper()
        original = '{"test": true}'
        encoded = _encapsulate(original)
        raw = bytearray(base64.b64decode(encoded))
        # Corrupt the KEM secret (first 32 bytes)
        raw[0] ^= 0xFF
        corrupted = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(ValueError, match="decryption error"):
            wrapper.decapsulate_envelope(corrupted)
