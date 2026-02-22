# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the MIT License. See LICENSE file in the project root
# for full license information.

"""Tests for the Post-Quantum Cryptography integration layer."""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from uon.transport.pqc import PQCHybridWrapper


class TestPQCHybridWrapper:
    def test_encapsulate_decapsulate(self) -> None:
        shared_secret = b"12345678901234567890123456789012"
        pqc = PQCHybridWrapper(shared_secret=shared_secret)

        envelope_json = '{"version": 1, "command": "ls", "assertion": {}}'
        payload = pqc.encapsulate_envelope(envelope_json)

        # It should decode back to the same envelope
        assert pqc.decapsulate_envelope(payload) == envelope_json

    def test_default_key_generation(self) -> None:
        pqc1 = PQCHybridWrapper()
        pqc2 = PQCHybridWrapper()

        assert len(pqc1._key) == 32
        assert len(pqc2._key) == 32
        assert pqc1._key != pqc2._key

    def test_tamper_detection(self) -> None:
        shared_secret = b"12345678901234567890123456789012"
        pqc = PQCHybridWrapper(shared_secret=shared_secret)

        envelope_json = '{"command": "whoami"}'
        payload = pqc.encapsulate_envelope(envelope_json)

        # Tamper the base64 string
        tampered_payload = payload[:-4] + "AAAA"

        with pytest.raises(InvalidTag):
            pqc.decapsulate_envelope(tampered_payload)

    def test_wrong_key(self) -> None:
        pqc_sender = PQCHybridWrapper(shared_secret=b"A" * 32)
        pqc_receiver = PQCHybridWrapper(shared_secret=b"B" * 32)

        payload = pqc_sender.encapsulate_envelope("top secret")

        with pytest.raises(InvalidTag):
            pqc_receiver.decapsulate_envelope(payload)
