# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Tests for src.transport.ssh_client — challenge generation, envelope, SSH exec."""

from __future__ import annotations

import base64
import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from uon.transport.ssh_client import (
    ChallengePacket,
    ExecResult,
    _build_envelope,
    _wrap_command,
    execute_signed,
    generate_challenge,
    request_challenge,
    verify_assertion_locally,
)

# ── Data containers ───────────────────────────────────────────────────


class TestExecResult:
    def test_frozen(self) -> None:
        r = ExecResult(exit_code=0, stdout="ok", stderr="")
        with pytest.raises(AttributeError):
            r.exit_code = 1  # type: ignore[misc]

    def test_fields(self) -> None:
        r = ExecResult(exit_code=42, stdout="out", stderr="err")
        assert r.exit_code == 42
        assert r.stdout == "out"
        assert r.stderr == "err"


class TestChallengePacket:
    def test_fields(self) -> None:
        cp = ChallengePacket(nonce=b"n", session_id=b"s")
        assert cp.nonce == b"n"
        assert cp.session_id == b"s"

    def test_frozen(self) -> None:
        cp = ChallengePacket(nonce=b"n", session_id=b"s")
        with pytest.raises(AttributeError):
            cp.nonce = b"x"  # type: ignore[misc]


# ── generate_challenge() ─────────────────────────────────────────────


class TestGenerateChallenge:
    def test_nonce_length(self) -> None:
        c = generate_challenge()
        assert len(c.nonce) == 32

    def test_session_id_length(self) -> None:
        c = generate_challenge()
        assert len(c.session_id) == 32  # SHA-256 digest

    def test_uniqueness(self) -> None:
        a = generate_challenge()
        b = generate_challenge()
        assert a.nonce != b.nonce


# ── request_challenge() ──────────────────────────────────────────────


class TestRequestChallenge:
    def test_returns_challenge_packet(self) -> None:
        cp = request_challenge("host", 22, "root")
        assert isinstance(cp, ChallengePacket)
        assert len(cp.nonce) == 32


# ── _build_envelope() ────────────────────────────────────────────────


class TestBuildEnvelope:
    def test_structure(self) -> None:
        from uon.contracts.fido_dto import FidoAssertionDto
        challenge = ChallengePacket(nonce=b"\x01" * 32, session_id=b"\x02" * 32)
        assertion = FidoAssertionDto(credential_id=b"cid", client_data=b"cd", auth_data=b"ad", signature=b"sig")
        env = _build_envelope("ls -la", assertion, challenge)
        assert env.session_id == base64.b64encode(challenge.session_id).decode()
        assert env.command == ["ls", "-la"]
        assert env.assertion == assertion

    def test_base64_encoding(self) -> None:
        from uon.contracts.fido_dto import FidoAssertionDto
        challenge = ChallengePacket(nonce=b"\xff" * 4, session_id=b"\xaa" * 4)
        assertion = FidoAssertionDto(credential_id=b"cid", client_data=b"cd", auth_data=b"ad", signature=b"sig")
        env = _build_envelope("cmd", assertion, challenge)
        assert base64.b64decode(env.session_id) == b"\xaa" * 4


# ── _wrap_command() ──────────────────────────────────────────────────


class TestWrapCommand:
    def test_prefix(self) -> None:
        from uon.contracts.fido_dto import FidoAssertionDto, SecureEnvelopeDto
        assertion = FidoAssertionDto(credential_id=b"c", client_data=b"c", auth_data=b"a", signature=b"s")
        envelope = SecureEnvelopeDto(session_id="si", command=["hello", "world"], assertion=assertion)
        wrapped = _wrap_command(envelope)
        assert wrapped.startswith("__UON_EXEC__ ")

    @patch("uon.transport.pqc.os.urandom")
    def test_decodable_payload(self, mock_urandom: MagicMock) -> None:
        from uon.contracts.fido_dto import FidoAssertionDto, SecureEnvelopeDto
        from uon.transport.pqc import PQCHybridWrapper

        # Ensure the random KEM seed and nonce are identical for both wrapper instances
        mock_urandom.side_effect = lambda n: b"\x00" * n

        assertion = FidoAssertionDto(credential_id=b"c", client_data=b"c", auth_data=b"a", signature=b"s")
        envelope = SecureEnvelopeDto(session_id="si", command=["uptime"], assertion=assertion)
        wrapped = _wrap_command(envelope)
        b64_part = wrapped.split(" ", 1)[1]

        pqc = PQCHybridWrapper()
        decoded_string = pqc.decapsulate_envelope(b64_part)
        decoded = json.loads(decoded_string)

        assert decoded["command"] == ["uptime"]


# ── execute_signed() ─────────────────────────────────────────────────


class TestExecuteSigned:
    @patch("uon.transport.ssh_client.core.execute_signed_rust")
    def test_success(self, mock_rust: MagicMock) -> None:
        from uon.contracts.fido_dto import FidoAssertionDto
        mock_rust.return_value = (0, "result\n", "")
        challenge = ChallengePacket(nonce=b"\x00" * 32, session_id=b"\x00" * 32)
        assertion = FidoAssertionDto(credential_id=b"cid", client_data=b"cd", auth_data=b"ad", signature=b"sig")
        result = execute_signed("h", 22, "root", "ls", assertion, challenge)

        assert result.exit_code == 0
        assert result.stdout == "result\n"
        mock_rust.assert_called_once()

    @patch("uon.transport.ssh_client.core.execute_signed_rust")
    def test_close_on_error(self, mock_rust: MagicMock) -> None:
        from uon.contracts.fido_dto import FidoAssertionDto
        mock_rust.side_effect = Exception("refused")
        challenge = ChallengePacket(nonce=b"\x00" * 32, session_id=b"\x00" * 32)
        assertion = FidoAssertionDto(credential_id=b"cid", client_data=b"cd", auth_data=b"ad", signature=b"sig")
        with pytest.raises(OSError, match="SSH execution failed: refused"):
            execute_signed("h", 22, "root", "ls", assertion, challenge)
        mock_rust.assert_called_once()


# ── verify_assertion_locally() ────────────────────────────────────────


class TestVerifyAssertionLocally:
    @pytest.fixture
    def ed25519_key(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.generate()

    def test_valid_signature(self, ed25519_key: Ed25519PrivateKey) -> None:
        pub_bytes = ed25519_key.public_key().public_bytes_raw()
        challenge = b"test-challenge"
        authenticator_data = b"\x00" * 37
        client_data_json = b'{"type":"webauthn.get","challenge":"dGVzdC1jaGFsbGVuZ2U"}'

        client_data_hash = hashlib.sha256(client_data_json).digest()
        signed_data = authenticator_data + client_data_hash
        signature = ed25519_key.sign(signed_data)

        assert (
            verify_assertion_locally(
                pub_bytes, challenge, authenticator_data, client_data_json, signature
            )
            is True
        )

    def test_invalid_signature(self, ed25519_key: Ed25519PrivateKey) -> None:
        pub_bytes = ed25519_key.public_key().public_bytes_raw()
        assert verify_assertion_locally(pub_bytes, b"c", b"\x00" * 37, b"{}", b"\xff" * 64) is False

    def test_wrong_key(self) -> None:
        signing_key = Ed25519PrivateKey.generate()
        wrong_key = Ed25519PrivateKey.generate()
        authenticator_data = b"\x00" * 37
        client_data_json = b'{"type":"webauthn.get"}'
        client_data_hash = hashlib.sha256(client_data_json).digest()
        signed_data = authenticator_data + client_data_hash
        signature = signing_key.sign(signed_data)

        assert (
            verify_assertion_locally(
                wrong_key.public_key().public_bytes_raw(),
                b"c",
                authenticator_data,
                client_data_json,
                signature,
            )
            is False
        )
