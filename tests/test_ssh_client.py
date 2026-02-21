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
    _connect,
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


# ── _connect() ───────────────────────────────────────────────────────


class TestConnect:
    @patch("uon.transport.ssh_client.paramiko.SSHClient")
    def test_returns_client(self, mock_ssh_cls: MagicMock) -> None:
        mock_client = mock_ssh_cls.return_value
        result = _connect("example.com", 22, "root")
        assert result is mock_client
        mock_client.set_missing_host_key_policy.assert_called_once()
        mock_client.connect.assert_called_once_with(
            hostname="example.com",
            port=22,
            username="root",
            look_for_keys=False,
            allow_agent=False,
            auth_timeout=10,
        )


# ── _build_envelope() ────────────────────────────────────────────────


class TestBuildEnvelope:
    def test_structure(self) -> None:
        challenge = ChallengePacket(nonce=b"\x01" * 32, session_id=b"\x02" * 32)
        env = _build_envelope("ls", {"sig": "abc"}, challenge)
        assert env["version"] == 1
        assert env["command"] == "ls"
        assert env["assertion"] == {"sig": "abc"}
        assert "challenge" in env
        assert "session_id" in env

    def test_base64_encoding(self) -> None:
        challenge = ChallengePacket(nonce=b"\xff" * 4, session_id=b"\xaa" * 4)
        env = _build_envelope("cmd", {}, challenge)
        assert base64.b64decode(env["challenge"]) == b"\xff" * 4
        assert base64.b64decode(env["session_id"]) == b"\xaa" * 4


# ── _wrap_command() ──────────────────────────────────────────────────


class TestWrapCommand:
    def test_prefix(self) -> None:
        wrapped = _wrap_command({"hello": "world"})
        assert wrapped.startswith("__UON_EXEC__ ")

    def test_decodable_payload(self) -> None:
        envelope = {"command": "uptime", "version": 1}
        wrapped = _wrap_command(envelope)
        b64_part = wrapped.split(" ", 1)[1]
        decoded = json.loads(base64.b64decode(b64_part))
        assert decoded["command"] == "uptime"


# ── execute_signed() ─────────────────────────────────────────────────


class TestExecuteSigned:
    @patch("uon.transport.ssh_client.paramiko.SSHClient")
    def test_success(self, mock_ssh_cls: MagicMock) -> None:
        client = mock_ssh_cls.return_value
        stdout_chan = MagicMock()
        stdout_chan.recv_exit_status.return_value = 0
        stdout_mock = MagicMock()
        stdout_mock.read.return_value = b"result\n"
        stdout_mock.channel = stdout_chan
        stderr_mock = MagicMock()
        stderr_mock.read.return_value = b""
        client.exec_command.return_value = (MagicMock(), stdout_mock, stderr_mock)

        challenge = ChallengePacket(nonce=b"\x00" * 32, session_id=b"\x00" * 32)
        result = execute_signed("h", 22, "root", "ls", {"s": "1"}, challenge)

        assert result.exit_code == 0
        assert result.stdout == "result\n"
        client.close.assert_called_once()

    @patch("uon.transport.ssh_client.paramiko.SSHClient")
    def test_close_on_error(self, mock_ssh_cls: MagicMock) -> None:
        client = mock_ssh_cls.return_value
        client.connect.side_effect = OSError("refused")

        challenge = ChallengePacket(nonce=b"\x00" * 32, session_id=b"\x00" * 32)
        with pytest.raises(OSError, match="refused"):
            execute_signed("h", 22, "root", "ls", {}, challenge)

        client.close.assert_called_once()


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
