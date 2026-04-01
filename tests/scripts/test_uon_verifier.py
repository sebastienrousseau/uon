# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Tests for the uon_verifier target-side FIDO2 verification script."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers to build a realistic (but mock-verified) envelope
# ---------------------------------------------------------------------------

# The verifier expects RP ID b"uon.local"
_RP_ID = b"uon.local"
_RP_ID_HASH = hashlib.sha256(_RP_ID).digest()

# Minimal AuthenticatorData: 32-byte rpIdHash + 1-byte flags (UP=0x01)
_AUTH_DATA_VALID = _RP_ID_HASH + b"\x01" + b"\x00" * 4
_AUTH_DATA_NO_UP = _RP_ID_HASH + b"\x00" + b"\x00" * 4
_AUTH_DATA_BAD_RP = (b"\x00" * 32) + b"\x01" + b"\x00" * 4


def _b64url_encode(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_envelope(
    command: str = "echo hello",
    session_id: str = "test-session-001",
    auth_data: bytes = _AUTH_DATA_VALID,
    client_data: bytes = (b'{"type":"webauthn.get","challenge":"AA","origin":"https://uon.local"}'),
    signature: bytes = b"\xde\xad",
) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "command": command,
        "assertion": {
            "client_data": _b64url_encode(client_data),
            "auth_data": _b64url_encode(auth_data),
            "signature": _b64url_encode(signature),
        },
    }


def _import_verifier() -> Any:
    """Import (or re-import) the verifier script as a module."""
    spec = importlib.util.spec_from_file_location(
        "uon_verifier",
        str(Path(__file__).resolve().parents[2] / "scripts" / "uon_verifier.py"),
        submodule_search_locations=[],
    )
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    for name in (
        "fido2",
        "fido2.cbor",
        "fido2.cose",
        "fido2.webauthn",
    ):
        if name not in sys.modules:
            sys.modules[name] = MagicMock()
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def verifier() -> Any:
    mod = _import_verifier()
    mod._AUTHORIZED_KEYS_CACHE = None
    return mod


@pytest.fixture
def nonce_cache(tmp_path: Path, verifier: Any) -> Path:
    """Redirect the nonce cache to a temp directory."""
    cache_file = tmp_path / "used_sessions.json"
    verifier.USED_SESSIONS_FILE = str(cache_file)
    return cache_file


@pytest.fixture
def keys_file(tmp_path: Path, verifier: Any) -> Path:
    """Redirect the authorized passkeys file to a temp directory."""
    kf = tmp_path / "authorized_passkeys.json"
    verifier.AUTHORIZED_KEYS_FILE = str(kf)
    return kf


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEnvelopeParsing:
    """Tests for malformed or missing envelopes."""

    def test_missing_ssh_original_command(
        self, verifier: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("SSH_ORIGINAL_COMMAND", raising=False)
        with pytest.raises(SystemExit) as exc_info:
            verifier.verify_and_execute()
        assert exc_info.value.code == 1

    def test_invalid_prefix(self, verifier: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "NOT_UON some-payload")
        with pytest.raises(SystemExit) as exc_info:
            verifier.verify_and_execute()
        assert exc_info.value.code == 1

    def test_malformed_envelope(
        self,
        verifier: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv(
            "SSH_ORIGINAL_COMMAND",
            "__UON_EXEC__ not-valid-base64!!!",
        )
        mock_pqc_cls = MagicMock()
        mock_pqc_cls.return_value.decapsulate_envelope.side_effect = Exception("Bad")
        pqc_mod = MagicMock(PQCHybridWrapper=mock_pqc_cls)
        with (
            patch.dict(sys.modules, {"uon.transport.pqc": pqc_mod}),
            pytest.raises(SystemExit) as exc_info,
        ):
            verifier.verify_and_execute()
        assert exc_info.value.code == 1


class TestReplayProtection:
    """Tests for session nonce replay detection (N2)."""

    def test_replay_rejected(
        self,
        verifier: Any,
        nonce_cache: Path,
    ) -> None:
        sid = "session-replay-test"
        verifier._check_replay(sid)

        with pytest.raises(SystemExit) as exc_info:
            verifier._check_replay(sid)
        assert exc_info.value.code == 1

    def test_different_sessions_allowed(
        self,
        verifier: Any,
        nonce_cache: Path,
    ) -> None:
        verifier._check_replay("session-a")
        verifier._check_replay("session-b")

    def test_expired_sessions_purged(
        self,
        verifier: Any,
        nonce_cache: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import time as time_mod

        now = time_mod.time()
        monkeypatch.setattr(time_mod, "time", lambda: now)
        verifier._check_replay("old-session")

        monkeypatch.setattr(time_mod, "time", lambda: now + 301)
        verifier._check_replay("old-session")

    def test_missing_session_id_rejected(
        self,
        verifier: Any,
        monkeypatch: pytest.MonkeyPatch,
        nonce_cache: Path,
    ) -> None:
        envelope = _make_envelope(session_id="")
        envelope_json = json.dumps(envelope)

        mock_pqc_cls = MagicMock()
        mock_pqc_cls.return_value.decapsulate_envelope.return_value = envelope_json
        pqc_mod = MagicMock(PQCHybridWrapper=mock_pqc_cls)

        monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "__UON_EXEC__ encoded-data")
        with (
            patch.dict(sys.modules, {"uon.transport.pqc": pqc_mod}),
            pytest.raises(SystemExit) as exc_info,
        ):
            verifier.verify_and_execute()
        assert exc_info.value.code == 1


class TestSignatureVerification:
    """Tests for FIDO2 cryptographic verification steps."""

    def _run_verifier_with_envelope(
        self,
        verifier: Any,
        monkeypatch: pytest.MonkeyPatch,
        envelope: dict[str, Any],
        kf: Path,
        nc: Path,
        authorized_keys: list[dict[str, Any]] | None = None,
    ) -> int:
        """Run the verifier with a mock envelope, return exit code."""
        envelope_json = json.dumps(envelope)

        mock_pqc_cls = MagicMock()
        mock_pqc_cls.return_value.decapsulate_envelope.return_value = envelope_json
        pqc_mod = MagicMock(PQCHybridWrapper=mock_pqc_cls)

        if authorized_keys is not None:
            kf.write_text(json.dumps(authorized_keys))
        else:
            kf.write_text(json.dumps([]))

        monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "__UON_EXEC__ encoded-data")

        with (
            patch.dict(sys.modules, {"uon.transport.pqc": pqc_mod}),
            pytest.raises(SystemExit) as exc_info,
        ):
            verifier.verify_and_execute()
        code = exc_info.value.code
        assert isinstance(code, int)
        return code

    def test_rp_id_mismatch_rejected(
        self,
        verifier: Any,
        monkeypatch: pytest.MonkeyPatch,
        keys_file: Path,
        nonce_cache: Path,
    ) -> None:
        envelope = _make_envelope(auth_data=_AUTH_DATA_BAD_RP)
        code = self._run_verifier_with_envelope(
            verifier,
            monkeypatch,
            envelope,
            keys_file,
            nonce_cache,
            authorized_keys=[],
        )
        assert code == 1

    def test_missing_up_flag_rejected(
        self,
        verifier: Any,
        monkeypatch: pytest.MonkeyPatch,
        keys_file: Path,
        nonce_cache: Path,
    ) -> None:
        envelope = _make_envelope(auth_data=_AUTH_DATA_NO_UP)
        code = self._run_verifier_with_envelope(
            verifier,
            monkeypatch,
            envelope,
            keys_file,
            nonce_cache,
            authorized_keys=[],
        )
        assert code == 1

    def test_invalid_signature_rejected(
        self,
        verifier: Any,
        monkeypatch: pytest.MonkeyPatch,
        keys_file: Path,
        nonce_cache: Path,
    ) -> None:
        envelope = _make_envelope()
        fake_cose_hex = (
            "a10102032620215820"
            "0000000000000000000000000000000000000000"
            "0000000000000000000000002258200000000000"
            "0000000000000000000000000000000000000000"
            "000000000000000000"
        )
        code = self._run_verifier_with_envelope(
            verifier,
            monkeypatch,
            envelope,
            keys_file,
            nonce_cache,
            authorized_keys=[{"cose_key_hex": fake_cose_hex}],
        )
        assert code == 1

    @patch("uon.core", create=True)
    def test_valid_envelope_executes(
        self,
        mock_core: MagicMock,
        verifier: Any,
        monkeypatch: pytest.MonkeyPatch,
        keys_file: Path,
        nonce_cache: Path,
    ) -> None:
        mock_auth_data = MagicMock()
        mock_auth_data.rp_id_hash = _RP_ID_HASH
        mock_auth_data.is_user_present = True

        mock_key = MagicMock()
        mock_key.verify.return_value = None

        mock_cbor = MagicMock()
        mock_cbor.decode.return_value = {}
        mock_cose_key = MagicMock()
        mock_cose_key.parse.return_value = mock_key

        envelope = _make_envelope()
        envelope_json = json.dumps(envelope)

        mock_pqc_cls = MagicMock()
        mock_pqc_cls.return_value.decapsulate_envelope.return_value = envelope_json
        pqc_mod = MagicMock(PQCHybridWrapper=mock_pqc_cls)

        keys_file.write_text(json.dumps([{"cose_key_hex": "a0"}]))
        monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "__UON_EXEC__ encoded-data")

        monkeypatch.setattr(
            verifier,
            "AuthenticatorData",
            lambda _: mock_auth_data,
        )
        monkeypatch.setattr(verifier, "CoseKey", mock_cose_key)
        monkeypatch.setattr(verifier, "cbor", mock_cbor)

        mock_core.spawn_zsp_process.return_value = 0

        with (
            patch.dict(
                sys.modules,
                {
                    "uon.transport.pqc": pqc_mod,
                    "uon": MagicMock(core=mock_core),
                },
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            verifier.verify_and_execute()

        assert exc_info.value.code == 0
        mock_core.spawn_zsp_process.assert_called_once()


class TestNonceCache:
    """Tests for the file-based nonce cache helper functions."""

    def test_load_empty_cache(self, verifier: Any, nonce_cache: Path) -> None:
        cache = verifier._load_nonce_cache()
        assert cache == {}

    def test_save_and_load_cache(self, verifier: Any, nonce_cache: Path) -> None:
        import time as time_mod

        cache = {
            "sid-1": time_mod.time(),
            "sid-2": time_mod.time(),
        }
        verifier._save_nonce_cache(cache)
        loaded = verifier._load_nonce_cache()
        assert set(loaded.keys()) == {"sid-1", "sid-2"}

    def test_cache_file_permissions(self, verifier: Any, nonce_cache: Path) -> None:
        verifier._save_nonce_cache({"test": 1.0})
        stat = os.stat(nonce_cache)
        assert oct(stat.st_mode & 0o777) == "0o600"

    def test_corrupt_cache_returns_empty(self, verifier: Any, nonce_cache: Path) -> None:
        nonce_cache.write_text("{corrupt json!!!")
        cache = verifier._load_nonce_cache()
        assert cache == {}


class TestAuthorizedKeyCache:
    def test_cached_key_load_skips_reparse(self, verifier: Any, keys_file: Path) -> None:
        keys_file.write_text(json.dumps([{"cose_key_hex": "a0"}]))

        mock_key = MagicMock()
        parse_mock = MagicMock(return_value=mock_key)
        decode_mock = MagicMock(return_value={})

        verifier.CoseKey = MagicMock(parse=parse_mock)
        verifier.cbor = MagicMock(decode=decode_mock)

        first = verifier.load_authorized_keys()
        second = verifier.load_authorized_keys()

        assert first == [mock_key]
        assert second == [mock_key]
        assert parse_mock.call_count == 1
        assert decode_mock.call_count == 1
