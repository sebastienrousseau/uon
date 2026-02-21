"""Tests for src.auth.fido_local — FIDO2 platform authenticator interactions."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

from uon.auth.fido_local import (
    RP_ID,
    RP_NAME,
    NoPlatformAuthenticatorError,
    _CliInteraction,
    _discover_client,
    _make_rp,
    _make_server,
    authenticate,
    register,
)

# ── Constants ─────────────────────────────────────────────────────────


class TestConstants:
    def test_rp_id(self) -> None:
        assert RP_ID == "uon.local"

    def test_rp_name(self) -> None:
        assert isinstance(RP_NAME, str)
        assert len(RP_NAME) > 0


# ── _CliInteraction ──────────────────────────────────────────────────


class TestCliInteraction:
    def test_prompt_up(self, capsys: pytest.CaptureFixture[str]) -> None:
        _CliInteraction().prompt_up()
        captured = capsys.readouterr()
        assert "Touch" in captured.err or "authenticator" in captured.err

    @patch("getpass.getpass", return_value="1234")
    def test_request_pin(self, mock_gp: MagicMock) -> None:
        result = _CliInteraction().request_pin(permissions=None)
        assert result == "1234"

    def test_request_uv(self) -> None:
        assert _CliInteraction().request_uv(permissions=None) is True


# ── _discover_client() ───────────────────────────────────────────────


class TestDiscoverClient:
    def test_darwin_touchid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("uon.auth.fido_local.sys.platform", "darwin")
        mock_client = MagicMock()
        fake_mod = MagicMock()
        fake_mod.MacOSClient.return_value = mock_client
        monkeypatch.setitem(sys.modules, "fido2.client", fake_mod)

        result = _discover_client("uon.local")
        assert result is mock_client

    def test_darwin_fallback_to_hid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("uon.auth.fido_local.sys.platform", "darwin")
        # MacOSClient constructor raises
        fake_mod = MagicMock()
        fake_mod.MacOSClient.side_effect = Exception("no touchid")
        monkeypatch.setitem(sys.modules, "fido2.client", fake_mod)

        hid_device = MagicMock()
        monkeypatch.setattr("uon.auth.fido_local.CtapHidDevice.list_devices", lambda: [hid_device])
        mock_fido_client = MagicMock()
        monkeypatch.setattr("uon.auth.fido_local.Fido2Client", lambda *a, **kw: mock_fido_client)
        result = _discover_client("uon.local")
        assert result is mock_fido_client

    def test_win32_hello(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("uon.auth.fido_local.sys.platform", "win32")
        mock_client = MagicMock()
        fake_mod = MagicMock()
        fake_mod.WindowsClient.is_available.return_value = True
        fake_mod.WindowsClient.return_value = mock_client
        monkeypatch.setitem(sys.modules, "fido2.client", fake_mod)

        result = _discover_client("uon.local")
        assert result is mock_client

    def test_win32_not_available_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("uon.auth.fido_local.sys.platform", "win32")
        fake_mod = MagicMock()
        fake_mod.WindowsClient.is_available.return_value = False
        monkeypatch.setitem(sys.modules, "fido2.client", fake_mod)
        monkeypatch.setattr("uon.auth.fido_local.CtapHidDevice.list_devices", lambda: [])
        with pytest.raises(NoPlatformAuthenticatorError):
            _discover_client("uon.local")

    def test_win32_exception_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Cover the except block in the win32 branch (lines 103-104)."""
        monkeypatch.setattr("uon.auth.fido_local.sys.platform", "win32")
        fake_mod = MagicMock()
        fake_mod.WindowsClient.is_available.side_effect = OSError("broken")
        monkeypatch.setitem(sys.modules, "fido2.client", fake_mod)
        monkeypatch.setattr("uon.auth.fido_local.CtapHidDevice.list_devices", lambda: [])
        with pytest.raises(NoPlatformAuthenticatorError):
            _discover_client("uon.local")

    def test_linux_hid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("uon.auth.fido_local.sys.platform", "linux")
        hid_device = MagicMock()
        monkeypatch.setattr("uon.auth.fido_local.CtapHidDevice.list_devices", lambda: [hid_device])
        mock_fido_client = MagicMock()
        monkeypatch.setattr("uon.auth.fido_local.Fido2Client", lambda *a, **kw: mock_fido_client)
        result = _discover_client("uon.local")
        assert result is mock_fido_client

    def test_no_device_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("uon.auth.fido_local.sys.platform", "linux")
        monkeypatch.setattr("uon.auth.fido_local.CtapHidDevice.list_devices", lambda: [])
        with pytest.raises(NoPlatformAuthenticatorError):
            _discover_client("uon.local")


# ── _make_rp / _make_server ──────────────────────────────────────────


class TestMakeRpAndServer:
    def test_make_rp_type(self) -> None:
        from fido2.webauthn import PublicKeyCredentialRpEntity

        rp = _make_rp()
        assert isinstance(rp, PublicKeyCredentialRpEntity)
        assert rp.get("id") == RP_ID

    def test_make_server_type(self) -> None:
        from fido2.server import Fido2Server

        server = _make_server()
        assert isinstance(server, Fido2Server)


# ── register() ───────────────────────────────────────────────────────


class TestRegister:
    @patch("uon.auth.fido_local._make_server")
    @patch("uon.auth.fido_local._discover_client")
    def test_success(self, mock_discover: MagicMock, mock_server_fn: MagicMock) -> None:
        mock_client = MagicMock()
        mock_discover.return_value = mock_client

        server = MagicMock()
        mock_server_fn.return_value = server

        server.register_begin.return_value = (
            {"publicKey": {"challenge": b"c"}},
            {"state": "s"},
        )
        mock_client.make_credential.return_value = MagicMock()

        cred_data = MagicMock()
        cred_data.credential_id = b"cred-id-123"
        cred_data.aaguid = MagicMock(__str__=lambda self: "2fc0579f-8113-47ea-b116-bb5a8db9202a")
        auth_data = MagicMock()
        auth_data.credential_data = cred_data
        auth_data.is_backup_eligible.return_value = False
        server.register_complete.return_value = auth_data

        result = register(user_id=b"uid", user_name="tester")
        assert result.credential_id == b"cred-id-123"
        assert result.auth_data is auth_data
        assert result.aaguid == "2fc0579f-8113-47ea-b116-bb5a8db9202a"
        assert result.backup_eligible is False

    @patch("uon.auth.fido_local._discover_client")
    def test_no_authenticator(self, mock_discover: MagicMock) -> None:
        mock_discover.side_effect = NoPlatformAuthenticatorError("none")
        with pytest.raises(NoPlatformAuthenticatorError):
            register(user_id=b"u", user_name="x")

    @patch("uon.auth.fido_local._make_server")
    @patch("uon.auth.fido_local._discover_client")
    @patch("uon.auth.fido_local.platform.system", return_value="Linux")
    def test_linux_cross_platform(
        self, mock_sys: MagicMock, mock_discover: MagicMock, mock_server_fn: MagicMock
    ) -> None:
        mock_client = MagicMock()
        mock_discover.return_value = mock_client
        server = MagicMock()
        mock_server_fn.return_value = server

        server.register_begin.return_value = (
            {"publicKey": {"challenge": b"c"}},
            {"state": "s"},
        )
        mock_client.make_credential.return_value = MagicMock()

        cred_data = MagicMock()
        cred_data.credential_id = b"id"
        cred_data.aaguid = MagicMock(__str__=lambda self: "2fc0579f-8113-47ea-b116-bb5a8db9202a")
        auth_data = MagicMock()
        auth_data.credential_data = cred_data
        auth_data.is_backup_eligible.return_value = False
        server.register_complete.return_value = auth_data

        register(user_id=b"u", user_name="x")

        # Verify CROSS_PLATFORM attachment was used
        call_kwargs = server.register_begin.call_args
        from fido2.webauthn import AuthenticatorAttachment

        assert (
            call_kwargs.kwargs.get("authenticator_attachment")
            == AuthenticatorAttachment.CROSS_PLATFORM
        )

    @patch("uon.auth.fido_local._make_server")
    @patch("uon.auth.fido_local._discover_client")
    def test_backup_eligible_flag(
        self, mock_discover: MagicMock, mock_server_fn: MagicMock
    ) -> None:
        mock_client = MagicMock()
        mock_discover.return_value = mock_client
        server = MagicMock()
        mock_server_fn.return_value = server

        server.register_begin.return_value = (
            {"publicKey": {"challenge": b"c"}},
            {"state": "s"},
        )
        mock_client.make_credential.return_value = MagicMock()

        cred_data = MagicMock()
        cred_data.credential_id = b"id"
        cred_data.aaguid = MagicMock(__str__=lambda self: "2fc0579f-8113-47ea-b116-bb5a8db9202a")
        auth_data = MagicMock()
        auth_data.credential_data = cred_data
        auth_data.is_backup_eligible.return_value = True
        server.register_complete.return_value = auth_data

        result = register(user_id=b"u", user_name="x")
        assert result.backup_eligible is True

    @patch("uon.auth.fido_local._make_server")
    @patch("uon.auth.fido_local._discover_client")
    def test_no_credential_data_raises(
        self, mock_discover: MagicMock, mock_server_fn: MagicMock
    ) -> None:
        mock_client = MagicMock()
        mock_discover.return_value = mock_client
        server = MagicMock()
        mock_server_fn.return_value = server

        server.register_begin.return_value = (
            {"publicKey": {"challenge": b"c"}},
            {"state": "s"},
        )
        mock_client.make_credential.return_value = MagicMock()

        auth_data = MagicMock()
        auth_data.credential_data = None
        server.register_complete.return_value = auth_data

        with pytest.raises(RuntimeError, match="no credential data"):
            register(user_id=b"u", user_name="x")


# ── authenticate() ───────────────────────────────────────────────────


class TestAuthenticate:
    @patch("uon.auth.fido_local._make_server")
    @patch("uon.auth.fido_local._discover_client")
    def test_success(self, mock_discover: MagicMock, mock_server_fn: MagicMock) -> None:
        mock_client = MagicMock()
        mock_discover.return_value = mock_client
        server = MagicMock()
        mock_server_fn.return_value = server

        server.authenticate_begin.return_value = (
            {"publicKey": {"challenge": b"server-challenge", "rpId": "uon.local"}},
            {"state": "s"},
        )

        mock_response = MagicMock()
        mock_assertion = MagicMock()
        mock_assertion.get_response.return_value = mock_response
        mock_client.get_assertion.return_value = mock_assertion

        result = authenticate(
            challenge=b"remote-nonce",
            credential_ids=[b"cid1"],
        )
        assert result is mock_response

    @patch("uon.auth.fido_local._discover_client")
    def test_no_authenticator(self, mock_discover: MagicMock) -> None:
        mock_discover.side_effect = NoPlatformAuthenticatorError("none")
        with pytest.raises(NoPlatformAuthenticatorError):
            authenticate(challenge=b"c", credential_ids=[b"id"])

    @patch("uon.auth.fido_local._make_server")
    @patch("uon.auth.fido_local._discover_client")
    def test_challenge_override(self, mock_discover: MagicMock, mock_server_fn: MagicMock) -> None:
        mock_client = MagicMock()
        mock_discover.return_value = mock_client
        server = MagicMock()
        mock_server_fn.return_value = server

        server.authenticate_begin.return_value = (
            {"publicKey": {"challenge": b"server-challenge"}},
            {"state": "s"},
        )
        mock_assertion = MagicMock()
        mock_client.get_assertion.return_value = mock_assertion
        mock_assertion.get_response.return_value = MagicMock()

        authenticate(challenge=b"my-nonce", credential_ids=[b"cid"])

        call_args = mock_client.get_assertion.call_args[0][0]
        assert call_args["challenge"] == b"my-nonce"

    @patch("uon.auth.fido_local._make_server")
    @patch("uon.auth.fido_local._discover_client")
    def test_multiple_credentials(
        self, mock_discover: MagicMock, mock_server_fn: MagicMock
    ) -> None:
        mock_client = MagicMock()
        mock_discover.return_value = mock_client
        server = MagicMock()
        mock_server_fn.return_value = server

        server.authenticate_begin.return_value = (
            {"publicKey": {"challenge": b"c"}},
            {"state": "s"},
        )
        mock_assertion = MagicMock()
        mock_client.get_assertion.return_value = mock_assertion
        mock_assertion.get_response.return_value = MagicMock()

        authenticate(
            challenge=b"c",
            credential_ids=[b"cid1", b"cid2", b"cid3"],
        )

        call_kwargs = server.authenticate_begin.call_args
        creds = call_kwargs.kwargs.get("credentials") or call_kwargs[1].get("credentials")
        assert len(creds) == 3
