# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Tests for src.auth.qr_bridge — QR-code FIDO2 fallback bridge."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest
from starlette.testclient import TestClient

from uon.auth.qr_bridge import (
    QrBridgeResult,
    _build_app,
    _get_lan_ip,
    _is_private_ip,
    _print_qr,
    _ServerThread,
    request_signature_via_qr,
)

# ── _get_lan_ip() ────────────────────────────────────────────────────


class TestGetLanIp:
    def test_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("192.168.1.42", 0)
        monkeypatch.setattr(
            "uon.auth.qr_bridge.socket.socket",
            lambda *a, **kw: mock_sock,
        )
        assert _get_lan_ip() == "192.168.1.42"

    def test_oserror_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("no route")
        mock_sock.getsockname.return_value = ("127.0.0.1", 0)
        monkeypatch.setattr(
            "uon.auth.qr_bridge.socket.socket",
            lambda *a, **kw: mock_sock,
        )
        result = _get_lan_ip()
        assert result == "127.0.0.1"


# ── _is_private_ip() ────────────────────────────────────────────────


class TestIsPrivateIp:
    @pytest.mark.parametrize(
        ("ip", "expected"),
        [
            ("192.168.1.1", True),
            ("10.0.0.1", True),
            ("172.16.0.1", True),
            ("127.0.0.1", True),
            ("8.8.8.8", False),
            ("not-an-ip", False),
        ],
    )
    def test_cases(self, ip: str, expected: bool) -> None:
        assert _is_private_ip(ip) is expected


# ── QrBridgeResult ──────────────────────────────────────────────────


class TestQrBridgeResult:
    def test_initial_state(self) -> None:
        r = QrBridgeResult()
        assert r.assertion_json is None
        assert r.error is None

    def test_set_assertion(self) -> None:
        r = QrBridgeResult()
        r.set_assertion({"sig": "data"})
        assert r.assertion_json == {"sig": "data"}
        assert r.wait(timeout=0.01) is True

    def test_set_error(self) -> None:
        r = QrBridgeResult()
        r.set_error("boom")
        assert r.error == "boom"
        assert r.wait(timeout=0.01) is True

    def test_wait_timeout(self) -> None:
        r = QrBridgeResult()
        assert r.wait(timeout=0.01) is False


# ── _build_app() route tests ────────────────────────────────────────


class TestBuildApp:
    @pytest.fixture(autouse=True)
    def _patch_private_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """TestClient sends from 'testclient' — make the IP guard accept it."""
        monkeypatch.setattr("uon.auth.qr_bridge._is_private_ip", lambda _: True)

    def _make_app(
        self,
        token: str = "test-token-123",  # noqa: S107
        result: QrBridgeResult | None = None,
    ) -> tuple[TestClient, str, QrBridgeResult]:
        if result is None:
            result = QrBridgeResult()
        shutdown = asyncio.Event()
        app = _build_app(
            challenge_b64="Y2hhbGxlbmdl",
            rp_id="uon.local",
            credential_ids_b64=["Y3JlZDE="],
            bearer_token=token,
            result=result,
            shutdown_event=shutdown,
        )
        return TestClient(app), token, result

    def test_sign_valid_token(self) -> None:
        client, token, _ = self._make_app()
        resp = client.get(f"/sign?token={token}")
        assert resp.status_code == 200
        assert "uon" in resp.text

    def test_sign_invalid_token(self) -> None:
        client, _, _ = self._make_app()
        resp = client.get("/sign?token=wrong")
        assert resp.status_code == 403

    def test_sign_non_private_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Override the autouse fixture's patch
        monkeypatch.setattr("uon.auth.qr_bridge._is_private_ip", lambda _: False)
        client, token, _ = self._make_app()
        resp = client.get(f"/sign?token={token}")
        assert resp.status_code == 403

    def test_callback_valid(self) -> None:
        client, token, result = self._make_app()
        body = {
            "credentialId": "YWJj",
            "authenticatorData": "ZGVm",
            "clientDataJSON": "Z2hp",
            "signature": "amts",
        }
        resp = client.post(
            "/callback",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert result.assertion_json == body

    def test_callback_missing_fields(self) -> None:
        client, token, _ = self._make_app()
        resp = client.post(
            "/callback",
            json={"credentialId": "x"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 422

    def test_callback_invalid_token(self) -> None:
        client, _, _ = self._make_app()
        body = {
            "credentialId": "a",
            "authenticatorData": "b",
            "clientDataJSON": "c",
            "signature": "d",
        }
        resp = client.post(
            "/callback",
            json=body,
            headers={"Authorization": "Bearer wrong"},
        )
        assert resp.status_code == 403

    def test_callback_non_private_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("uon.auth.qr_bridge._is_private_ip", lambda _: False)
        client, token, _ = self._make_app()
        body = {
            "credentialId": "a",
            "authenticatorData": "b",
            "clientDataJSON": "c",
            "signature": "d",
        }
        resp = client.post(
            "/callback",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_callback_shutdown_event_none(self) -> None:
        token = "t"  # noqa: S105
        result = QrBridgeResult()
        app = _build_app("c", "rp", [], token, result, shutdown_event=None)
        client = TestClient(app)
        body = {
            "credentialId": "a",
            "authenticatorData": "b",
            "clientDataJSON": "c",
            "signature": "d",
        }
        resp = client.post(
            "/callback",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert result.assertion_json == body


# ── _print_qr() ─────────────────────────────────────────────────────


class TestPrintQr:
    def test_prints_to_stderr(self, capsys: pytest.CaptureFixture[str]) -> None:
        _print_qr("http://192.168.1.1:8080/sign?token=abc")
        captured = capsys.readouterr()
        assert "192.168.1.1" in captured.err


# ── _ServerThread ────────────────────────────────────────────────────


class TestServerThread:
    def test_init(self) -> None:
        from fastapi import FastAPI

        app = FastAPI()
        st = _ServerThread(app, "127.0.0.1", 9999)
        assert st.daemon is True

    def test_shutdown_sets_should_exit(self) -> None:
        from fastapi import FastAPI

        app = FastAPI()
        st = _ServerThread(app, "127.0.0.1", 9998)
        st.shutdown()
        assert st.server.should_exit is True

    def test_run_calls_server(self) -> None:
        from fastapi import FastAPI

        app = FastAPI()
        st = _ServerThread(app, "127.0.0.1", 9997)
        st.server = MagicMock()
        st.run()
        st.server.run.assert_called_once()


# ── request_signature_via_qr() ──────────────────────────────────────


class TestRequestSignatureViaQr:
    @patch("uon.auth.qr_bridge._print_qr")
    @patch("uon.auth.qr_bridge._ServerThread")
    @patch("uon.auth.qr_bridge._get_lan_ip", return_value="192.168.1.5")
    @patch("uon.auth.qr_bridge.time.sleep")
    def test_success(
        self,
        mock_sleep: MagicMock,
        mock_ip: MagicMock,
        mock_thread_cls: MagicMock,
        mock_print_qr: MagicMock,
    ) -> None:
        assertion_data = {
            "credentialId": "YWJj",
            "authenticatorData": "ZGVm",
            "clientDataJSON": "Z2hp",
            "signature": "amts",
        }

        mock_thread = MagicMock()
        mock_thread_cls.return_value = mock_thread

        with patch("uon.auth.qr_bridge.QrBridgeResult") as mock_result_cls:
            mock_result = MagicMock()
            mock_result.wait.return_value = True
            mock_result.error = None
            mock_result.assertion_json = assertion_data
            mock_result_cls.return_value = mock_result

            result = request_signature_via_qr(
                challenge=b"nonce",
                rp_id="uon.local",
                credential_ids=[b"cid"],
                timeout=5,
            )

        assert result.credential_id == b"abc"
        assert result.signature == b"jkl"
        mock_thread.start.assert_called_once()
        mock_thread.shutdown.assert_called_once()

    @patch("uon.auth.qr_bridge._print_qr")
    @patch("uon.auth.qr_bridge._ServerThread")
    @patch("uon.auth.qr_bridge._get_lan_ip", return_value="192.168.1.5")
    @patch("uon.auth.qr_bridge.time.sleep")
    def test_timeout(
        self,
        mock_sleep: MagicMock,
        mock_ip: MagicMock,
        mock_thread_cls: MagicMock,
        mock_print_qr: MagicMock,
    ) -> None:
        mock_thread = MagicMock()
        mock_thread_cls.return_value = mock_thread

        with patch("uon.auth.qr_bridge.QrBridgeResult") as mock_result_cls:
            mock_result = MagicMock()
            mock_result.wait.return_value = False
            mock_result_cls.return_value = mock_result

            with pytest.raises(TimeoutError):
                request_signature_via_qr(
                    challenge=b"n",
                    rp_id="uon.local",
                    credential_ids=[b"c"],
                    timeout=0.01,
                )

    @patch("uon.auth.qr_bridge._print_qr")
    @patch("uon.auth.qr_bridge._ServerThread")
    @patch("uon.auth.qr_bridge._get_lan_ip", return_value="192.168.1.5")
    @patch("uon.auth.qr_bridge.time.sleep")
    def test_error(
        self,
        mock_sleep: MagicMock,
        mock_ip: MagicMock,
        mock_thread_cls: MagicMock,
        mock_print_qr: MagicMock,
    ) -> None:
        mock_thread = MagicMock()
        mock_thread_cls.return_value = mock_thread

        with patch("uon.auth.qr_bridge.QrBridgeResult") as mock_result_cls:
            mock_result = MagicMock()
            mock_result.wait.return_value = True
            mock_result.error = "phone error"
            mock_result.assertion_json = None
            mock_result_cls.return_value = mock_result

            with pytest.raises(RuntimeError, match="phone error"):
                request_signature_via_qr(
                    challenge=b"n",
                    rp_id="uon.local",
                    credential_ids=[b"c"],
                    timeout=5,
                )
