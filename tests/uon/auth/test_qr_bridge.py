# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Tests for src.auth.qr_bridge — QR-code FIDO2 fallback bridge."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.requests import Request
from starlette.routing import Route

from uon.auth.qr_bridge import (
    QrBridgeResult,
    _build_app,
    _get_lan_ip,
    _is_private_ip,
    _print_qr,
    _ServerThread,
    request_signature_via_qr,
)

RequestFactory = Callable[..., Request]

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
        """Keep route tests focused on token and payload handling."""
        monkeypatch.setattr("uon.auth.qr_bridge._is_private_ip", lambda _: True)

    def _make_app(
        self,
        token: str = "test-token-123",  # noqa: S107
        result: QrBridgeResult | None = None,
    ) -> tuple[FastAPI, str, QrBridgeResult]:
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
        return app, token, result

    @staticmethod
    def _route(
        app: FastAPI, path: str
    ) -> Callable[[Request], Awaitable[HTMLResponse | JSONResponse]]:
        for route in app.routes:
            if isinstance(route, Route) and route.path == path:
                return route.endpoint
        raise AssertionError(f"route not found: {path}")

    @staticmethod
    def _make_request(
        path: str,
        *,
        token: str | None = None,
        body: object | None = None,
        client_host: str = "192.168.1.50",
    ) -> Request:
        headers: list[tuple[bytes, bytes]] = []
        if token is not None:
            headers.append((b"authorization", f"Bearer {token}".encode()))

        if body is None:
            raw_body = b""
        elif isinstance(body, bytes):
            raw_body = body
        else:
            headers.append((b"content-type", b"application/json"))
            raw_body = json.dumps(body).encode("utf-8")

        delivered = False

        async def receive() -> dict[str, object]:
            nonlocal delivered
            if delivered:
                return {"type": "http.request", "body": b"", "more_body": False}
            delivered = True
            return {"type": "http.request", "body": raw_body, "more_body": False}

        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": "POST" if body is not None else "GET",
            "path": path,
            "query_string": b"" if token is None else f"token={token}".encode(),
            "headers": headers,
            "client": (client_host, 12345),
        }
        return Request(scope, receive)

    @pytest.mark.anyio
    async def test_sign_valid_token(self) -> None:
        app, token, _ = self._make_app()
        resp = await self._route(app, "/sign")(self._make_request("/sign", token=token))
        assert resp.status_code == 200
        assert "uon" in resp.body.decode()

    @pytest.mark.anyio
    async def test_sign_invalid_token(self) -> None:
        app, _, _ = self._make_app()
        bad_token = "".join(["wr", "ong"])
        with pytest.raises(HTTPException, match="Invalid token"):
            await self._route(app, "/sign")(self._make_request("/sign", token=bad_token))

    @pytest.mark.anyio
    async def test_sign_non_private_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Override the autouse fixture's patch
        monkeypatch.setattr("uon.auth.qr_bridge._is_private_ip", lambda _: False)
        app, token, _ = self._make_app()
        with pytest.raises(HTTPException, match="Non-private source IP rejected"):
            await self._route(app, "/sign")(self._make_request("/sign", token=token))

    @pytest.mark.anyio
    async def test_callback_valid(self) -> None:
        app, token, result = self._make_app()
        body = {
            "credentialId": "YWJj",
            "authenticatorData": "ZGVm",
            "clientDataJSON": "Z2hp",
            "signature": "amts",
        }
        resp = await self._route(app, "/callback")(
            self._make_request("/callback", token=token, body=body)
        )
        assert resp.status_code == 200
        assert result.assertion_json == body

    @pytest.mark.anyio
    async def test_callback_missing_fields(self) -> None:
        app, token, _ = self._make_app()
        with pytest.raises(HTTPException, match="Missing assertion fields"):
            await self._route(app, "/callback")(
                self._make_request("/callback", token=token, body={"credentialId": "x"})
            )

    @pytest.mark.anyio
    async def test_callback_invalid_token(self) -> None:
        app, _, _ = self._make_app()
        bad_token = "".join(["wr", "ong"])
        body = {
            "credentialId": "a",
            "authenticatorData": "b",
            "clientDataJSON": "c",
            "signature": "d",
        }
        with pytest.raises(HTTPException, match="Invalid token"):
            await self._route(app, "/callback")(
                self._make_request("/callback", token=bad_token, body=body)
            )

    @pytest.mark.anyio
    async def test_callback_non_private_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("uon.auth.qr_bridge._is_private_ip", lambda _: False)
        app, token, _ = self._make_app()
        body = {
            "credentialId": "a",
            "authenticatorData": "b",
            "clientDataJSON": "c",
            "signature": "d",
        }
        with pytest.raises(HTTPException, match="Non-private source IP rejected"):
            await self._route(app, "/callback")(
                self._make_request("/callback", token=token, body=body)
            )

    @pytest.mark.anyio
    async def test_callback_shutdown_event_none(self) -> None:
        token = "t"  # noqa: S105
        result = QrBridgeResult()
        app = _build_app("c", "rp", [], token, result, shutdown_event=None)
        body = {
            "credentialId": "a",
            "authenticatorData": "b",
            "clientDataJSON": "c",
            "signature": "d",
        }
        resp = await self._route(app, "/callback")(
            self._make_request("/callback", token=token, body=body)
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

    @patch("uon.auth.qr_bridge.uvicorn.Config")
    def test_init_with_ssl_context(self, mock_config: MagicMock) -> None:
        from fastapi import FastAPI

        app = FastAPI()
        ssl_context = MagicMock()
        _ServerThread(app, "127.0.0.1", 9996, ssl_context=ssl_context)
        assert mock_config.call_args is not None
        assert mock_config.call_args.kwargs["ssl"] is ssl_context


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
