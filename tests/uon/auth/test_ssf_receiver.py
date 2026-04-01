# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Tests for the Shared Signals Framework (SSF) Receiver."""

from __future__ import annotations

import json
from collections.abc import Callable
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from uon.auth.ssf_receiver import RISC_ACCOUNT_DISABLED, receive_ssf_event

_TEST_BEARER_TOKEN = "test-ssf-token-42"  # noqa: S105

RequestFactory = Callable[[object], Request]


@pytest.fixture(autouse=True)
def _set_ssf_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure a test shared secret for all SSF tests."""
    monkeypatch.setattr("uon.auth.ssf_receiver._SSF_SHARED_SECRET", _TEST_BEARER_TOKEN)


@pytest.fixture
def make_request() -> RequestFactory:
    def factory(payload: object, authorization: str | None = None) -> Request:
        headers: list[tuple[bytes, bytes]] = []
        if authorization is not None:
            headers.append((b"authorization", authorization.encode("utf-8")))

        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        delivered = False

        async def receive() -> dict[str, object]:
            nonlocal delivered
            if delivered:
                return {"type": "http.request", "body": b"", "more_body": False}
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}

        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "path": "/ssf/events",
            "headers": headers,
        }
        return Request(scope, receive)

    return factory


class TestSSFAuthentication:
    @pytest.mark.anyio
    async def test_missing_auth_header(self, make_request: RequestFactory) -> None:
        with pytest.raises(HTTPException, match="Missing Bearer"):
            await receive_ssf_event(make_request({"events": {}}))

    @pytest.mark.anyio
    async def test_wrong_token(self, make_request: RequestFactory) -> None:
        with pytest.raises(HTTPException, match="Invalid Bearer"):
            await receive_ssf_event(make_request({"events": {}}, "Bearer wrong-token"))

    @pytest.mark.anyio
    async def test_no_secret_configured(
        self, make_request: RequestFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("uon.auth.ssf_receiver._SSF_SHARED_SECRET", "")
        with pytest.raises(HTTPException, match="not configured"):
            await receive_ssf_event(make_request({"events": {}}, f"Bearer {_TEST_BEARER_TOKEN}"))


class TestSSFReceiver:
    @patch("uon.auth.ssf_receiver.subprocess.run")
    def test_kill_sessions_without_subject(self, mock_run: MagicMock) -> None:
        from uon.auth.ssf_receiver import kill_uon_sessions

        kill_uon_sessions("")
        mock_run.assert_called_once_with(["pkill", "-9", "-f", "uon_verifier.py"], check=False)

    @patch("uon.auth.ssf_receiver.subprocess.run")
    @pytest.mark.anyio
    async def test_account_disabled_event(
        self, mock_run: MagicMock, make_request: RequestFactory
    ) -> None:
        payload = {
            "iss": "https://idp.example.com/",
            "iat": 1600000000,
            "jti": "jti123456",
            "events": {
                RISC_ACCOUNT_DISABLED: {
                    "subject": {"format": "email", "email": "admin@example.com"}
                }
            },
        }
        response = await receive_ssf_event(make_request(payload, f"Bearer {_TEST_BEARER_TOKEN}"))
        assert response["status"] == "accepted"

        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "pkill" in args
        pattern = args[-1]
        assert "uon_verifier.py" in pattern
        assert "admin@example.com" in pattern

    @patch("uon.auth.ssf_receiver.subprocess.run")
    @pytest.mark.anyio
    async def test_irrelevant_event(
        self, mock_run: MagicMock, make_request: RequestFactory
    ) -> None:
        payload = {
            "iss": "https://idp.example.com/",
            "iat": 1600000000,
            "jti": "jti123456",
            "events": {"https://schemas.openid.net/secevent/risc/event-type/account-enabled": {}},
        }
        response = await receive_ssf_event(make_request(payload, f"Bearer {_TEST_BEARER_TOKEN}"))
        assert response["status"] == "ignored"
        mock_run.assert_not_called()

    @pytest.mark.anyio
    async def test_invalid_json_bytes(self, make_request: RequestFactory) -> None:
        with pytest.raises(HTTPException, match="Invalid SET payload"):
            await receive_ssf_event(make_request(b"{not-json!!!", f"Bearer {_TEST_BEARER_TOKEN}"))

    @patch("uon.auth.ssf_receiver.core.parse_ssf_event")
    @pytest.mark.anyio
    async def test_explicit_value_error(
        self, mock_parse: MagicMock, make_request: RequestFactory
    ) -> None:
        mock_parse.side_effect = ValueError("Simulated Bad JSON")
        with pytest.raises(HTTPException, match="Invalid SET payload"):
            await receive_ssf_event(make_request(b"{}", f"Bearer {_TEST_BEARER_TOKEN}"))

    @patch("uon.auth.ssf_receiver.core.parse_ssf_event")
    @pytest.mark.anyio
    async def test_explicit_internal_error(
        self, mock_parse: MagicMock, make_request: RequestFactory
    ) -> None:
        mock_parse.side_effect = Exception("Simulated Core Panic")
        with pytest.raises(HTTPException, match="Internal server error"):
            await receive_ssf_event(make_request(b"{}", f"Bearer {_TEST_BEARER_TOKEN}"))

    @pytest.mark.anyio
    async def test_spam_payload_graceful_drop(self, make_request: RequestFactory) -> None:
        response = await receive_ssf_event(
            make_request({"invalid": "payload"}, f"Bearer {_TEST_BEARER_TOKEN}")
        )
        assert response["status"] == "ignored"

    @patch("uon.auth.ssf_receiver.subprocess.run")
    @pytest.mark.anyio
    async def test_kill_sessions_exception(
        self, mock_run: MagicMock, make_request: RequestFactory
    ) -> None:
        mock_run.side_effect = Exception("System error")
        payload = {
            "iss": "https://idp.example.com/",
            "iat": 1600000000,
            "jti": "jti123456",
            "events": {
                RISC_ACCOUNT_DISABLED: {"subject": {"format": "email", "email": "user@example.com"}}
            },
        }
        response = await receive_ssf_event(make_request(payload, f"Bearer {_TEST_BEARER_TOKEN}"))
        assert response["status"] == "accepted"
