# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Tests for the Shared Signals Framework (SSF) Receiver."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from uon.auth.ssf_receiver import RISC_ACCOUNT_DISABLED, app

_TEST_SECRET = "test-ssf-secret-token-42"
_AUTH_HEADER = {"Authorization": f"Bearer {_TEST_SECRET}"}


@pytest.fixture(autouse=True)
def _set_ssf_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure a test shared secret for all SSF tests."""
    monkeypatch.setattr("uon.auth.ssf_receiver._SSF_SHARED_SECRET", _TEST_SECRET)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


class TestSSFAuthentication:
    def test_missing_auth_header(self, client: TestClient) -> None:
        response = client.post("/ssf/events", json={"events": {}})
        assert response.status_code == 401
        assert "Missing Bearer" in response.json()["detail"]

    def test_wrong_token(self, client: TestClient) -> None:
        response = client.post(
            "/ssf/events",
            json={"events": {}},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert response.status_code == 401
        assert "Invalid Bearer" in response.json()["detail"]

    def test_no_secret_configured(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("uon.auth.ssf_receiver._SSF_SHARED_SECRET", "")
        response = client.post(
            "/ssf/events",
            json={"events": {}},
            headers=_AUTH_HEADER,
        )
        assert response.status_code == 401
        assert "not configured" in response.json()["detail"]


class TestSSFReceiver:
    @patch("uon.auth.ssf_receiver.subprocess.run")
    def test_account_disabled_event(self, mock_run: MagicMock, client: TestClient) -> None:
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
        response = client.post("/ssf/events", json=payload, headers=_AUTH_HEADER)
        assert response.status_code == 200
        assert response.json()["status"] == "accepted"

        # Verify pkill was called to terminate sessions
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "pkill" in args
        assert "uon_verifier.py" in args

    @patch("uon.auth.ssf_receiver.subprocess.run")
    def test_irrelevant_event(self, mock_run: MagicMock, client: TestClient) -> None:
        payload = {
            "iss": "https://idp.example.com/",
            "iat": 1600000000,
            "jti": "jti123456",
            "events": {"https://schemas.openid.net/secevent/risc/event-type/account-enabled": {}},
        }
        response = client.post("/ssf/events", json=payload, headers=_AUTH_HEADER)
        assert response.status_code == 200
        assert response.json()["status"] == "ignored"
        mock_run.assert_not_called()

    def test_invalid_json_bytes(self, client: TestClient) -> None:
        response = client.post("/ssf/events", content=b"{not-json!!!", headers=_AUTH_HEADER)
        assert response.status_code == 400

    @patch("uon.auth.ssf_receiver.core.parse_ssf_event")
    def test_explicit_value_error(self, mock_parse: MagicMock, client: TestClient) -> None:
        mock_parse.side_effect = ValueError("Simulated Bad JSON")
        response = client.post("/ssf/events", content=b"{}", headers=_AUTH_HEADER)
        assert response.status_code == 400

    @patch("uon.auth.ssf_receiver.core.parse_ssf_event")
    def test_explicit_internal_error(self, mock_parse: MagicMock, client: TestClient) -> None:
        mock_parse.side_effect = Exception("Simulated Core Panic")
        response = client.post("/ssf/events", content=b"{}", headers=_AUTH_HEADER)
        assert response.status_code == 500

    def test_spam_payload_graceful_drop(self, client: TestClient) -> None:
        response = client.post("/ssf/events", json={"invalid": "payload"}, headers=_AUTH_HEADER)
        assert response.status_code == 200
        assert response.json()["status"] == "ignored"

    @patch("uon.auth.ssf_receiver.subprocess.run")
    def test_kill_sessions_exception(self, mock_run: MagicMock, client: TestClient) -> None:
        mock_run.side_effect = Exception("System error")
        payload = {
            "iss": "https://idp.example.com/",
            "iat": 1600000000,
            "jti": "jti123456",
            "events": {
                RISC_ACCOUNT_DISABLED: {"subject": {"format": "email", "email": "user@example.com"}}
            },
        }
        response = client.post("/ssf/events", json=payload, headers=_AUTH_HEADER)
        assert response.status_code == 200
        assert response.json()["status"] == "accepted"
