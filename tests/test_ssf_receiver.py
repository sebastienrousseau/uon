"""Tests for the Shared Signals Framework (SSF) Receiver."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from uon.auth.ssf_receiver import app, RISC_ACCOUNT_DISABLED


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


class TestSSFReceiver:
    @patch("uon.auth.ssf_receiver.subprocess.run")
    def test_account_disabled_event(self, mock_run: MagicMock, client: TestClient) -> None:
        payload = {
            "iss": "https://idp.example.com/",
            "iat": 1600000000,
            "jti": "jti123456",
            "events": {
                RISC_ACCOUNT_DISABLED: {
                    "subject": {
                        "format": "email",
                        "email": "admin@example.com"
                    }
                }
            }
        }
        response = client.post("/ssf/events", json=payload)
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
            "events": {
                "https://schemas.openid.net/secevent/risc/event-type/account-enabled": {}
            }
        }
        response = client.post("/ssf/events", json=payload)
        assert response.status_code == 200
        assert response.json()["status"] == "ignored"
        mock_run.assert_not_called()

    def test_invalid_payload(self, client: TestClient) -> None:
        response = client.post("/ssf/events", json={"invalid": "payload"})
        assert response.status_code == 400

    @patch("uon.auth.ssf_receiver.subprocess.run")
    def test_kill_sessions_exception(self, mock_run: MagicMock, client: TestClient) -> None:
        mock_run.side_effect = Exception("System error")
        payload = {
            "iss": "https://idp.example.com/",
            "iat": 1600000000,
            "jti": "jti123456",
            "events": {
                RISC_ACCOUNT_DISABLED: {
                    "subject": {
                        "format": "email",
                        "email": "user@example.com"
                    }
                }
            }
        }
        # The exception is caught and logged, so the endpoint should still return 200
        response = client.post("/ssf/events", json=payload)
        assert response.status_code == 200
        assert response.json()["status"] == "accepted"
