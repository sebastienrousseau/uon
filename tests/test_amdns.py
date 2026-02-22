"""Tests for Authenticated mDNS (AmDNS) discovery mechanics."""

from __future__ import annotations

import time
from unittest.mock import patch

from uon.transport.amdns import compute_amdns_hmac, verify_discovery_beacon


class TestAmDNS:
    def test_compute_hmac(self) -> None:
        ble_secret = b"12345678901234567890123456789012"
        alias = "my-target"
        timestamp = 1000
        
        mac = compute_amdns_hmac(ble_secret, alias, timestamp)
        assert len(mac) == 64  # SHA-256 hex digest length
        
        # Reproducible determinism
        assert mac == compute_amdns_hmac(ble_secret, alias, timestamp)

    @patch("uon.transport.amdns.time.time")
    def test_verify_beacon_valid(self, mock_time) -> None:
        mock_time.return_value = 3000.0  # Window = 3000 // 30 = 100
        ble_secret = b"12345678901234567890123456789012"
        alias = "prod-node"
        
        # Valid window
        expected_hmac = compute_amdns_hmac(ble_secret, alias, 100)
        assert verify_discovery_beacon(ble_secret, alias, expected_hmac) is True

    @patch("uon.transport.amdns.time.time")
    def test_verify_beacon_drift(self, mock_time) -> None:
        mock_time.return_value = 3005.0  # Current window is 100
        ble_secret = b"secret_key_32_bytes_long_exactly"
        alias = "dev-db"
        
        # Simulate beacon computed from the previous window (99) due to clock drift
        old_hmac = compute_amdns_hmac(ble_secret, alias, 99)
        assert verify_discovery_beacon(ble_secret, alias, old_hmac) is True

    @patch("uon.transport.amdns.time.time")
    def test_verify_beacon_invalid(self, mock_time) -> None:
        mock_time.return_value = 5000.0
        ble_secret = b"12345678901234567890123456789012"
        alias = "staging"
        
        # Completely random HMAC
        assert verify_discovery_beacon(ble_secret, alias, "deadbeef" * 8) is False
        
        # Wrong alias
        wrong_hmac = compute_amdns_hmac(ble_secret, "wrong-alias", 5000 // 30)
        assert verify_discovery_beacon(ble_secret, alias, wrong_hmac) is False
