# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Tests for Authenticated mDNS (AmDNS) discovery mechanics."""

from __future__ import annotations

import time

from uon.transport.amdns import compute_amdns_hmac, verify_discovery_beacon


class TestAmDNS:
    def test_compute_hmac(self) -> None:
        ble_secret = b"12345678901234567890123456789012"
        alias = "my-target"
        timestamp = 1000

        mac = compute_amdns_hmac(ble_secret, alias, timestamp)
        assert len(mac) == 64  # SHA-256 hex digest length
        assert mac == compute_amdns_hmac(ble_secret, alias, timestamp)

    def test_verify_beacon_valid(self) -> None:
        ble_secret = b"12345678901234567890123456789012"
        alias = "prod-node"

        # compute_amdns_hmac divides the timestamp by 30 internally,
        # so we pass the raw current time (not pre-divided).
        now = int(time.time())
        expected_hmac = compute_amdns_hmac(ble_secret, alias, now)
        assert verify_discovery_beacon(ble_secret, alias, expected_hmac) is True

    def test_verify_beacon_drift(self) -> None:
        ble_secret = b"secret_key_32_bytes_long_exactly"
        alias = "dev-db"

        # Simulate beacon computed from the previous window due to clock drift
        now = int(time.time()) - 30
        old_hmac = compute_amdns_hmac(ble_secret, alias, now)
        assert verify_discovery_beacon(ble_secret, alias, old_hmac) is True

    def test_verify_beacon_invalid(self) -> None:
        ble_secret = b"12345678901234567890123456789012"
        alias = "staging"

        # Completely random HMAC
        assert verify_discovery_beacon(ble_secret, alias, "deadbeef" * 8) is False

        # Wrong alias
        wrong_window_hmac = compute_amdns_hmac(ble_secret, "wrong-alias", int(time.time()))
        assert verify_discovery_beacon(ble_secret, alias, wrong_window_hmac) is False
