"""Authenticated mDNS (AmDNS) for secure local network discovery.

Standard mDNS broadcasts are trivially spoofable. This module implements
discovery seeded by an out-of-band Bluetooth Low Energy (BLE) secret,
ensuring that `uon` target nodes are cryptographically authenticated
before the SSH transport and FIDO2 assertions proceed.
"""

from __future__ import annotations

from uon import core  # type: ignore[import-untyped,import-not-found]


def compute_amdns_hmac(ble_secret: bytes, target_alias: str, timestamp: int) -> str:
    """Compute the expected Authenticated mDNS HMAC for a discovery beacon natively via Rust.

    Args:
        ble_secret:   32-byte shared secret negotiated via BLE proximity.
        target_alias: The `uon` alias being discovered.
        timestamp:    UNIX epoch timestamp modulo 30 seconds (TOTP style).

    Returns:
        A hex-encoded HMAC string representing the current cryptographic
        expectation for the network target.
    """
    return core.compute_amdns_hmac(ble_secret, target_alias, timestamp)  # type: ignore[no-any-return,unused-ignore]


def verify_discovery_beacon(
    ble_secret: bytes, target_alias: str, reported_hmac: str, time_tolerance_seconds: int = 30
) -> bool:
    """Validate an intercepted AmDNS beacon via the high-throughput Rust parser natively evaluating clock drifts.

    Args:
        ble_secret:   The 32-byte secret negotiated via the active BLE connection.
        target_alias: The alias expected from the beacon.
        reported_hmac: The HMAC string captured off the local network broadcast.
        time_tolerance_seconds: Accepted clock drift out-of-bounds limit.

    Returns:
        ``True`` if the beacon mathematically proves ownership of the BLE
        secret; ``False`` otherwise.
    """
    return core.verify_discovery_beacon(  # type: ignore[no-any-return,unused-ignore]
        ble_secret, target_alias, reported_hmac, time_tolerance_seconds
    )
