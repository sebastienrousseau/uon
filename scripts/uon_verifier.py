#!/usr/bin/env python3
# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""uon Target Verifier.

Intercepts SSH commands via ForceCommand, validates the FIDO2 WebAuthn
signature against locally stored COSE public keys, and executes the
payload only if verification succeeds.
"""

import base64
import hashlib
import json
import os
import shlex
import sqlite3
import sys
import time
from contextlib import suppress
from typing import Any

from fido2 import cbor
from fido2.cose import CoseKey
from fido2.webauthn import AuthenticatorData, CollectedClientData

# Path to the stored public keys on the target machine
AUTHORIZED_KEYS_FILE = os.path.expanduser("~/.config/uon/authorized_passkeys.json")
USED_SESSIONS_FILE = os.path.expanduser("~/.config/uon/used_sessions.json")
UON_RP_ID = b"uon.local"
SESSION_TTL_SECONDS = 300  # 5 minutes — envelope lifetime
_AUTHORIZED_KEYS_CACHE: tuple[int | None, list[Any]] | None = None


def _file_mtime_ns(path: str) -> int | None:
    """Return the file mtime in nanoseconds, or ``None`` when unavailable."""
    try:
        return os.stat(path).st_mtime_ns
    except OSError:
        return None


def _connect_nonce_cache() -> sqlite3.Connection:
    """Open the replay-protection cache and ensure the schema exists."""
    config_dir = os.path.dirname(USED_SESSIONS_FILE)
    os.makedirs(config_dir, mode=0o700, exist_ok=True)
    conn = sqlite3.connect(USED_SESSIONS_FILE)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS used_sessions (
            session_id TEXT PRIMARY KEY,
            used_at REAL NOT NULL
        )
        """
    )
    with suppress(OSError):
        os.chmod(USED_SESSIONS_FILE, 0o600)
    return conn


def _b64url_decode(value: str) -> bytes:
    """Decode URL-safe base64 strings emitted by the Rust core."""
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded)


def _load_nonce_cache() -> dict[str, float]:
    """Load the used session nonce cache, purging entries older than 5 minutes."""
    now = time.time()
    try:
        with _connect_nonce_cache() as conn:
            conn.execute(
                "DELETE FROM used_sessions WHERE used_at < ?",
                (now - SESSION_TTL_SECONDS,),
            )
            rows = conn.execute("SELECT session_id, used_at FROM used_sessions").fetchall()
    except sqlite3.DatabaseError:
        return {}
    return {str(session_id): float(used_at) for session_id, used_at in rows}


def _save_nonce_cache(cache: dict[str, float]) -> None:
    """Persist the nonce cache with restrictive permissions."""
    try:
        with _connect_nonce_cache() as conn:
            conn.execute("DELETE FROM used_sessions")
            conn.executemany(
                "INSERT OR REPLACE INTO used_sessions(session_id, used_at) VALUES(?, ?)",
                cache.items(),
            )
    except sqlite3.DatabaseError:
        pass


def _check_replay(session_id: str) -> None:
    """Reject replayed session IDs and record the current one."""
    now = time.time()
    try:
        with _connect_nonce_cache() as conn:
            conn.execute(
                "DELETE FROM used_sessions WHERE used_at < ?",
                (now - SESSION_TTL_SECONDS,),
            )
            existing = conn.execute(
                "SELECT 1 FROM used_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if existing is not None:
                print(
                    "UON Verifier Error: Replay detected — session already used.",
                    file=sys.stderr,
                )
                sys.exit(1)
            conn.execute(
                "INSERT INTO used_sessions(session_id, used_at) VALUES(?, ?)",
                (session_id, now),
            )
    except sqlite3.DatabaseError as exc:
        print(f"UON Verifier Error: Replay cache unavailable - {exc}", file=sys.stderr)
        sys.exit(1)


def load_authorized_keys() -> list[Any]:
    """Load and cache the allowed FIDO2 COSE public keys for this user."""
    global _AUTHORIZED_KEYS_CACHE

    if not os.path.exists(AUTHORIZED_KEYS_FILE):
        print("UON Verifier Error: No authorized passkeys found.", file=sys.stderr)
        sys.exit(1)

    mtime_ns = _file_mtime_ns(AUTHORIZED_KEYS_FILE)
    if _AUTHORIZED_KEYS_CACHE is not None and _AUTHORIZED_KEYS_CACHE[0] == mtime_ns:
        return _AUTHORIZED_KEYS_CACHE[1]

    with open(AUTHORIZED_KEYS_FILE, encoding="utf-8") as f:
        key_records: list[dict[str, Any]] = json.load(f)

    parsed_keys = []
    for key_record in key_records:
        try:
            cbor_bytes = bytes.fromhex(key_record["cose_key_hex"])
            parsed_keys.append(CoseKey.parse(cbor.decode(cbor_bytes)))
        except (KeyError, TypeError, ValueError):
            continue

    _AUTHORIZED_KEYS_CACHE = (mtime_ns, parsed_keys)
    return parsed_keys


def verify_and_execute() -> None:
    """Parse the ``__UON_EXEC__`` envelope, verify the signature, and execute."""
    # 1. Intercept the SSH Command
    original_command = os.environ.get("SSH_ORIGINAL_COMMAND")
    if not original_command or not original_command.startswith("__UON_EXEC__ "):
        print("UON Verifier Error: Missing or invalid UON envelope.", file=sys.stderr)
        sys.exit(1)

    # 2. Extract and Decode Payload
    try:
        encoded_payload = original_command.split(" ", 1)[1]

        # Phase 5 PQC Decapsulation (Hybrid wrapper)
        from uon.transport.pqc import PQCHybridWrapper

        pqc = PQCHybridWrapper()
        decoded_payload = pqc.decapsulate_envelope(encoded_payload)

        envelope = json.loads(decoded_payload)
        payload = envelope
        session_id = payload.get("session_id", "")
        command = payload["command"]
        if isinstance(command, list):
            command = shlex.join(str(part) for part in command)
        assertion = payload["assertion"]
    except Exception as e:
        print(f"UON Verifier Error: Malformed envelope - {e}", file=sys.stderr)
        sys.exit(1)

    # 2b. Replay Protection
    if not session_id:
        print("UON Verifier Error: Missing session_id in envelope.", file=sys.stderr)
        sys.exit(1)
    _check_replay(session_id)

    client_data_bytes = _b64url_decode(assertion["client_data"])
    auth_data_bytes = _b64url_decode(assertion["auth_data"])
    signature = _b64url_decode(assertion["signature"])

    _client_data = CollectedClientData(client_data_bytes)
    auth_data = AuthenticatorData(auth_data_bytes)

    # 4. Cryptographic Verification
    # A) Verify RP ID Hash (Ensures the signature was meant for 'uon.local')
    expected_rp_id_hash = hashlib.sha256(UON_RP_ID).digest()
    if auth_data.rp_id_hash != expected_rp_id_hash:
        print(
            "UON Verifier Error: RP ID Hash mismatch. Possible replay attack.",
            file=sys.stderr,
        )
        sys.exit(1)

    # B) Verify User Presence / User Verification flags
    if not auth_data.is_user_present:
        print(
            "UON Verifier Error: Physical touch was not detected in signature.",
            file=sys.stderr,
        )
        sys.exit(1)

    # C) Reconstruct Signature Base: authenticatorData + SHA256(clientDataJSON)
    client_data_hash = hashlib.sha256(client_data_bytes).digest()
    signature_base = auth_data_bytes + client_data_hash

    # D) Validate Signature against authorized keys
    is_verified = False

    for public_key in load_authorized_keys():
        try:
            public_key.verify(signature_base, signature)
            is_verified = True
            break
        except Exception:  # noqa: S112 — iterate through all keys before rejecting
            continue

    if not is_verified:
        print(
            "UON Verifier Error: Cryptographic signature verification failed.",
            file=sys.stderr,
        )
        sys.exit(1)

    # 5. Execution — Zero Standing Privilege (ZSP) Dynamic Profiling Natively in Rust
    # Instead of exposing process spawning vulnerabilities via Python's subprocess,
    # we dispatch the workload to the core C-extension runtime.
    # The Rust runtime orchestrates the Just-In-Time ephemeral group allocation,
    # command execution, process tracking, OS-conditional kernel bounds (eBPF/EndpointSecurity)
    # and teardown without Python GIL contention.
    from uon import core  # type: ignore[import-untyped]

    try:
        # spawn_zsp_process: broker request -> least-privilege exec -> streamed result
        exit_code = core.spawn_zsp_process(command)
        sys.exit(exit_code)
    except Exception as e:
        print(f"UON Verifier Error: ZSP Extractor exception - {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    verify_and_execute()
