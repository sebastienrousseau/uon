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
import sys
import time
from typing import Any

from fido2 import cbor
from fido2.cose import CoseKey
from fido2.webauthn import AuthenticatorData, CollectedClientData

# Path to the stored public keys on the target machine
AUTHORIZED_KEYS_FILE = os.path.expanduser("~/.config/uon/authorized_passkeys.json")
USED_SESSIONS_FILE = os.path.expanduser("~/.config/uon/used_sessions.json")
UON_RP_ID = b"uon.local"
SESSION_TTL_SECONDS = 300  # 5 minutes — envelope lifetime


def _load_nonce_cache() -> dict[str, float]:
    """Load the used session nonce cache, purging entries older than 5 minutes."""
    if not os.path.exists(USED_SESSIONS_FILE):
        return {}
    try:
        with open(USED_SESSIONS_FILE) as f:
            cache: dict[str, float] = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}
    now = time.time()
    return {sid: ts for sid, ts in cache.items() if now - ts < SESSION_TTL_SECONDS}


def _save_nonce_cache(cache: dict[str, float]) -> None:
    """Persist the nonce cache with restrictive permissions."""
    config_dir = os.path.dirname(USED_SESSIONS_FILE)
    os.makedirs(config_dir, mode=0o700, exist_ok=True)
    fd = os.open(USED_SESSIONS_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(cache, f)
    except Exception:  # noqa: S110 — best-effort persistence
        pass


def _check_replay(session_id: str) -> None:
    """Reject replayed session IDs and record the current one."""
    cache = _load_nonce_cache()
    if session_id in cache:
        print("UON Verifier Error: Replay detected — session already used.", file=sys.stderr)
        sys.exit(1)
    cache[session_id] = time.time()
    _save_nonce_cache(cache)


def load_authorized_keys() -> list[dict[str, Any]]:
    """Load the allowed FIDO2 COSE public keys for this user."""
    if not os.path.exists(AUTHORIZED_KEYS_FILE):
        print("UON Verifier Error: No authorized passkeys found.", file=sys.stderr)
        sys.exit(1)
    with open(AUTHORIZED_KEYS_FILE) as f:
        return json.load(f)


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
        assertion = payload["assertion"]
    except Exception as e:
        print(f"UON Verifier Error: Malformed envelope - {e}", file=sys.stderr)
        sys.exit(1)

    # 2b. Replay Protection
    if not session_id:
        print("UON Verifier Error: Missing session_id in envelope.", file=sys.stderr)
        sys.exit(1)
    _check_replay(session_id)

    # 3. Parse FIDO2 Assertion Data (URL-safe base64 without padding from Rust core)
    def _b64url_decode(s: str) -> bytes:
        padded = s + "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(padded)

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
    keys = load_authorized_keys()
    is_verified = False

    for key_record in keys:
        try:
            # Reconstruct the COSE Public Key from stored mapping.
            # fido2 >= 1.1.0: CoseKey.parse() expects a dict (Mapping), not raw bytes.
            # Decode CBOR first, then parse the resulting dict.
            cbor_bytes = bytes.fromhex(key_record["cose_key_hex"])
            public_key = CoseKey.parse(cbor.decode(cbor_bytes))
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
        # spawn_zsp_process: GroupAdd -> Sudo -> eBPF sandbox -> Wait -> GroupDel
        exit_code = core.spawn_zsp_process(command)
        sys.exit(exit_code)
    except Exception as e:
        print(f"UON Verifier Error: ZSP Extractor exception - {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    verify_and_execute()
