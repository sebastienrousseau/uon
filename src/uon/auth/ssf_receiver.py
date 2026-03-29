# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Shared Signals Framework (SSF) Receiver.

Monitors an external Identity Provider (IdP) for OpenID Security Event Tokens
(SETs). If a session revocation or account disablement token is received,
this service instantly triggers dynamic teardown of active uon pipelines.

Authentication:
    The endpoint requires a shared secret configured via the
    ``UON_SSF_SHARED_SECRET`` environment variable. Incoming requests must
    present the secret as a ``Bearer`` token in the ``Authorization`` header.
    Requests without a valid token are rejected with HTTP 401.
"""

from __future__ import annotations

import hmac
import logging
import os
import subprocess
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

app = FastAPI(title="uon_ssf_receiver", version="1.0.0")

# The shared secret MUST be set via environment variable in production.
_SSF_SHARED_SECRET = os.environ.get("UON_SSF_SHARED_SECRET", "")


class SSFToken(BaseModel):
    iss: str
    iat: int
    jti: str
    events: dict[str, Any]


# SSF standard URI (credential-change is handled in Rust core only)
RISC_ACCOUNT_DISABLED = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"


def _verify_bearer_token(request: Request) -> None:
    """Validate the Authorization header against the configured shared secret.

    Raises:
        HTTPException(401): If no secret is configured, the header is
            missing, or the token does not match.
    """
    if not _SSF_SHARED_SECRET:
        raise HTTPException(
            status_code=401,
            detail="SSF receiver not configured: UON_SSF_SHARED_SECRET not set",
        )
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = auth_header[len("Bearer "):]
    if not hmac.compare_digest(token, _SSF_SHARED_SECRET):
        raise HTTPException(status_code=401, detail="Invalid Bearer token")


def kill_uon_sessions(subject_identifier: str) -> None:
    """Terminate all active uon processes associated with the revoked subject.

    This fulfills the Zero-Trust Continuous Access Evaluation Protocol (CAEP)
    mandate of actively monitoring and instantly acting on downstream revocations.
    """
    logging.warning("SSF Revocation received for %s! Terminating sessions.", subject_identifier)
    try:
        pkill_cmd = ["pkill", "-9", "-f", "uon_verifier.py"]
        subprocess.run(pkill_cmd, check=False)  # noqa: S603
    except Exception as e:
        logging.error("Failed to terminate uon sessions: %s", e)


from uon import core  # type: ignore[import-untyped,import-not-found]


@app.post("/ssf/events")
async def receive_ssf_event(request: Request) -> dict[str, str]:
    """Ingest a Security Event Token from the IdP stream natively parsed in Rust.

    Requires a valid ``Authorization: Bearer <secret>`` header matching the
    ``UON_SSF_SHARED_SECRET`` environment variable.
    """
    _verify_bearer_token(request)

    try:
        body_bytes = await request.body()
        payload = body_bytes.decode("utf-8")

        identifier = core.parse_ssf_event(payload)  # type: ignore[attr-defined]

        if identifier is not None:
            kill_uon_sessions(identifier)
            return {"status": "accepted"}

        return {"status": "ignored", "reason": "event_type_not_actionable"}
    except ValueError as e:
        logging.error("Invalid SSF payload: %s", e)
        raise HTTPException(status_code=400, detail="Invalid SET payload")
    except Exception as e:
        logging.error("SSF processing error: %s", e)
        raise HTTPException(status_code=500, detail="Internal server error")
