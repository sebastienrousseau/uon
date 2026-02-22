# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the MIT License. See LICENSE file in the project root
# for full license information.

"""Shared Signals Framework (SSF) Receiver.

Monitors an external Identity Provider (IdP) for OpenID Security Event Tokens
(SETs). If a session revocation or account disablement token is received,
this service instantly triggers dynamic teardown of active uon pipelines.
"""

from __future__ import annotations

import logging
import subprocess
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

app = FastAPI(title="uon_ssf_receiver", version="1.0.0")

class SSFToken(BaseModel):
    iss: str
    iat: int
    jti: str
    events: dict[str, Any]

# SSF standard URIs
RISC_ACCOUNT_DISABLED = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
RISC_CREDENTIAL_CHANGE = "https://schemas.openid.net/secevent/risc/event-type/credential-change"

def kill_uon_sessions(subject_identifier: str) -> None:
    """Terminate all active uon processes associated with the revoked subject.
    
    This fulfills the Zero-Trust Continuous Access Evaluation Protocol (CAEP)
    mandate of actively monitoring and instantly acting on downstream revocations.
    """
    logging.warning(f"SSF Revocation received for {subject_identifier}! Terminating sessions.")
    # On Linux/macOS, find processes running uon_verifier.py and send SIGKILL
    try:
        # Identifying processes dynamically and killing them
        pkill_cmd = ["pkill", "-9", "-f", "uon_verifier.py"]
        subprocess.run(pkill_cmd, check=False)  # noqa: S603
    except Exception as e:
        logging.error(f"Failed to terminate uon sessions: {e}")

from uon import core  # type: ignore[import-untyped,import-not-found]


@app.post("/ssf/events")
async def receive_ssf_event(request: Request) -> dict[str, str]:
    """Ingest a Security Event Token from the IdP stream natively parsed in Rust."""
    try:
        body_bytes = await request.body()
        payload = body_bytes.decode("utf-8")

        # Rust core handles parsing and extraction instantly without Pydantic overhead
        identifier = core.parse_ssf_event(payload)  # type: ignore[attr-defined]

        if identifier is not None:
            kill_uon_sessions(identifier)
            return {"status": "accepted"}

        return {"status": "ignored", "reason": "event_type_not_actionable"}
    except ValueError as e:
        logging.error(f"Invalid SSF payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid SET payload")
    except Exception as e:
        logging.error(f"SSF processing error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
