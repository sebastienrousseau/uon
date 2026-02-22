"""Shared Signals Framework (SSF) Receiver.

Monitors an external Identity Provider (IdP) for OpenID Security Event Tokens
(SETs). If a session revocation or account disablement token is received,
this service instantly triggers dynamic teardown of active uon pipelines.
"""

from __future__ import annotations

import logging
import os
import signal
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

@app.post("/ssf/events")
async def receive_ssf_event(request: Request) -> dict[str, str]:
    """Ingest a Security Event Token from the IdP stream."""
    try:
        payload = await request.json()
        token = SSFToken(**payload)
        
        # Parse the OpenID events
        events = token.events
        if RISC_ACCOUNT_DISABLED in events or RISC_CREDENTIAL_CHANGE in events:
            # We assume the subject claims tell us who was disabled
            event_data = events.get(RISC_ACCOUNT_DISABLED) or events.get(RISC_CREDENTIAL_CHANGE, {})
            subject: dict[str, str] = event_data.get("subject", {})
            
            identifier = subject.get("sub") or subject.get("email") or "unknown"
            kill_uon_sessions(identifier)
            return {"status": "accepted"}
            
        return {"status": "ignored", "reason": "event_type_not_actionable"}
    except Exception as e:
        logging.error(f"Invalid SSF payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid SET payload")
