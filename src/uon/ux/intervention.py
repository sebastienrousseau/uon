# Copyright (c) 2026 Sebastien Rousseau
# Licensed under the MIT License.

"""UX Orchestrator for handling CAEP Anomalies."""

from __future__ import annotations

import logging
import click
from uon.core import freeze_execution, resume_execution
from uon.auth.fido_local import prompt_fido2_step_up

logger = logging.getLogger(__name__)

def handle_caep_anomaly(pid: int, anomaly_details: str) -> bool:
    """Intervenes upon a CAEP anomaly, freezing the process and demanding step-up auth.
    
    Args:
        pid: The process ID of the active local or remote execution hook.
        anomaly_details: Contextual string detailing the perceived threat.
        
    Returns:
        True if the user successfully signs the step-up challenge, False otherwise.
    """
    try:
        # 1. Swiftly freeze the execution via Rust core to mitigate damage
        freeze_execution(pid)
    except Exception as e:
        logger.error(f"Failed to freeze ephemeral execution: {e}")
        return False

    # 2. Dim terminal and prompt user (UX Phase)
    click.secho(f"\n[!] CAEP ANOMALY DETECTED: {anomaly_details}", fg="red", bold=True)
    click.secho("[!] Execution paused. Step-Up Hardware Authentication Required.", fg="yellow")
    
    try:
        # Prompt the hardware key
        assertion = prompt_fido2_step_up(reason=anomaly_details)
        if assertion:
            click.secho("[✓] Identity verified. Resuming execution.", fg="green")
            resume_execution(pid)
            return True
    except Exception:
        click.secho("[✗] Step-Up Authentication Failed. Session terminated.", fg="red", bold=True)
        
    return False
