# Copyright (c) 2026 Sebastien Rousseau
# Licensed under the MIT License.

"""UX Orchestrator for handling CAEP Anomalies via Textual Overlays.

Uses an Elm-inspired event loop to slide a CAEP Alert Modal over the
active terminal, demanding FIDO2 satisfaction to thaw the frozen PID.
"""

from __future__ import annotations

import logging

from textual.app import App, ComposeResult
from textual.containers import Center, Grid
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static

from uon.auth.fido_local import authenticate
from uon.core import freeze_execution, resume_execution

logger = logging.getLogger(__name__)


class CAEPInterventionScreen(ModalScreen[bool]):
    """An un-dismissible overlay demanding hardware signature clearance."""

    CSS = """
    CAEPInterventionScreen {
        align: center middle;
        background: $error 40%;
    }
    #caep-dialog {
        grid-size: 1 3;
        grid-rows: auto 1fr auto;
        padding: 1 2;
        width: 80;
        height: 20;
        border: thick $error;
        background: $surface;
    }
    #caep-title {
        content-align: center middle;
        text-style: bold;
        color: $error;
        margin-bottom: 2;
    }
    #caep-info {
        padding: 1;
        border: dashed $warning;
        color: $text;
        content-align: center middle;
    }
    #caep-btn {
        margin-top: 2;
        width: 100%;
        content-align: center middle;
    }
    """

    def __init__(self, anomaly_details: str) -> None:
        super().__init__()
        self.anomaly_details = anomaly_details

    def compose(self) -> ComposeResult:
        """The View: declarative construction of the security modal."""
        with Grid(id="caep-dialog"):
            yield Label("CAEP ANOMALY DETECTED: Execution Frozen", id="caep-title")

            # The Model reflects the specific string violation that triggered the hook
            yield Static(self.anomaly_details, id="caep-info")

            with Center():
                yield Button("Acknowledge & Initiate Step-Up Auth", variant="error", id="caep-btn")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """The Update Loop: Fires the FIDO2 driver securely."""
        if event.button.id == "caep-btn":
            try:
                # Prompt the hardware key synchronously using the primary authenticate wrapper
                assertion = authenticate(challenge=b"CAEP_STEP_UP", credential_ids=[])
                if assertion:
                    self.dismiss(True)
                else:
                    self.dismiss(False)
            except Exception:
                self.dismiss(False)


class CAEPInterventionApp(App[bool]):
    """Single-run application managing the CAEP thaw state."""

    def __init__(self, anomaly: str):
        super().__init__()
        self.anomaly = anomaly

    def on_mount(self) -> None:
        def capture_auth(cleared: bool | None) -> None:
            self.exit(cleared if cleared is not None else False)

        self.push_screen(CAEPInterventionScreen(self.anomaly), capture_auth)


def handle_caep_anomaly(pid: int, anomaly_details: str) -> bool:
    """Intervenes upon a CAEP anomaly, freezing the process and demanding step-up auth.

    Args:
        pid: The process ID of the active local or remote execution hook.
        anomaly_details: Contextual string detailing perceived threat.

    Returns:
        True if the user successfully signs the step-up challenge, False otherwise.
    """
    try:
        # Swiftly freeze the execution via Rust core to mitigate damage
        freeze_execution(pid)
    except Exception as e:
        logger.error(f"Failed to freeze ephemeral execution: {e}")
        return False

    # Execute Bubble Tea/Elm UI Intervention
    app = CAEPInterventionApp(anomaly_details)
    cleared = app.run() or False

    if cleared:
        resume_execution(pid)
        return True

    # Process remains frozen or is assumed dead
    return False
