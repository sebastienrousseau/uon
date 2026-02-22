# Copyright (c) 2026 Sebastien Rousseau
# Licensed under the MIT License.

"""Pre-execution static analysis for explainable blast radius via Textual UI.

Employs the Model-Update-View event loop to interactively halt the terminal
and confirm the user accepts the semantic risk profile of the pending command.
"""

from __future__ import annotations

import re

from textual.app import App, ComposeResult
from textual.containers import Grid, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Static

# Combine patterns into single pre-compiled OR strings to flatten cyclomatic branch evaluation
_HIGH_IMPACT_PATTERN = re.compile(
    r"(rm\s+-r?[fF])|(chmod\s+-R\s+777)|(chown\s+-R)|(mkfs.*)|(dd\s+if=.*of=/dev/)"
)

_NETWORK_PATTERN = re.compile(
    r"(curl\s+.*\|.*sh)|(wget\s+.*\|.*sh)|(nc\s+-e)"
)


def evaluate_blast_radius(command: str) -> str:
    """Evaluates the command string and calculates the expected blast radius."""
    impacts: list[str] = []

    if _HIGH_IMPACT_PATTERN.search(command):
        impacts.append("HIGH RISK: Destructive file mapping or permission alterations detected.")

    if _NETWORK_PATTERN.search(command):
        impacts.append("HIGH RISK: Arbitrary network execution piping detected.")

    if "sudo" in command.lower():
        impacts.append("MEDIUM RISK: Contains nested escalation directives.")

    if not impacts:
        return "LOW RISK: Standard functional execution profile."
        
    return " | ".join(impacts)


class BlastRadiusScreen(ModalScreen[bool]):
    """An overlay screen demanding user confirmation before High-Risk executions."""

    CSS = """
    BlastRadiusScreen {
        align: center middle;
        background: $background 70%;
    }
    #dialog {
        grid-size: 1 3;
        grid-rows: auto 1fr auto;
        padding: 1 2;
        width: 80;
        height: 20;
        border: thick $primary;
        background: $surface;
    }
    #question {
        content-align: center middle;
        text-style: bold;
        margin-bottom: 2;
    }
    #warning-box {
        padding: 1;
        border: dashed $warning;
        color: $text;
        content-align: center middle;
    }
    .high-risk {
        border: dashed $error !important;
        color: $error !important;
        text-style: bold;
    }
    #button-tray {
        content-align: center middle;
        height: auto;
        margin-top: 2;
        align: center middle;
    }
    Button {
        margin: 0 2;
    }
    """

    def __init__(self, command: str, impact_warning: str) -> None:
        super().__init__()
        self.command = command
        self.impact_warning = impact_warning

    def compose(self) -> ComposeResult:
        """The View: declarative component structure."""
        with Grid(id="dialog"):
            yield Label(f"Proceed with execution: '{self.command}'?", id="question")

            box = Static(self.impact_warning, id="warning-box")
            if "HIGH RISK" in self.impact_warning or "WARN" in self.impact_warning:
                box.add_class("high-risk")
            yield box

            with Horizontal(id="button-tray"):
                yield Button("Proceed (y)", variant="error", id="btn-yes")
                yield Button("Cancel (N)", variant="success", id="btn-no")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """The Update Loop: Maps interaction messages to the Modal dismissal."""
        if event.button.id == "btn-yes":
            self.dismiss(True)
        else:
            self.dismiss(False)


class BlastRadiusApp(App[bool]):
    """Single-run application capturing the user state."""

    def __init__(self, command: str, warning: str):
        super().__init__()
        self.command = command
        self.warning = warning

    def on_mount(self) -> None:
        def capture_decision(decision: bool | None) -> None:
            # Fallback to False if modal abruptly dismissed
            self.exit(decision if decision is not None else False)

        self.push_screen(BlastRadiusScreen(self.command, self.warning), capture_decision)


def display_blast_radius(command: str) -> bool:
    """Interactively renders the blast radius and returns caller commitment.

    If True, the caller envelopes the payload and transmits it over SSH.
    If False, the execution is entirely scrubbed before wrapping.
    """
    radius = evaluate_blast_radius(command)

    # Bypass manual confirmation loops for standard low-risk functional executions
    if "LOW RISK" in radius:
        return True

    app = BlastRadiusApp(command, radius)
    return app.run() or False
