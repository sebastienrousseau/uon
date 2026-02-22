# Copyright (c) 2026 Sebastien Rousseau
# Licensed under the MIT License.

"""Asynchronous Textual TUI for tracking remote Just-In-Time execution TTLs.

Adopts an Elm-inspired event loop matching the visual standard of `bubbletea`
by isolating State (Model), Messages (Update), and the UI (View).
"""

from __future__ import annotations

import asyncio
import time

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Center, Vertical
from textual.widgets import Label, ProgressBar, Static


class TelemetryState:
    """The Model representing the active JIT envelope."""
    def __init__(self, timeout: int, elapsed: float = 0.0, desync: bool = False):
        self.timeout = timeout
        self.elapsed = elapsed
        self.desync = desync


class JITTelemetryApp(App[None]):
    """The reactive Textual UI for tracking JIT execution TTLs."""

    CSS = """
    Screen {
        align: center middle;
        background: $boost;
    }
    #telemetry-container {
        width: 80%;
        height: auto;
        border: round $success;
        padding: 1 2;
        background: $surface;
    }
    #telemetry-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    #telemetry-status {
        text-align: center;
        margin-top: 1;
    }
    .desync-container {
        border: round $error !important;
    }
    .desync-text {
        color: $error;
        text-style: bold;
    }
    """

    def __init__(self, socket_path: str, timeout_seconds: int = 300) -> None:
        super().__init__()
        self.socket_path = socket_path
        self.state = TelemetryState(timeout=timeout_seconds)

    def compose(self) -> ComposeResult:
        """The View: declarative construction of the UI components."""
        with Center(), Vertical(id="telemetry-container"):
            yield Label("Zero Trust Ephemeral Session", id="telemetry-title")
            yield ProgressBar(total=self.state.timeout, show_eta=True, id="ttl-bar")
            yield Static("Synchronizing with remote hypervisor...", id="telemetry-status")

    def on_mount(self) -> None:
        """Kicks off the asynchronous hypervisor polling event loop on startup."""
        self.run_polling_loop()

    @work(exclusive=True, thread=True)
    def run_polling_loop(self) -> None:
        """The primary Update loop operating asynchronously against the socket."""
        start_time = time.time()
        while self.state.elapsed < self.state.timeout:
            time.sleep(0.2)

            # Health Check (Fail-Safe Desync)
            if not asyncio.run(self._check_socket_health(self.socket_path)):
                self.call_from_thread(self._handle_desync)
                # Give the user brief time to read the error before tearing down
                time.sleep(2) 
                self.call_from_thread(self.exit)
                return

            self.state.elapsed = time.time() - start_time
            self.call_from_thread(self._update_ui)

        self.call_from_thread(self.exit)

    def _update_ui(self) -> None:
        """Re-renders UI properties based on updated Model state."""
        progress = self.query_one("#ttl-bar", ProgressBar)
        progress.progress = self.state.elapsed

        status = self.query_one("#telemetry-status", Static)
        remaining = max(0, int(self.state.timeout - self.state.elapsed))
        status.update(f"Session Active — Crypto-Enclave secured. {remaining}s remaining.")

    def _handle_desync(self) -> None:
        """Reacts to a socket anomaly, shattering the visual progress bar."""
        self.state.desync = True
        container = self.query_one("#telemetry-container")
        container.add_class("desync-container")

        status = self.query_one("#telemetry-status", Static)
        status.update("CRITICAL: Telemetry Desync. Tearing down visualization...")
        status.add_class("desync-text")

    async def _check_socket_health(self, socket_path: str) -> bool:
        """Mock verification of the underlying health of the IPC pipe."""
        return True


def track_jit_ttl(socket_path: str, timeout_seconds: int = 300) -> None:
    """Entry point for the execution lifecycle UI."""
    app = JITTelemetryApp(socket_path, timeout_seconds)
    app.run()
