# Copyright (c) 2024 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Interactive TUI Onboarding Wizard for new uon environments.

This module leverages Textual to guide users through their first target
registration and FIDO2 passkey enrollment in a strictly controlled,
aesthetically pleasing terminal interface.

Command flow: ``uon init`` -> ``OnboardingWizard().run()``.
"""

from __future__ import annotations

import base64
import os

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Button, Footer, Header, Input, Static
from textual.validation import Length, Integer

from uon.auth.fido_local import NoPlatformAuthenticatorError
from uon.auth.fido_local import register as fido_register
from uon.utils.config import Credential, Target, TargetStore
from uon.utils.policy import PolicyStore


class HeroBanner(Static):
    """The UON branding banner for the onboarding wizard."""

    def compose(self) -> ComposeResult:
        yield Static(
            "\n         _   _  ___  _ __  \n"
            "        | | | |/ _ \\| '_ \\ \n"
            "        | |_| | (_) | | | |\n"
            "         \\__,_|\\___/|_| |_|\n"
            "                           \n"
            "  Zero-Trust Terminal Execution\n",
            id="hero-art",
        )


class ValidatedInputRow(Horizontal):
    """A row containing a label and an input field."""

    def __init__(self, label: str, placeholder: str, id: str, value: str = "", **kwargs) -> None:
        super().__init__(**kwargs)
        self.label_text = label
        self.placeholder = placeholder
        self.input_id = id
        self.default_value = value

    def compose(self) -> ComposeResult:
        yield Static(self.label_text, classes="label")
        input_widget = Input(placeholder=self.placeholder, id=self.input_id, value=self.default_value)
        
        # Add basic integer validation for ports
        if self.input_id == "input-port":
            input_widget.validators = [Integer(minimum=1, maximum=65535)]
            
        yield input_widget


class TargetDefinitionScreen(Container):
    """Screen 1: Gather alias, host, user, and port telemetry."""

    def compose(self) -> ComposeResult:
        yield Vertical(
            HeroBanner(),
            Static("Step 1 of 2: Define your Remote Target", classes="step-title"),
            Static(
                "Let's register the server you want to securely access.\n"
                "This maps your local uon client to the SSH daemon.",
                classes="step-desc"
            ),
            Container(
                ValidatedInputRow("Alias", "e.g., prod-db-01", "input-alias"),
                ValidatedInputRow("Host", "e.g., 192.168.1.50 or aws.com", "input-host"),
                ValidatedInputRow("User", "e.g., root", "input-user", value="root"),
                ValidatedInputRow("Port", "e.g., 22", "input-port", value="22"),
                id="form-container"
            ),
            Horizontal(
                Button("Cancel", variant="error", id="btn-cancel"),
                Button("Next: Enroll Passkey", variant="success", id="btn-next"),
                id="action-row"
            ),
            id="screen-container"
        )


class FidoEnrollmentScreen(Container):
    """Screen 2: Bridges into hardware attestation."""

    def compose(self) -> ComposeResult:
        yield Vertical(
            HeroBanner(),
            Static("Step 2 of 2: Hardware Enrollment", classes="step-title"),
            Static(
                "We are ready to mint a Zero-Trust FIDO2 passkey.\n"
                "When you click the button below, prepare to tap your authenticating hardware.",
                classes="step-desc"
            ),
            Container(
                Static("Status: Waiting for interaction...", id="fido-status"),
                id="fido-container"
            ),
            Horizontal(
                Button("Cancel", variant="error", id="btn-cancel"),
                Button("Mint Passkey [Tap Hardware]", variant="primary", id="btn-mint"),
                id="action-row"
            ),
            id="screen-container"
        )


class SuccessScreen(Container):
    """Screen 3: Summary and public-key payload deployment instructions."""

    def compose(self) -> ComposeResult:
        yield Vertical(
            HeroBanner(),
            Static("✓ Onboarding Complete", classes="step-title success-text"),
            Static(
                "Your credential was securely minted into the hardware Secure Enclave.\n"
                "The target configuration has been saved locally.\n\n"
                "To finalize deployment, you must drop the uon public key onto the remote host:",
                classes="step-desc"
            ),
            Container(
                Static("$ uon pubkey > payload.pub\n$ scp payload.pub user@host:~/\n$ [remote] cat payload.pub >> ~/.ssh/authorized_keys", id="code-snippet"),
                id="code-container"
            ),
            Horizontal(
                Button("Exit Wizard", variant="primary", id="btn-exit"),
                id="action-row"
            ),
            id="screen-container"
        )


class OnboardingWizard(App[None]):
    """The main Textual application orchestrating the TUI wizard."""

    CSS = """
    #screen-container { width: 100%; height: 100%; align: center middle; }
    Vertical { width: 70%; max-width: 800; align: center middle; }
    
    #hero-art { color: #DFFF00; text-align: center; text-style: bold; margin-bottom: 2; }
    
    .step-title { text-align: center; text-style: bold; margin-bottom: 1; }
    .success-text { color: #DFFF00; }
    .step-desc { text-align: center; color: ansi_bright_black; margin-bottom: 2; }
    
    #form-container { border: round #DFFF00; padding: 1 2; margin-bottom: 2; height: auto; }
    ValidatedInputRow { height: 3; margin-bottom: 1; align: left middle; }
    .label { width: 15; text-align: right; padding-right: 2; color: ansi_white; }
    Input { width: 40; }
    
    #action-row { align: right middle; height: 3; dock: bottom; margin-top: 1; }
    Button { margin-left: 2; }
    
    #fido-container { border: dashed ansi_bright_black; padding: 2 4; margin-bottom: 2; align: center middle; height: auto; }
    #fido-status { text-align: center; color: ansi_bright_yellow; }
    
    #code-container { border: solid ansi_bright_black; padding: 1 2; margin-bottom: 2; background: $surface; height: auto;}
    #code-snippet { color: ansi_bright_green; }
    """

    BINDINGS = [
        ("q", "quit", "Quit Wizard"),
        ("ctrl+c", "quit", "Quit Wizard"),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        # Ephemeral state to transfer across screens
        self.tmp_alias: str = ""
        self.tmp_host: str = ""
        self.tmp_user: str = "root"
        self.tmp_port: int = 22

    def compose(self) -> ComposeResult:
        """Mount the Header, Footer, and the initial form screen."""
        yield Header()
        yield Footer()
        yield TargetDefinitionScreen(id="screen-target")
        yield FidoEnrollmentScreen(id="screen-fido")
        yield SuccessScreen(id="screen-success")

    def on_mount(self) -> None:
        """Hide all screens except the first."""
        self.query_one("#screen-fido").display = False
        self.query_one("#screen-success").display = False

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle Wizard navigation clicks."""
        
        # Abort logic
        if event.button.id == "btn-cancel" or event.button.id == "btn-exit":
            self.exit()

        # Step 1 -> Step 2
        elif event.button.id == "btn-next":
            alias_input = self.query_one("#input-alias", Input)
            host_input = self.query_one("#input-host", Input)
            user_input = self.query_one("#input-user", Input)
            port_input = self.query_one("#input-port", Input)

            if not alias_input.value or not host_input.value:
                # Basic validation (could be enhanced via Textual Native Validation)
                self.notify("Error: Alias and Host are strictly required.", severity="error")
                return

            self.tmp_alias = alias_input.value.strip()
            self.tmp_host = host_input.value.strip()
            self.tmp_user = user_input.value.strip() or "root"
            try:
                self.tmp_port = int(port_input.value.strip() or 22)
            except ValueError:
                self.notify("Error: Port must be an integer.", severity="error")
                return

            # Transition View
            self.query_one("#screen-target").display = False
            self.query_one("#screen-fido").display = True
            
        # Step 2 -> FIDO Bridge (Hardware Minting)
        elif event.button.id == "btn-mint":
            self._execute_hardware_enrollment()

    def _execute_hardware_enrollment(self) -> None:
        """Bridges Textual TUI with the FIDO2 hardware generation pipeline."""
        
        status = self.query_one("#fido-status", Static)
        status.update("Status: [bold yellow]Awaiting Hardware Tap...[/bold yellow]")
        self.query_one("#btn-mint", Button).disabled = True

        display_name = f"uon:{self.tmp_user}@{self.tmp_host}"
        user_id = os.urandom(32)

        try:
            # Note: This is a synchronous, blocking FIDO2 loop.
            # In a production async UI, we would execute this in a worker thread.
            result = fido_register(
                user_id=user_id,
                user_name=display_name,
            )
            
            # Attestation validation
            policy = PolicyStore()
            rejection = policy.check_credential(result.aaguid, result.backup_eligible)
            if rejection is not None:
                self.notify(f"Policy Rejection: {rejection}", severity="error")
                self.exit(1)
                return

            # Store the Target telemetry alongside the new Credential
            store = TargetStore()
            t = Target(alias=self.tmp_alias, host=self.tmp_host, port=self.tmp_port, user=self.tmp_user)
            cred_id_b64 = base64.b64encode(result.credential_id).decode()
            credential = Credential(id=cred_id_b64, aaguid=result.aaguid)
            t.credentials.append(credential)
            store.add(t)

            # Advance to completion screen
            self.query_one("#screen-fido").display = False
            self.query_one("#screen-success").display = True
            
        except NoPlatformAuthenticatorError as exc:
            status.update(f"Status: [bold red]Error: {exc}[/bold red]")
            self.notify(str(exc), severity="error")
            self.query_one("#btn-mint", Button).disabled = False
        except Exception as exc:
            status.update(f"Status: [bold red]Hardware Error ({exc}).[/bold red]")
            self.notify("The hardware transaction was aborted or timed out.", severity="error")
            self.query_one("#btn-mint", Button).disabled = False

if __name__ == "__main__":
    app = OnboardingWizard()
    app.run()
