# Copyright (c) 2024 Sebastien Rousseau
#
# Licensed under the MIT License. See LICENSE file in the project root
# for full license information.

"""CLI entry point for uon -- FIDO2-signed remote terminal execution.

This module wires together every uon subsystem into a Click-based command
line interface.  You interact with it through five commands:

======================  ==================================================
Command                 Purpose
======================  ==================================================
``uon <t> "<cmd>"``     Sign and execute *cmd* on target *t*.
``uon add``             Register a new target machine.
``uon list``            Show all registered targets.
``uon register``        Enroll a FIDO2 passkey for a target.
``uon remove``          Un-register a target.
======================  ==================================================

Execution flow (``uon myserver "uptime"``):

1. ``_run_command()`` loads the target from the ``TargetStore``, decodes
   the stored credential IDs, and calls ``request_challenge()`` for a
   fresh nonce.
2. ``_resolve_signature()`` implements **tiered authentication**:

   * **Tier 1** -- attempt local biometric signing via
     ``fido_local.authenticate()``.
   * **Tier 2** -- if no platform authenticator is found (or any other
     error occurs), gracefully degrade to the QR bridge
     (``qr_bridge.request_signature_via_qr()``).

3. ``execute_signed()`` wraps the command + assertion in a
   ``__UON_EXEC__`` envelope and sends it over SSH.
4. ``_print_result()`` streams stdout/stderr to the local terminal.
"""

from __future__ import annotations

import base64
import os
import sys
from typing import Any

import click

from uon.auth.fido_local import (
    RP_ID,
    NoPlatformAuthenticatorError,
)
from uon.auth.fido_local import (
    authenticate as fido_authenticate,
)
from uon.auth.fido_local import (
    register as fido_register,
)
from uon.auth.qr_bridge import request_signature_via_qr
from uon.transport.ssh_client import ExecResult, execute_signed, request_challenge
from uon.utils.config import Credential, Target, TargetStore
from uon.utils.policy import PolicyStore, is_valid_aaguid

# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group(invoke_without_command=True)
@click.argument("target", required=False)
@click.argument("command", required=False)
@click.pass_context
def main(ctx: click.Context, target: str | None, command: str | None) -> None:
    """uon -- FIDO2-signed remote command execution.

    Run a command on a registered target::

        uon myserver "uptime"

    Or use a subcommand (``add``, ``list``, ``register``, ``remove``).

    When invoked without a subcommand, the first positional argument is
    the target alias and the second is the shell command to execute.
    """
    if ctx.invoked_subcommand is not None:
        return

    if target is None:
        click.echo(ctx.get_help())
        ctx.exit(0)

    if command is None:
        click.echo("Error: missing COMMAND argument.", err=True)
        click.echo('Usage: uon <target> "<command>"', err=True)
        ctx.exit(1)

    _run_command(target, command)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


@main.command()
@click.argument("alias")
@click.argument("host")
@click.option("--port", "-p", default=22, show_default=True, help="SSH port.")
@click.option("--user", "-u", default="root", show_default=True, help="Remote username.")
def add(alias: str, host: str, port: int, user: str) -> None:
    """Register a new target machine.

    Persists the target in the ``TargetStore``.  If a target with the
    same alias already exists it is silently overwritten.
    """
    store = TargetStore()
    t = Target(alias=alias, host=host, port=port, user=user)
    store.add(t)
    click.echo(f"Target '{alias}' added ({user}@{host}:{port}).")


@main.command(name="list")
def list_targets() -> None:
    """Show all registered targets and their credential counts."""
    store = TargetStore()
    targets = store.list_targets()
    if not targets:
        click.echo("No targets registered.  Use 'uon add' first.")
        return
    for t in targets:
        creds = len(t.credential_ids)
        click.echo(f"  {t.alias:20s}  {t.user}@{t.host}:{t.port}  ({creds} credential(s))")


@main.command()
@click.argument("alias")
def remove(alias: str) -> None:
    """Un-register a target.

    Exits with code 1 if the alias does not exist.
    """
    store = TargetStore()
    if store.remove(alias):
        click.echo(f"Target '{alias}' removed.")
    else:
        click.echo(f"Target '{alias}' not found.", err=True)
        raise SystemExit(1)


@main.command()
@click.argument("alias")
@click.option("--user-name", default=None, help="Display name for the credential.")
def register(alias: str, user_name: str | None) -> None:
    """Enroll a FIDO2 passkey for a target.

    Triggers a biometric prompt on your authenticator, creates a new
    resident-key credential inside the hardware Secure Enclave, and
    records the base64-encoded credential ID in the ``TargetStore``.

    When an AAGUID policy is enforcing, the credential's AAGUID and
    backup-eligibility flag are validated before storage.

    After enrollment you must install the corresponding public key on
    the target machine (e.g. via ``scripts/setup_uon.py`` and
    ``scp``).

    Raises:
        SystemExit(1): If the target alias is unknown, no FIDO2
            authenticator is available, or the policy rejects the
            credential.
    """
    store = TargetStore()
    target = store.get(alias)
    if target is None:
        click.echo(f"Unknown target '{alias}'.  Run 'uon add' first.", err=True)
        raise SystemExit(1)

    display_name = user_name or f"uon:{target.user}@{target.host}"
    user_id = os.urandom(32)

    click.echo(f"Enrolling FIDO2 credential for '{alias}' …")
    click.echo("You may be prompted for biometric verification.\n")

    try:
        result = fido_register(
            user_id=user_id,
            user_name=display_name,
        )
    except NoPlatformAuthenticatorError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1) from exc

    policy = PolicyStore()
    rejection = policy.check_credential(result.aaguid, result.backup_eligible)
    if rejection is not None:
        click.echo(rejection, err=True)
        raise SystemExit(1)

    cred_id_b64 = base64.b64encode(result.credential_id).decode()
    credential = Credential(id=cred_id_b64, aaguid=result.aaguid)
    target.credentials.append(credential)
    store.add(target)

    click.echo(f"\nCredential registered (ID: {cred_id_b64[:16]}…, AAGUID: {result.aaguid}).")
    click.echo(
        "\nInstall the public key on the target by appending it to "
        "~/.ssh/authorized_keys on the remote machine."
    )


# ---------------------------------------------------------------------------
# Policy subcommands
# ---------------------------------------------------------------------------


@main.group()
def policy() -> None:
    """Manage the AAGUID attestation policy."""


@policy.command(name="show")
def policy_show() -> None:
    """Display the current AAGUID policy state and listed AAGUIDs."""
    ps = PolicyStore()
    if not ps.is_enforcing:
        click.echo("Policy: OPEN (all authenticators allowed)")
        return
    click.echo("Policy: ENFORCING")
    for aaguid in ps.list_aaguids():
        click.echo(f"  {aaguid}")


@policy.command(name="add")
@click.argument("aaguid")
def policy_add(aaguid: str) -> None:
    """Add an AAGUID to the attestation allowlist."""
    if not is_valid_aaguid(aaguid):
        click.echo(f"Invalid AAGUID format: {aaguid}", err=True)
        raise SystemExit(1)
    ps = PolicyStore()
    if ps.add(aaguid):
        click.echo(f"Added {aaguid.lower()} to policy.")
    else:
        click.echo(f"AAGUID {aaguid.lower()} is already in the policy.")


@policy.command(name="remove")
@click.argument("aaguid")
def policy_remove(aaguid: str) -> None:
    """Remove an AAGUID from the attestation allowlist."""
    ps = PolicyStore()
    if ps.remove(aaguid):
        click.echo(f"Removed {aaguid.lower()} from policy.")
    else:
        click.echo(f"AAGUID {aaguid.lower()} not found in policy.", err=True)
        raise SystemExit(1)


@policy.command(name="clear")
def policy_clear() -> None:
    """Remove all AAGUIDs from the attestation policy."""
    ps = PolicyStore()
    count = ps.clear()
    click.echo(f"Cleared {count} AAGUID(s) from policy.")


# ---------------------------------------------------------------------------
# Core execution logic
# ---------------------------------------------------------------------------


def _run_command(target_alias: str, command: str) -> None:
    """Resolve a target, authenticate via FIDO2, and execute a remote command.

    This is the core execution path for ``uon <target> "<command>"``.
    It orchestrates three stages:

    1. **Lookup** -- load the target from the ``TargetStore`` and verify
       that at least one FIDO2 credential is enrolled.
    2. **Challenge + Sign** -- obtain a nonce via ``request_challenge()``
       and sign it through ``_resolve_signature()`` (tiered auth).
    3. **Execute** -- send the signed envelope via ``execute_signed()``
       and print the result.

    Args:
        target_alias: The short name of the target (e.g. ``"prod"``).
        command:      The shell command to run on the remote machine.

    Raises:
        SystemExit(1): If the target is unknown, has no credentials, or
            if both authentication tiers fail.
        SystemExit(exit_code): With the remote process's exit code on
            successful execution.
    """
    store = TargetStore()
    target = store.get(target_alias)
    if target is None:
        click.echo(f"Unknown target '{target_alias}'.  Run 'uon add' first.", err=True)
        raise SystemExit(1)

    if not target.credential_ids:
        click.echo(
            f"No FIDO2 credentials for '{target_alias}'.  Run 'uon register' first.",
            err=True,
        )
        raise SystemExit(1)

    credential_ids_raw = [base64.b64decode(c) for c in target.credential_ids]

    # Step 1: Obtain challenge
    click.echo(f"Connecting to {target.user}@{target.host}:{target.port} …", err=True)
    challenge = request_challenge(target.host, target.port, target.user)

    # Step 2: Sign challenge — try local biometric first, fall back to QR
    assertion = _resolve_signature(challenge.nonce, credential_ids_raw)

    # Step 3: Execute
    click.echo("Executing command …", err=True)
    result = execute_signed(
        host=target.host,
        port=target.port,
        username=target.user,
        command=command,
        assertion=assertion,
        challenge=challenge,
    )

    _print_result(result)
    raise SystemExit(result.exit_code)


def _resolve_signature(
    challenge: bytes,
    credential_ids: list[bytes],
) -> dict[str, Any]:
    """Negotiate the strongest available FIDO2 signing method automatically.

    Implements a two-tier degradation strategy so that command signing
    succeeds even when the local platform authenticator is unavailable
    (lid closed, WSL without Windows Hello, headless server).

    Tier resolution order:

    =====  =========================  ===================================
    Tier   Method                     Trigger for fallback
    =====  =========================  ===================================
    1      Local biometric            ``NoPlatformAuthenticatorError`` or
           (``fido_local.authenticate``) any other ``Exception``
    2      QR bridge                  ``TimeoutError`` or
           (``qr_bridge``)            ``RuntimeError`` → hard exit
    =====  =========================  ===================================

    Args:
        challenge: Raw 32-byte nonce from ``request_challenge()`` that
            the authenticator must sign.
        credential_ids: Allowed credential IDs (raw bytes) from prior
            ``register()`` calls stored in the ``TargetStore``.

    Returns:
        A dict with four base64-encoded string values keyed as
        ``credentialId``, ``authenticatorData``, ``clientDataJSON``,
        and ``signature`` -- ready for JSON serialisation into the
        ``__UON_EXEC__`` envelope.

    Raises:
        SystemExit(1): If **both** tiers fail.  Tier 2 failures
            (``TimeoutError``, ``RuntimeError``) are fatal because no
            further fallback exists.

    Security:
        Tier 1 errors are reported to stderr but never leak stack
        traces.  The ``except Exception`` guard ensures that transient
        USB or driver errors degrade gracefully rather than aborting
        the session.
    """
    # --- Tier 1: local platform authenticator ---
    try:
        response = fido_authenticate(
            challenge=challenge,
            credential_ids=credential_ids,
        )
        return {
            "credentialId": base64.b64encode(response.credential_id).decode(),  # type: ignore[attr-defined]
            "authenticatorData": base64.b64encode(response.authenticator_data).decode(),
            "clientDataJSON": base64.b64encode(response.client_data).decode(),
            "signature": base64.b64encode(response.signature).decode(),
        }
    except NoPlatformAuthenticatorError:
        click.echo("No local authenticator found — launching QR bridge …", err=True)
    except Exception as exc:
        click.echo(
            f"Local authenticator error ({exc}) — falling back to QR bridge …",
            err=True,
        )

    # --- Tier 2: QR code fallback ---
    try:
        return request_signature_via_qr(
            challenge=challenge,
            rp_id=RP_ID,
            credential_ids=credential_ids,
        )
    except TimeoutError as exc:
        click.echo(f"QR bridge timed out: {exc}", err=True)
        raise SystemExit(1) from exc
    except RuntimeError as exc:
        click.echo(f"QR bridge error: {exc}", err=True)
        raise SystemExit(1) from exc


def _print_result(result: ExecResult) -> None:
    """Write the remote command's output to the corresponding local streams.

    Stdout and stderr are forwarded independently so that downstream
    shell pipelines and redirections behave identically to a direct SSH
    session.  A trailing newline is appended only when the remote output
    does not already end with one, preventing double-spacing in
    terminal output.

    Args:
        result: Immutable ``ExecResult`` snapshot returned by
            ``execute_signed()``.
    """
    if result.stdout:
        sys.stdout.write(result.stdout)
        if not result.stdout.endswith("\n"):
            sys.stdout.write("\n")
    if result.stderr:
        sys.stderr.write(result.stderr)
        if not result.stderr.endswith("\n"):
            sys.stderr.write("\n")


if __name__ == "__main__":
    main()
