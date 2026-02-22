# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Tests for src.cli — Click CLI group, subcommands, core execution."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import click
import click.testing
import pytest

from uon.cli import (
    _print_result,
    _resolve_signature,
    _run_command,
    add,
    list_targets,
    main,
    policy_add,
    policy_clear,
    policy_remove,
    policy_show,
    register,
    remove,
)
from uon.transport.ssh_client import ExecResult
from uon.utils.config import Credential, Target, TargetStore

# ── helpers ──────────────────────────────────────────────────────────


def _make_reg_result(
    credential_id: bytes = b"cred-id",
    aaguid: str = "2fc0579f-8113-47ea-b116-bb5a8db9202a",
    backup_eligible: bool = False,
) -> object:
    from uon.auth.fido_local import RegistrationResult

    return RegistrationResult(MagicMock(), credential_id, aaguid, backup_eligible)


# ── main group ───────────────────────────────────────────────────────


class TestMainGroup:
    def test_no_args_shows_help(
        self, cli_runner: click.testing.CliRunner, isolate_store: Path
    ) -> None:
        result = cli_runner.invoke(main, [])
        assert result.exit_code == 0
        assert "uon" in result.output

    def test_target_without_command(
        self, cli_runner: click.testing.CliRunner, isolate_store: Path
    ) -> None:
        # "myserver" is consumed as target, command=None → error
        result = cli_runner.invoke(main, ["myserver"])
        assert result.exit_code != 0

    def test_target_and_command_runs(
        self, cli_runner: click.testing.CliRunner, isolate_store: Path
    ) -> None:
        # Both target and command provided but target doesn't exist
        with patch("uon.cli._run_command", side_effect=SystemExit(1)):
            result = cli_runner.invoke(main, ["myserver", "uptime"])
        assert result.exit_code != 0

    def test_invoked_subcommand_returns(self) -> None:
        """When ctx.invoked_subcommand is set, main() returns immediately."""
        ctx = click.Context(main)
        ctx.invoked_subcommand = "add"
        with ctx:
            result = main.callback(target=None, command=None)
        assert result is None


# ── add subcommand ───────────────────────────────────────────────────


class TestAdd:
    def test_success(self, cli_runner: click.testing.CliRunner, isolate_store: Path) -> None:
        result = cli_runner.invoke(add, ["dev", "10.0.0.1"])
        assert result.exit_code == 0
        assert "added" in result.output

    def test_with_options(self, cli_runner: click.testing.CliRunner, isolate_store: Path) -> None:
        result = cli_runner.invoke(add, ["prod", "10.0.0.2", "--port", "2222", "--user", "deploy"])
        assert result.exit_code == 0
        store = TargetStore()
        t = store.get("prod")
        assert t is not None
        assert t.port == 2222
        assert t.user == "deploy"


# ── list subcommand ──────────────────────────────────────────────────


class TestList:
    def test_empty(self, cli_runner: click.testing.CliRunner, isolate_store: Path) -> None:
        result = cli_runner.invoke(list_targets, [])
        assert result.exit_code == 0
        assert "No targets" in result.output

    def test_populated(self, cli_runner: click.testing.CliRunner, isolate_store: Path) -> None:
        cli_runner.invoke(add, ["box", "1.2.3.4"])
        result = cli_runner.invoke(list_targets, [])
        assert result.exit_code == 0
        assert "box" in result.output


# ── remove subcommand ────────────────────────────────────────────────


class TestRemove:
    def test_existing(self, cli_runner: click.testing.CliRunner, isolate_store: Path) -> None:
        cli_runner.invoke(add, ["rm_me", "1.1.1.1"])
        result = cli_runner.invoke(remove, ["rm_me"])
        assert result.exit_code == 0
        assert "removed" in result.output

    def test_missing(self, cli_runner: click.testing.CliRunner, isolate_store: Path) -> None:
        result = cli_runner.invoke(remove, ["ghost"])
        assert result.exit_code != 0


# ── register subcommand ─────────────────────────────────────────────


class TestRegister:
    def test_unknown_target(self, cli_runner: click.testing.CliRunner, isolate_store: Path) -> None:
        result = cli_runner.invoke(register, ["nope"])
        assert result.exit_code != 0
        assert "Unknown" in result.output

    @patch("uon.cli.PolicyStore")
    @patch("uon.cli.fido_register")
    def test_success(
        self,
        mock_fido: MagicMock,
        mock_policy_cls: MagicMock,
        cli_runner: click.testing.CliRunner,
        isolate_store: Path,
    ) -> None:
        cli_runner.invoke(add, ["dev", "10.0.0.1"])
        mock_fido.return_value = _make_reg_result()
        mock_policy_inst = MagicMock()
        mock_policy_inst.check_credential.return_value = None
        mock_policy_cls.return_value = mock_policy_inst

        result = cli_runner.invoke(register, ["dev"])
        assert result.exit_code == 0
        assert "Credential registered" in result.output
        assert "AAGUID" in result.output

    @patch("uon.cli.fido_register")
    def test_no_authenticator(
        self,
        mock_fido: MagicMock,
        cli_runner: click.testing.CliRunner,
        isolate_store: Path,
    ) -> None:
        from uon.auth.fido_local import NoPlatformAuthenticatorError

        cli_runner.invoke(add, ["dev", "10.0.0.1"])
        mock_fido.side_effect = NoPlatformAuthenticatorError("none")

        result = cli_runner.invoke(register, ["dev"])
        assert result.exit_code != 0

    @patch("uon.cli.PolicyStore")
    @patch("uon.cli.fido_register")
    def test_policy_rejects_unlisted(
        self,
        mock_fido: MagicMock,
        mock_policy_cls: MagicMock,
        cli_runner: click.testing.CliRunner,
        isolate_store: Path,
    ) -> None:
        cli_runner.invoke(add, ["dev", "10.0.0.1"])
        mock_fido.return_value = _make_reg_result()
        mock_policy_inst = MagicMock()
        mock_policy_inst.check_credential.return_value = "Policy rejection: AAGUID not listed"
        mock_policy_cls.return_value = mock_policy_inst

        result = cli_runner.invoke(register, ["dev"])
        assert result.exit_code != 0

    @patch("uon.cli.PolicyStore")
    @patch("uon.cli.fido_register")
    def test_policy_rejects_backup_eligible(
        self,
        mock_fido: MagicMock,
        mock_policy_cls: MagicMock,
        cli_runner: click.testing.CliRunner,
        isolate_store: Path,
    ) -> None:
        cli_runner.invoke(add, ["dev", "10.0.0.1"])
        mock_fido.return_value = _make_reg_result(backup_eligible=True)
        mock_policy_inst = MagicMock()
        mock_policy_inst.check_credential.return_value = "Policy rejection: backup-eligible"
        mock_policy_cls.return_value = mock_policy_inst

        result = cli_runner.invoke(register, ["dev"])
        assert result.exit_code != 0

    @patch("uon.cli.PolicyStore")
    @patch("uon.cli.fido_register")
    def test_open_policy_allows_all(
        self,
        mock_fido: MagicMock,
        mock_policy_cls: MagicMock,
        cli_runner: click.testing.CliRunner,
        isolate_store: Path,
    ) -> None:
        cli_runner.invoke(add, ["dev", "10.0.0.1"])
        mock_fido.return_value = _make_reg_result()
        mock_policy_inst = MagicMock()
        mock_policy_inst.check_credential.return_value = None
        mock_policy_cls.return_value = mock_policy_inst

        result = cli_runner.invoke(register, ["dev"])
        assert result.exit_code == 0


# ── _run_command ─────────────────────────────────────────────────────


class TestRunCommand:
    def test_unknown_target(self, isolate_store: Path) -> None:
        with pytest.raises(SystemExit):
            _run_command("nope", "ls")

    def test_no_credentials(self, isolate_store: Path) -> None:
        store = TargetStore()
        store.add(Target(alias="dev", host="10.0.0.1"))
        with pytest.raises(SystemExit):
            _run_command("dev", "ls")

    @patch("uon.cli.execute_signed")
    @patch("uon.cli._resolve_signature")
    @patch("uon.cli.request_challenge")
    def test_full_success(
        self,
        mock_challenge: MagicMock,
        mock_resolve: MagicMock,
        mock_exec: MagicMock,
        isolate_store: Path,
    ) -> None:
        store = TargetStore()
        t = Target(alias="dev", host="10.0.0.1", credentials=[Credential(id="Y3JlZA==")])
        store.add(t)

        from uon.transport.ssh_client import ChallengePacket

        mock_challenge.return_value = ChallengePacket(nonce=b"\x00" * 32, session_id=b"\x01" * 32)
        mock_resolve.return_value = {"sig": "ok"}
        mock_exec.return_value = ExecResult(exit_code=0, stdout="done\n", stderr="")

        with pytest.raises(SystemExit) as exc_info:
            _run_command("dev", "uptime")
        assert exc_info.value.code == 0


# ── _resolve_signature ──────────────────────────────────────────────


class TestResolveSignature:
    @patch("uon.cli.fido_authenticate")
    def test_tier1_success(self, mock_auth: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.credential_id = b"cid"
        mock_response.authenticator_data = b"ad"
        mock_response.client_data = b"cd"
        mock_response.signature = b"sig"
        mock_auth.return_value = mock_response

        result = _resolve_signature(b"challenge", [b"cid"])
        assert result.credential_id == b"cid"
        assert result.signature == b"sig"

    @patch("uon.cli.request_signature_via_qr")
    @patch("uon.cli.fido_authenticate")
    def test_tier1_no_auth_falls_to_tier2(self, mock_auth: MagicMock, mock_qr: MagicMock) -> None:
        from uon.auth.fido_local import NoPlatformAuthenticatorError
        from uon.contracts.fido_dto import FidoAssertionDto

        mock_auth.side_effect = NoPlatformAuthenticatorError("none")
        expected_dto = FidoAssertionDto(credential_id=b"qr-cid", client_data=b"cd", auth_data=b"ad", signature=b"sig")
        mock_qr.return_value = expected_dto

        result = _resolve_signature(b"c", [b"id"])
        assert result == expected_dto

    @patch("uon.cli.request_signature_via_qr")
    @patch("uon.cli.fido_authenticate")
    def test_tier1_generic_error_falls_to_tier2(
        self, mock_auth: MagicMock, mock_qr: MagicMock
    ) -> None:
        from uon.contracts.fido_dto import FidoAssertionDto
        
        mock_auth.side_effect = ValueError("device error")
        expected_dto = FidoAssertionDto(credential_id=b"qr-cid", client_data=b"cd", auth_data=b"ad", signature=b"sig")
        mock_qr.return_value = expected_dto

        result = _resolve_signature(b"c", [b"id"])
        assert result == expected_dto

    @patch("uon.cli.request_signature_via_qr")
    @patch("uon.cli.fido_authenticate")
    def test_both_fail_timeout(self, mock_auth: MagicMock, mock_qr: MagicMock) -> None:
        from uon.auth.fido_local import NoPlatformAuthenticatorError

        mock_auth.side_effect = NoPlatformAuthenticatorError("none")
        mock_qr.side_effect = TimeoutError("timed out")

        with pytest.raises(SystemExit):
            _resolve_signature(b"c", [b"id"])

    @patch("uon.cli.request_signature_via_qr")
    @patch("uon.cli.fido_authenticate")
    def test_both_fail_runtime(self, mock_auth: MagicMock, mock_qr: MagicMock) -> None:
        from uon.auth.fido_local import NoPlatformAuthenticatorError

        mock_auth.side_effect = NoPlatformAuthenticatorError("none")
        mock_qr.side_effect = RuntimeError("bridge broke")

        with pytest.raises(SystemExit):
            _resolve_signature(b"c", [b"id"])


# ── _print_result ───────────────────────────────────────────────────


class TestPrintResult:
    def test_stdout_only(self, capsys: pytest.CaptureFixture[str]) -> None:
        _print_result(ExecResult(exit_code=0, stdout="hello\n", stderr=""))
        captured = capsys.readouterr()
        assert captured.out == "hello\n"
        assert captured.err == ""

    def test_stderr_only(self, capsys: pytest.CaptureFixture[str]) -> None:
        _print_result(ExecResult(exit_code=1, stdout="", stderr="oops\n"))
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == "oops\n"

    def test_both(self, capsys: pytest.CaptureFixture[str]) -> None:
        _print_result(ExecResult(exit_code=0, stdout="out\n", stderr="err\n"))
        captured = capsys.readouterr()
        assert "out" in captured.out
        assert "err" in captured.err

    def test_no_trailing_newline(self, capsys: pytest.CaptureFixture[str]) -> None:
        _print_result(ExecResult(exit_code=0, stdout="no-nl", stderr="no-nl"))
        captured = capsys.readouterr()
        assert captured.out.endswith("\n")
        assert captured.err.endswith("\n")

    def test_empty(self, capsys: pytest.CaptureFixture[str]) -> None:
        _print_result(ExecResult(exit_code=0, stdout="", stderr=""))
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""


# ── policy subcommands ──────────────────────────────────────────────


class TestPolicyShow:
    def test_open_policy(self, cli_runner: click.testing.CliRunner, isolate_policy: Path) -> None:
        result = cli_runner.invoke(policy_show, [])
        assert result.exit_code == 0
        assert "OPEN" in result.output

    def test_enforcing_policy(
        self, cli_runner: click.testing.CliRunner, isolate_policy: Path
    ) -> None:
        from uon.utils.policy import PolicyStore

        ps = PolicyStore()
        ps.add("2fc0579f-8113-47ea-b116-bb5a8db9202a")

        result = cli_runner.invoke(policy_show, [])
        assert result.exit_code == 0
        assert "ENFORCING" in result.output
        assert "2fc0579f-8113-47ea-b116-bb5a8db9202a" in result.output


class TestPolicyAdd:
    def test_valid_aaguid(self, cli_runner: click.testing.CliRunner, isolate_policy: Path) -> None:
        result = cli_runner.invoke(policy_add, ["2fc0579f-8113-47ea-b116-bb5a8db9202a"])
        assert result.exit_code == 0
        assert "Added" in result.output

    def test_invalid_format(
        self, cli_runner: click.testing.CliRunner, isolate_policy: Path
    ) -> None:
        result = cli_runner.invoke(policy_add, ["not-a-uuid"])
        assert result.exit_code != 0
        assert "Invalid" in result.output

    def test_duplicate(self, cli_runner: click.testing.CliRunner, isolate_policy: Path) -> None:
        cli_runner.invoke(policy_add, ["2fc0579f-8113-47ea-b116-bb5a8db9202a"])
        result = cli_runner.invoke(policy_add, ["2fc0579f-8113-47ea-b116-bb5a8db9202a"])
        assert result.exit_code == 0
        assert "already in the policy" in result.output


class TestPolicyRemove:
    def test_existing(self, cli_runner: click.testing.CliRunner, isolate_policy: Path) -> None:
        cli_runner.invoke(policy_add, ["2fc0579f-8113-47ea-b116-bb5a8db9202a"])
        result = cli_runner.invoke(policy_remove, ["2fc0579f-8113-47ea-b116-bb5a8db9202a"])
        assert result.exit_code == 0
        assert "Removed" in result.output

    def test_missing(self, cli_runner: click.testing.CliRunner, isolate_policy: Path) -> None:
        result = cli_runner.invoke(policy_remove, ["2fc0579f-8113-47ea-b116-bb5a8db9202a"])
        assert result.exit_code != 0
        assert "not found" in result.output


class TestPolicyClear:
    def test_with_entries(self, cli_runner: click.testing.CliRunner, isolate_policy: Path) -> None:
        cli_runner.invoke(policy_add, ["2fc0579f-8113-47ea-b116-bb5a8db9202a"])
        cli_runner.invoke(policy_add, ["00000000-0000-0000-0000-000000000000"])
        result = cli_runner.invoke(policy_clear, [])
        assert result.exit_code == 0
        assert "2" in result.output
