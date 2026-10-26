# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Tests for the authorized_keys hooking step of install_target.sh."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "install_target.sh"
_PREFIX = (
    'command="/usr/local/bin/uon_verifier.py",'
    "no-port-forwarding,no-X11-forwarding,no-agent-forwarding"
)

# Runs Step 3's loop over $KEYS_IN with the script's own functions.
_HARNESS = """
set -eo pipefail
UON_INSTALL_TARGET_SOURCE_ONLY=1 source "$SCRIPT"
while IFS= read -r line || [[ -n $line ]]; do
    hook_authorized_key "$line"
done < "$KEYS_IN"
"""

_BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(_BASH is None, reason="needs bash")


def _hook(tmp_path: Path, content: str) -> subprocess.CompletedProcess[str]:
    keys = tmp_path / "authorized_keys"
    keys.write_text(content)
    env = {**os.environ, "SCRIPT": str(_SCRIPT), "KEYS_IN": str(keys)}
    assert _BASH is not None
    return subprocess.run(  # noqa: S603 - runs this repository's own installer functions
        [_BASH, "-c", _HARNESS],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )


@pytest.mark.parametrize(
    "key",
    [
        "ssh-ed25519 AAAAC3Nza ed25519@admin",
        "ssh-rsa AAAAB3Nza rsa@admin",
        "ecdsa-sha2-nistp256 AAAAE2Vj p256@admin",
        "ecdsa-sha2-nistp384 AAAAE2Vj p384@admin",
        "ecdsa-sha2-nistp521 AAAAE2Vj p521@admin",
        "sk-ssh-ed25519@openssh.com AAAAGnNr sk-ed25519@admin",
        "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNr sk-p256@admin",
    ],
)
def test_every_key_type_is_hooked(tmp_path: Path, key: str) -> None:
    assert _hook(tmp_path, key + "\n").stdout == f"{_PREFIX} {key}\n"


@pytest.mark.parametrize(
    "key",
    [
        'from="10.0.0.0/8" ssh-ed25519 AAAAC3Nza from@admin',
        'no-pty,from="10.0.0.0/8,192.168.0.0/16" ssh-ed25519 AAAAC3Nza two@admin',
        'environment="A=b c" sk-ssh-ed25519@openssh.com AAAAGnNr quoted-space@admin',
        'environment="A=\\"b c\\"" ssh-ed25519 AAAAC3Nza escaped-quote@admin',
    ],
)
def test_existing_options_follow_the_hook(tmp_path: Path, key: str) -> None:
    assert _hook(tmp_path, key + "\n").stdout == f"{_PREFIX},{key}\n"


def test_leading_whitespace_is_hooked(tmp_path: Path) -> None:
    out = _hook(tmp_path, "  ssh-ed25519 AAAAC3Nza indented@admin\n").stdout
    assert out == f"{_PREFIX} ssh-ed25519 AAAAC3Nza indented@admin\n"


def test_last_line_without_newline_is_kept(tmp_path: Path) -> None:
    out = _hook(tmp_path, "ssh-ed25519 AAAAC3Nza last@admin").stdout
    assert out == f"{_PREFIX} ssh-ed25519 AAAAC3Nza last@admin\n"


def test_blank_lines_and_comments_pass_through(tmp_path: Path) -> None:
    content = "# admin keys\n\n   \n"
    assert _hook(tmp_path, content).stdout == content


def test_hooking_twice_changes_nothing(tmp_path: Path) -> None:
    content = (
        'ssh-ed25519 AAAAC3Nza a@admin\nfrom="10.0.0.0/8" ecdsa-sha2-nistp384 AAAAE2Vj b@admin\n'
    )
    once = _hook(tmp_path, content).stdout
    assert _hook(tmp_path, once).stdout == once


@pytest.mark.parametrize(
    "key",
    [
        'command="/usr/bin/rrsync -ro /srv" ssh-ed25519 AAAAC3Nza backup',
        'from="1.2.3.4",command="/bin/true" ssh-ed25519 AAAAC3Nza ci',
    ],
)
def test_forced_command_keys_are_left_with_a_warning(tmp_path: Path, key: str) -> None:
    result = _hook(tmp_path, key + "\n")
    assert result.stdout == key + "\n"
    assert "conflicting command=" in result.stderr
