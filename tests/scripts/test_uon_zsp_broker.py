# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Tests for the persistent ZSP broker."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest


def _import_broker() -> Any:
    spec = importlib.util.spec_from_file_location(
        "uon_zsp_broker",
        str(Path(__file__).resolve().parents[2] / "scripts" / "uon_zsp_broker.py"),
    )
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def broker() -> Any:
    return _import_broker()


def test_run_command_encodes_streams_and_exit_code(
    broker: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = MagicMock()
    process.communicate.return_value = (b"hello", b"warn")
    process.returncode = 7

    popen = MagicMock(return_value=process)
    monkeypatch.setattr(broker.subprocess, "Popen", popen)

    result = broker._run_command("echo hello")

    assert result["exit_code"] == 7
    assert result["stdout"] == "aGVsbG8="
    assert result["stderr"] == "d2Fybg=="


def test_handle_connection_returns_error_payload_on_bad_request(broker: Any) -> None:
    conn = MagicMock()
    reader = MagicMock()
    reader.readline.return_value = "not-json\n"
    writer = MagicMock()
    conn.makefile.side_effect = [reader, writer]
    conn.__enter__.return_value = conn

    broker._handle_connection(conn)

    writer.write.assert_called()
    payload = writer.write.call_args_list[0].args[0]
    assert '"exit_code":1' in payload
