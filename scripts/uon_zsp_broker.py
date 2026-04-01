#!/usr/bin/env python3
# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Persistent Zero Standing Privilege broker for target-side command execution."""

from __future__ import annotations

import base64
import json
import os
import shlex
import socket
import stat
import subprocess
from typing import Final

DEFAULT_SOCKET_PATH: Final[str] = "/run/uon/zsp.sock"
DEFAULT_EXEC_GROUP: Final[str] = "uon-exec"


def _env_int(name: str) -> int | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return None
    return int(value)


def _resolve_exec_uid() -> int:
    value = _env_int("UON_ZSP_TARGET_UID")
    if value is not None:
        return value
    return os.getuid()


def _resolve_exec_gid() -> int:
    value = _env_int("UON_ZSP_EXEC_GID")
    if value is not None:
        return value

    import grp

    return grp.getgrnam(DEFAULT_EXEC_GROUP).gr_gid


def _resolve_socket_uid() -> int:
    value = _env_int("UON_ZSP_SOCKET_UID")
    if value is not None:
        return value
    return _resolve_exec_uid()


def _resolve_socket_gid() -> int:
    value = _env_int("UON_ZSP_SOCKET_GID")
    if value is not None:
        return value
    return _resolve_exec_gid()


def _socket_path() -> str:
    return os.environ.get("UON_ZSP_SOCKET", DEFAULT_SOCKET_PATH)


def _prepare_socket(path: str) -> socket.socket:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, mode=0o755, exist_ok=True)
    if os.path.exists(path):
        if stat.S_ISSOCK(os.stat(path).st_mode):
            os.unlink(path)
        else:
            raise RuntimeError(f"Refusing to replace non-socket path: {path}")

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    os.chown(path, _resolve_socket_uid(), _resolve_socket_gid())
    os.chmod(path, 0o660)
    server.listen()
    return server


def _preexec_fn() -> None:
    gid = _resolve_exec_gid()
    uid = _resolve_exec_uid()
    os.setgroups([gid])
    os.setgid(gid)
    os.setuid(uid)


def _run_command(command: str) -> dict[str, object]:
    try:
        args = shlex.split(command)
        use_shell = False
        popen_args: str | list[str] = args
    except ValueError:
        use_shell = True
        popen_args = command

    proc = subprocess.Popen(  # noqa: S603 - broker is the explicit command execution boundary
        popen_args,
        shell=use_shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        preexec_fn=_preexec_fn,
    )
    stdout, stderr = proc.communicate()
    return {
        "exit_code": proc.returncode,
        "stdout": base64.b64encode(stdout).decode("ascii"),
        "stderr": base64.b64encode(stderr).decode("ascii"),
    }


def _handle_connection(conn: socket.socket) -> None:
    with conn:
        reader = conn.makefile("r", encoding="utf-8")
        raw_request = reader.readline()
        if not raw_request:
            return
        try:
            payload = json.loads(raw_request)
            command = str(payload["command"])
            response = _run_command(command)
        except Exception as exc:
            response = {
                "exit_code": 1,
                "stdout": "",
                "stderr": base64.b64encode(str(exc).encode("utf-8")).decode("ascii"),
            }

        writer = conn.makefile("w", encoding="utf-8")
        writer.write(json.dumps(response, separators=(",", ":")))
        writer.write("\n")
        writer.flush()


def main() -> int:
    server = _prepare_socket(_socket_path())
    try:
        while True:
            conn, _ = server.accept()
            _handle_connection(conn)
    except KeyboardInterrupt:
        return 0
    finally:
        server.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
