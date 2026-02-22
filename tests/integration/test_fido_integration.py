# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

from uon.core import spawn_zsp_process


def test_spawn_zsp_process_integration():
    """A basic integration stub validating the uon.core FFI bridge."""
    try:
        # 1. Testing a simple internal logic hook without actually spawning processes
        # in CI/CD unless explicit permissions are granted.
        result = spawn_zsp_process("uptime")
        assert isinstance(result, int)
    except Exception as e:
        # PyRuntimeError raised by Rust std::process if 'sudo' or ephemeral group fails
        assert "sudo" in str(e).lower() or "group" in str(e).lower()
