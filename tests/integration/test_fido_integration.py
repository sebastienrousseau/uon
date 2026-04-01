# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

import pytest

from uon.core import spawn_zsp_process


def test_spawn_zsp_process_integration() -> None:
    """A basic integration stub validating the uon.core FFI bridge."""
    try:
        # Test a simple internal logic hook without actually spawning processes
        # in CI/CD unless explicit permissions are granted.
        result = spawn_zsp_process("uptime")
        assert isinstance(result, int)
    except Exception:
        with pytest.raises(Exception, match=r"(?i)sudo|group"):
            spawn_zsp_process("uptime")
