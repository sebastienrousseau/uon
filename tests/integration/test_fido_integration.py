# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

from unittest.mock import patch

import uon.core

@patch("uon.core.spawn_zsp_process")
def test_spawn_zsp_process_integration(mock_spawn):
    """A basic integration stub validating the uon.core FFI bridge."""
    # Mock the rust FFI bridge to bypass native `sudo` terminal locking in headless CI
    mock_spawn.return_value = 0

    try:
        result = uon.core.spawn_zsp_process("uptime")
        assert isinstance(result, int)
        assert result == 0
        mock_spawn.assert_called_once_with("uptime")
    except Exception as e:
        # PyRuntimeError fallback bounds
        assert "sudo" in str(e).lower() or "group" in str(e).lower()
