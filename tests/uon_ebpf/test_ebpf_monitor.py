# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Tests for the eBPF Kernel Execution Monitor."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from uon_ebpf.ebpf_monitor import KernelMonitor


class TestKernelMonitor:
    def test_native_bcc_import(self) -> None:
        import importlib
        import sys
        from unittest.mock import MagicMock

        import uon_ebpf.ebpf_monitor as em

        mock_bcc = MagicMock()
        mock_bcc.BPF = MagicMock
        sys.modules["bcc"] = mock_bcc

        try:
            importlib.reload(em)
            assert em.HAS_BCC is True
        finally:
            del sys.modules["bcc"]
            importlib.reload(em)

    @patch("uon_ebpf.ebpf_monitor.HAS_BCC", False)
    def test_attach_without_bcc(self) -> None:
        monitor = KernelMonitor()
        monitor._os = "Linux"  # Simulate Linux environment

        # Should exit gracefully without raising exception
        monitor.attach()
        assert monitor.bpf is None

    def test_attach_non_linux(self) -> None:
        monitor = KernelMonitor()
        monitor._os = "Darwin"

        # Should exit gracefully on macOS
        monitor.attach()
        assert monitor.bpf is None

    @patch("uon_ebpf.ebpf_monitor.HAS_BCC", True)
    @patch("uon_ebpf.ebpf_monitor.BPF")
    def test_attach_success(self, mock_bpf_cls: MagicMock) -> None:
        mock_bpf = mock_bpf_cls.return_value
        mock_bpf.get_syscall_fnname.return_value = "sys_execve"

        monitor = KernelMonitor()
        monitor._os = "Linux"

        monitor.attach()
        mock_bpf.attach_kprobe.assert_called_once_with(
            event="sys_execve", fn_name="restrict_execve"
        )

    @patch("uon_ebpf.ebpf_monitor.HAS_BCC", True)
    @patch("uon_ebpf.ebpf_monitor.BPF")
    def test_attach_exception(self, mock_bpf_cls: MagicMock) -> None:
        mock_bpf_cls.side_effect = Exception("Compile error")
        monitor = KernelMonitor()
        monitor._os = "Linux"

        # Exception should be caught and logged
        monitor.attach()
        assert monitor.bpf is None

    def test_monitor_pid_no_bpf(self) -> None:
        monitor = KernelMonitor()
        monitor.bpf = None

        # Should gracefully ignore without crashing
        monitor.monitor_pid(1234)

    @patch("uon_ebpf.ebpf_monitor.HAS_BCC", True)
    @patch("uon_ebpf.ebpf_monitor.BPF")
    def test_monitor_pid_success(self, mock_bpf_cls: MagicMock) -> None:
        mock_bpf = mock_bpf_cls.return_value
        mock_table = MagicMock()
        mock_bpf.get_table.return_value = mock_table

        mock_key = MagicMock()
        mock_bpf.Key.return_value = mock_key
        mock_leaf = MagicMock()
        mock_bpf.Leaf.return_value = mock_leaf

        monitor = KernelMonitor()
        monitor.bpf = mock_bpf

        monitor.monitor_pid(4567)
        mock_bpf.get_table.assert_called_once_with("authorized_pids")
        mock_bpf.Key.assert_called_once_with(4567)
        mock_bpf.Leaf.assert_called_once_with(0)
        mock_table.__setitem__.assert_called_once_with(mock_key, mock_leaf)
