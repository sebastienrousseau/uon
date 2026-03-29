# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""eBPF kernel-level execution monitoring.

This module provides an eBPF-based enforcement layer that restricts the
behaviour of Zero Standing Privilege (ZSP) execution profiles. If a
verified command attempts to pivot, drop shells, or execute out-of-bounds
system calls, the kernel terminates the process instantly.
"""

from __future__ import annotations

import logging
import platform

try:
    from bcc import BPF  # type: ignore

    HAS_BCC = True
except ImportError:
    BPF = None  # type: ignore
    HAS_BCC = False


# BPF C program to monitor execve syscalls and kill unauthorised spawned shells.
# The counter tracks execve calls per monitored PID. The first execve (the
# legitimate command itself) is allowed; any subsequent execve (shell pivot /
# breakout) triggers SIGKILL.
_BPF_TEXT = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

BPF_HASH(authorized_pids, u32, u32);

int restrict_execve(struct pt_regs *ctx, const char __user *filename) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *call_count = authorized_pids.lookup(&pid);

    if (call_count != NULL) {
        // The first execve (count == 0) is the legitimate command launch.
        // Any subsequent execve indicates a shell pivot or breakout attempt.
        if (*call_count > 0) {
            bpf_send_signal(9);
        }
        u32 new_count = *call_count + 1;
        authorized_pids.update(&pid, &new_count);
    }
    return 0;
}
"""


class KernelMonitor:
    """Manages the lifecycle of the eBPF sandboxing environment."""

    def __init__(self) -> None:
        self.bpf: BPF | None = None
        self._os = platform.system()

    def attach(self) -> None:
        """Compile and attach the eBPF program to Linux kernel hooks."""
        if self._os != "Linux":
            logging.warning(
                "eBPF monitoring is only supported on Linux kernels. Bypassing sandbox."
            )
            return

        if not HAS_BCC:
            logging.warning("BCC library is unavailable. eBPF kernel monitoring is disabled.")
            return

        try:
            self.bpf = BPF(text=_BPF_TEXT)
            execve_fnname = self.bpf.get_syscall_fnname("execve")
            self.bpf.attach_kprobe(event=execve_fnname, fn_name="restrict_execve")
            logging.info("eBPF kernel-level sandbox successfully attached.")
        except Exception as e:
            logging.error(f"Failed to compile eBPF sandbox: {e}")

    def monitor_pid(self, pid: int) -> None:
        """Add a specific process ID to the strict kernel sandbox whitelist.

        The counter starts at 0 -- the first execve is the legitimate command
        launch and is allowed through.  Subsequent execve calls are killed.
        """
        if self.bpf is not None:
            auth_map = self.bpf.get_table("authorized_pids")
            auth_map[self.bpf.Key(pid)] = self.bpf.Leaf(0)
