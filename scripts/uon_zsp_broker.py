#!/usr/bin/env python3
# Copyright (c) 2026 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Launcher for the native Rust-backed ZSP broker."""

from __future__ import annotations


def main() -> int:
    from uon import core

    core.run_zsp_broker()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
