# Copyright (c) 2026 Sebastien Rousseau
# Licensed under the MIT License.

"""Pre-execution static analysis for explainable blast radius."""

from __future__ import annotations

import re
import click

# Define deterministic heuristics for common destructive or far-reaching commands
_HIGH_IMPACT_PATTERNS = [
    re.compile(r"rm\s+-r?[fF]"),
    re.compile(r"chmod\s+-R\s+777"),
    re.compile(r"chown\s+-R"),
    re.compile(r"mkfs.*"),
    re.compile(r"dd\s+if=.*of=/dev/"),
]

_NETWORK_PATTERNS = [
    re.compile(r"curl\s+.*\|.*sh"),
    re.compile(r"wget\s+.*\|.*sh"),
    re.compile(r"nc\s+-e"),
]

def evaluate_blast_radius(command: str) -> str:
    """Evaluates the command string and calculates the expected blast radius.
    
    Args:
        command: The plaintext shell command intended for execution.
        
    Returns:
        A human-readable string explaining the risk category. Returns 
        'WARN: Blast radius unknown' if parsing faults.
    """
    try:
        impacts: list[str] = []
        
        if any(p.search(command) for p in _HIGH_IMPACT_PATTERNS):
            impacts.append("HIGH RISK: Destructive file mapping or permission alterations detected.")
            
        if any(p.search(command) for p in _NETWORK_PATTERNS):
            impacts.append("HIGH RISK: Arbitrary network execution piping detected.")
            
        if "sudo" in command.lower():
            impacts.append("MEDIUM RISK: Contains nested escalation directives.")

        if not impacts:
            return "LOW RISK: Standard functional execution profile."
            
        return " | ".join(impacts)
    except Exception:
        return "WARN: Blast radius unknown"

def display_blast_radius(command: str) -> None:
    """Renders the blast radius interactively before execution."""
    radius = evaluate_blast_radius(command)
    if "HIGH RISK" in radius:
        click.secho(f"\n[BLAST RADIUS] {radius}", fg="red", bold=True)
    elif "MEDIUM" in radius:
        click.secho(f"\n[BLAST RADIUS] {radius}", fg="yellow")
    elif "WARN" in radius:
        click.secho(f"\n[BLAST RADIUS] {radius}", fg="magenta")
    else:
        click.secho(f"\n[BLAST RADIUS] {radius}", fg="green")
