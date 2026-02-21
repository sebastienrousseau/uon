"""Local configuration and target management.

Persists known remote targets as a JSON array in a platform-appropriate
directory.  You register targets with ``uon add`` and the resulting
entries are consumed by every other uon subsystem (challenge exchange,
FIDO2 enrollment, signed execution).

Security posture:
    **No secret material is ever written to disk.**  The file contains
    only hostnames, ports, usernames, and FIDO2 credential IDs -- all of
    which are public data.  Private keys remain exclusively inside the
    hardware Secure Enclave.

Storage locations (resolved by ``_config_dir()``):

===========  =============================================
Platform     Default path
===========  =============================================
macOS        ``~/Library/Application Support/uon/``
Windows      ``%APPDATA%/uon/``
Linux / WSL  ``$XDG_CONFIG_HOME/uon/`` (or ``~/.config/uon/``)
===========  =============================================
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Self


def _config_dir() -> Path:
    """Resolve and create the platform-appropriate uon config directory.

    The directory is created on first access (``mkdir -p`` semantics).

    Returns:
        Absolute ``Path`` to the config directory.  The directory is
        guaranteed to exist when this function returns.

    Platform behaviour:
        * **macOS** -- ``~/Library/Application Support/uon/``
        * **Windows** -- ``%APPDATA%\\uon\\`` (falls back to ``~/uon/``
          if ``APPDATA`` is unset).
        * **Linux / other** -- ``$XDG_CONFIG_HOME/uon/`` (falls back to
          ``~/.config/uon/`` if the env var is unset).
    """
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / "uon"
    elif sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home())) / "uon"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "uon"
    base.mkdir(parents=True, exist_ok=True)
    return base


CONFIG_DIR: Path = _config_dir()
TARGETS_FILE: Path = CONFIG_DIR / "targets.json"


@dataclass(slots=True)
class Target:
    """A remote machine that uon can reach.

    Each ``Target`` maps a human-friendly *alias* to SSH coordinates and
    an optional list of FIDO2 credential IDs enrolled for that machine.
    Credential IDs are base64-encoded public identifiers -- they do not
    contain secret key material.

    Attributes:
        alias: Short name you use on the command line (e.g. ``"prod"``).
        host:  IPv4 address or hostname of the target.
        port:  SSH port (default ``22``).
        user:  Remote username (default ``"root"``).
        credential_ids: Base64-encoded FIDO2 credential IDs enrolled
            via ``uon register``.  Empty until first enrollment.
    """

    alias: str
    host: str
    port: int = 22
    user: str = "root"
    credential_ids: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Self:
        """Deserialise a ``Target`` from a plain dict (e.g. parsed JSON).

        Missing optional keys fall back to their dataclass defaults
        (``port=22``, ``user="root"``, ``credential_ids=[]``).

        Args:
            data: Dictionary with at least ``"alias"`` and ``"host"``
                keys.  Extra keys are silently ignored.

        Returns:
            A fully-initialised ``Target`` instance.
        """
        return cls(
            alias=str(data["alias"]),
            host=str(data["host"]),
            port=int(data.get("port", 22)),  # type: ignore[arg-type]
            user=str(data.get("user", "root")),
            credential_ids=[str(c) for c in data.get("credential_ids", [])],  # type: ignore[union-attr]
        )


class TargetStore:
    """Thin persistence layer around the targets JSON file.

    You create a ``TargetStore`` to add, look up, list, or remove
    ``Target`` entries.  Every mutation is immediately flushed to disk
    via an atomic write (write to ``.tmp``, then ``os.replace``), so the
    file is never in a half-written state.

    The store is **not** thread-safe.  CLI commands are single-threaded,
    so this is acceptable for the current architecture.

    Args:
        path: Filesystem path to the JSON file.  Defaults to the
            module-level ``TARGETS_FILE`` (inside the platform config
            directory).  Pass a custom path in tests to isolate state.
    """

    def __init__(self, path: Path = TARGETS_FILE) -> None:
        """Load existing targets from *path*, creating an empty store if the file is absent."""
        self._path = path
        self._targets: dict[str, Target] = {}
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_targets(self) -> list[Target]:
        """Return every registered target.

        Returns:
            A new list of all ``Target`` objects.  Returns an empty list
            if no targets have been registered.
        """
        return list(self._targets.values())

    def get(self, alias: str) -> Target | None:
        """Look up a target by its human-friendly alias.

        Args:
            alias: The short name passed on the command line.

        Returns:
            The matching ``Target``, or ``None`` if no target with that
            alias is registered.
        """
        return self._targets.get(alias)

    def add(self, target: Target) -> None:
        """Register a target, overwriting any previous entry with the same alias.

        The change is flushed to disk immediately via an atomic write.

        Args:
            target: The ``Target`` to persist.  If a target with the
                same ``alias`` already exists, it is silently replaced.
        """
        self._targets[target.alias] = target
        self._save()

    def remove(self, alias: str) -> bool:
        """Remove a target by alias and flush the change to disk.

        Args:
            alias: The short name of the target to delete.

        Returns:
            ``True`` if a target with that alias existed and was removed;
            ``False`` if no such target was found (no-op).
        """
        if alias in self._targets:
            del self._targets[alias]
            self._save()
            return True
        return False

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Deserialise all targets from the JSON file into ``_targets``."""
        if not self._path.exists():
            return
        with self._path.open("r", encoding="utf-8") as fh:
            raw: list[dict[str, object]] = json.load(fh)
        for entry in raw:
            t = Target.from_dict(entry)
            self._targets[t.alias] = t

    def _save(self) -> None:
        """Atomically write all targets to disk (write to ``.tmp``, then ``os.replace``)."""
        payload = [asdict(t) for t in self._targets.values()]
        tmp = self._path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        tmp.replace(self._path)
