# Copyright (c) 2024 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""AAGUID-based attestation policy for FIDO2 credential enrollment.

When the policy file contains at least one AAGUID the policy is
*enforcing*: only credentials created by listed authenticators (and not
flagged as backup-eligible / synced passkeys) are accepted during
``uon register``.

When the file is absent or empty the policy is *open* and all
authenticators are allowed -- suitable for personal-use deployments
where restricting hardware is unnecessary.

Storage location: ``allowed_aaguids.json`` in the same config directory
as ``targets.json`` (see ``config._config_dir()``).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from uon.utils.config import CONFIG_DIR

POLICY_FILE: Path = CONFIG_DIR / "allowed_aaguids.json"

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def is_valid_aaguid(value: str) -> bool:
    """Check whether *value* is a valid UUID-formatted AAGUID string.

    Args:
        value: Candidate string to validate.

    Returns:
        ``True`` if *value* matches the canonical 8-4-4-4-12 hex UUID
        pattern (case-insensitive); ``False`` otherwise.
    """
    return bool(_UUID_RE.match(value))


class PolicyStore:
    """Persistence layer for the AAGUID allowlist.

    Mirrors the atomic-write pattern used by ``TargetStore``.

    Args:
        path: Filesystem path to the JSON file.  Defaults to the
            module-level ``POLICY_FILE``.  Pass a custom path in tests
            to isolate state.
    """

    def __init__(self, path: Path = POLICY_FILE) -> None:
        self._path = path
        self._aaguids: set[str] = set()
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_enforcing(self) -> bool:
        """``True`` when at least one AAGUID is in the allowlist."""
        return len(self._aaguids) > 0

    def add(self, aaguid: str) -> bool:
        """Add an AAGUID to the allowlist.

        Args:
            aaguid: UUID-formatted AAGUID string.

        Returns:
            ``True`` if the AAGUID was newly added; ``False`` if it was
            already present.
        """
        normalised = aaguid.lower()
        if normalised in self._aaguids:
            return False
        self._aaguids.add(normalised)
        self._save()
        return True

    def remove(self, aaguid: str) -> bool:
        """Remove an AAGUID from the allowlist.

        Args:
            aaguid: UUID-formatted AAGUID string.

        Returns:
            ``True`` if the AAGUID was found and removed; ``False`` if
            it was not present.
        """
        normalised = aaguid.lower()
        if normalised not in self._aaguids:
            return False
        self._aaguids.discard(normalised)
        self._save()
        return True

    def clear(self) -> int:
        """Remove all AAGUIDs from the allowlist.

        Returns:
            The number of AAGUIDs that were removed.
        """
        count = len(self._aaguids)
        self._aaguids.clear()
        self._save()
        return count

    def list_aaguids(self) -> list[str]:
        """Return all AAGUIDs in the allowlist, sorted.

        Returns:
            A sorted list of lowercase UUID strings.
        """
        return sorted(self._aaguids)

    def is_allowed(self, aaguid: str) -> bool:
        """Check whether an AAGUID is in the allowlist (case-insensitive).

        Args:
            aaguid: UUID-formatted AAGUID string to check.

        Returns:
            ``True`` if present; ``False`` otherwise.
        """
        return aaguid.lower() in self._aaguids

    def check_credential(self, aaguid: str, backup_eligible: bool) -> str | None:
        """Validate a credential against the current policy.

        Args:
            aaguid:          UUID-formatted AAGUID from the authenticator.
            backup_eligible: Whether the credential is flagged as
                             backup-eligible (synced passkey).

        Returns:
            ``None`` if the credential is allowed; a descriptive error
            string if it is rejected.
        """
        # Enterprise Attestation Strict Enforcement:
        # Synced passkeys (Apple iCloud, Bitwarden) are inherently extractable and
        # unconditionally violate the zero-trust hardware-bound mandate.
        if backup_eligible:
            return (
                "Enterprise Attestation violation: credential is backup-eligible (synced passkey). "
                "Only strictly hardware-bound credentials are permitted."
            )

        if not self.is_enforcing:
            return None

        if not self.is_allowed(aaguid):
            if aaguid == "00000000-0000-0000-0000-000000000000":
                return (
                    "Policy rejection: authenticator reported a zero AAGUID. "
                    "This usually means attestation is not available. "
                    "Add the zero AAGUID to the policy to allow it explicitly."
                )
            return (
                f"Policy rejection: AAGUID {aaguid} is not in the allowlist. "
                f"Run 'uon policy add {aaguid}' to trust this authenticator."
            )

        return None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Deserialise the allowlist from the JSON file."""
        if not self._path.exists():
            return
        with self._path.open("r", encoding="utf-8") as fh:
            raw: list[str] = json.load(fh)
        self._aaguids = {a.lower() for a in raw}

    def _save(self) -> None:
        """Atomically write the allowlist to disk."""
        import sys as _sys

        payload = sorted(self._aaguids)
        tmp = self._path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        # Restrict permissions before replacing to prevent information disclosure.
        if _sys.platform != "win32":
            tmp.chmod(0o600)
        os.replace(tmp, self._path)
