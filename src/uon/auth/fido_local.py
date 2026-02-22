# Copyright (c) 2024 Sebastien Rousseau
#
# Licensed under the GNU AGPLv3 License. See LICENSE file in the project root
# for full license information.

"""Platform-local FIDO2 biometric signing (Touch ID / Windows Hello / USB key).

You use this module to create and exercise FIDO2 resident-key credentials
that live exclusively inside your device's hardware Secure Enclave.  No
private key material ever touches disk or process memory -- every
cryptographic operation is delegated to the platform authenticator.

Typical call sequence:

1. **One-time enrollment** -- ``register(user_id, user_name)`` triggers a
   biometric prompt, generates a resident key inside the enclave, and
   returns the attestation object + credential ID.  You store the
   credential ID in the ``TargetStore``; the public key is installed on
   the remote target.
2. **Per-command signing** -- ``authenticate(challenge, credential_ids)``
   presents the server-issued nonce to the authenticator, which signs it
   after biometric verification.  The resulting assertion is bundled into
   the ``__UON_EXEC__`` envelope by the transport layer.

Platform-specific authenticator resolution (``_discover_client``):

============  =============================================================
Platform      Behaviour
============  =============================================================
macOS         Tries Touch ID via ``MacOSClient``.  Falls back to USB HID
              if Touch ID is unavailable (e.g., lid closed on a MacBook
              connected to an external display).
Windows       Tries Windows Hello via ``WindowsClient``.  Falls back to
              USB HID if Hello is not configured or not available.
Linux / WSL   Directly probes USB HID (YubiKey, SoloKey, etc.).  There is
              no platform authenticator on Linux; if no USB device is
              found, the caller degrades to the QR bridge.
============  =============================================================

Security invariants:
    * The relying party ID (``RP_ID``) is ``"uon.local"`` -- a non-
      routable domain that prevents phishing redirects.
    * ``ResidentKeyRequirement.REQUIRED`` ensures the credential is
      discoverable without a server-side allow-list.
    * ``UserVerificationRequirement.REQUIRED`` forces biometric or PIN
      verification on every operation.
"""

from __future__ import annotations

import platform
import sys
from typing import TYPE_CHECKING, NamedTuple

from fido2.client import Fido2Client, UserInteraction
from fido2.hid import CtapHidDevice
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

if TYPE_CHECKING:
    from fido2.webauthn import AuthenticatorAssertionResponse, AuthenticatorData


# ---------------------------------------------------------------------------
# Relying-party defaults
# ---------------------------------------------------------------------------

RP_ID = "uon.local"
RP_NAME = "uon — FIDO2 Remote Exec"


class _CliInteraction(UserInteraction):
    """Minimal CLI interaction handler for FIDO2 user prompts.

    Prints touch / biometric prompts to **stderr** so they never
    contaminate command output on stdout.  PIN entry uses
    ``getpass.getpass`` (hidden input, no echo).

    This class is instantiated once per ``_discover_client()`` call and
    passed to the ``fido2`` library's ``Fido2Client`` constructor.
    """

    def prompt_up(self) -> None:
        """Print a touch-prompt to stderr when the authenticator awaits physical contact."""
        print("\n>>> Touch your authenticator device …", file=sys.stderr)

    def request_pin(self, permissions: object, rd_id: str | None = None) -> str:
        """Read the FIDO2 PIN from the terminal with hidden input via ``getpass``."""
        import getpass

        return getpass.getpass("FIDO2 PIN: ")

    def request_uv(self, permissions: object, rd_id: str | None = None) -> bool:
        """Acknowledge a biometric verification request and return ``True`` to proceed."""
        print(">>> Biometric verification requested …", file=sys.stderr)
        return True


# ---------------------------------------------------------------------------
# Client discovery
# ---------------------------------------------------------------------------


class NoPlatformAuthenticatorError(RuntimeError):
    """Raised when no usable FIDO2 authenticator can be found.

    This is the signal that triggers graceful degradation from the local
    biometric path to the QR bridge fallback in ``cli._resolve_signature``.
    """


def _discover_client(rp_id: str) -> Fido2Client:
    """Discover and return a ``Fido2Client`` bound to the best available authenticator.

    Walks the platform-specific resolution order described in the module
    docstring.  Each candidate is tried inside a broad ``except
    Exception`` guard so that a misconfigured or inaccessible
    authenticator never prevents the next candidate from being probed.

    Args:
        rp_id: FIDO2 relying-party identifier (e.g. ``"uon.local"``).
            Used to construct the WebAuthn ``origin``.

    Returns:
        A ``Fido2Client`` ready for ``make_credential`` or
        ``get_assertion`` calls.

    Raises:
        NoPlatformAuthenticatorError: If no platform authenticator
            (Touch ID / Windows Hello) **and** no USB HID security key
            can be found.  Callers should fall back to the QR bridge.

    Resolution order:
        1. **macOS** -- ``MacOSClient`` (Touch ID).
        2. **Windows** -- ``WindowsClient`` (Windows Hello).
        3. **Any platform** -- first connected CTAP HID device.
        4. All candidates exhausted -- raise.
    """
    origin = f"https://{rp_id}"
    interaction = _CliInteraction()

    # -- macOS platform authenticator (Touch ID) --
    if sys.platform == "darwin":
        try:
            from fido2.client import MacOSClient  # type: ignore[attr-defined]

            client = MacOSClient(origin, interaction=interaction)
            return client  # type: ignore[no-any-return]
        except Exception:  # noqa: S110 — intentional silent fallthrough to HID
            pass

    # -- Windows Hello --
    if sys.platform == "win32":
        try:
            from fido2.client import WindowsClient  # type: ignore[attr-defined]

            if WindowsClient.is_available():
                client = WindowsClient(origin, interaction=interaction)
                return client
        except Exception:  # noqa: S110 — intentional silent fallthrough to HID
            pass

    # -- USB HID (YubiKey etc.) --
    devices = list(CtapHidDevice.list_devices())
    if devices:
        return Fido2Client(
            devices[0],
            origin,  # type: ignore[arg-type]
            interaction=interaction,  # type: ignore[call-arg]
        )

    raise NoPlatformAuthenticatorError(
        "No platform authenticator (Touch ID / Windows Hello) or USB security key detected. "
        "Use the QR bridge fallback instead (uon will offer this automatically)."
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _make_rp() -> PublicKeyCredentialRpEntity:
    """Construct the WebAuthn Relying Party entity for uon.

    Returns:
        A ``PublicKeyCredentialRpEntity`` with ``id="uon.local"`` and
        the uon display name.
    """
    return PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)


def _make_server() -> Fido2Server:
    """Construct a ``Fido2Server`` bound to the uon Relying Party.

    Returns:
        A ``Fido2Server`` instance used to orchestrate the WebAuthn
        registration and authentication ceremonies.
    """
    return Fido2Server(_make_rp())


class RegistrationResult(NamedTuple):
    """Rich return type from ``register()`` with attestation metadata.

    Attributes:
        auth_data:       The ``AuthenticatorData`` returned by the server.
        credential_id:   Raw credential ID bytes.
        aaguid:          UUID-formatted string identifying the authenticator model.
        backup_eligible: Whether the credential is flagged as backup-eligible
                         (i.e. a synced passkey).
    """

    auth_data: AuthenticatorData
    credential_id: bytes
    aaguid: str
    backup_eligible: bool


def register(
    user_id: bytes,
    user_name: str,
    rp_id: str = RP_ID,
) -> RegistrationResult:
    """Create a new FIDO2 resident-key credential inside the hardware enclave.

    Triggers a biometric prompt (Touch ID / Windows Hello / USB key tap),
    generates a resident key inside the authenticator's Secure Enclave,
    and returns a ``RegistrationResult`` containing the authenticator
    data, credential ID, AAGUID, and backup-eligibility flag.

    Args:
        user_id:   Opaque identifier for the user (typically 32 bytes
                   of ``os.urandom``).
        user_name: Human-readable display name shown on the
                   authenticator's credential picker.
        rp_id:     FIDO2 relying-party identifier (default
                   ``"uon.local"``).

    Returns:
        A ``RegistrationResult`` with ``auth_data``, ``credential_id``,
        ``aaguid``, and ``backup_eligible``.

    Raises:
        NoPlatformAuthenticatorError: If no usable authenticator is
            present (no Touch ID, no Hello, no USB key).

    Platform behaviour:
        * **Linux** -- uses ``AuthenticatorAttachment.CROSS_PLATFORM``
          because there is no OS-level platform authenticator.
        * **macOS / Windows** -- uses ``PLATFORM`` to prefer the
          built-in Secure Enclave.
    """
    client = _discover_client(rp_id)
    server = _make_server()

    user = PublicKeyCredentialUserEntity(
        id=user_id,
        name=user_name,
        display_name=user_name,
    )

    create_options, state = server.register_begin(
        user=user,
        credentials=[],
        authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM
        if platform.system() == "Linux"
        else AuthenticatorAttachment.PLATFORM,
        resident_key_requirement=ResidentKeyRequirement.REQUIRED,
        user_verification=UserVerificationRequirement.REQUIRED,
        attestation=AttestationConveyancePreference.DIRECT,  # type: ignore[call-arg]
    )

    attestation_response = client.make_credential(create_options["publicKey"])
    auth_data = server.register_complete(
        state,
        attestation_response,
    )

    credential_data = auth_data.credential_data
    if credential_data is None:
        raise RuntimeError("Authenticator returned no credential data.")

    credential_id = credential_data.credential_id
    aaguid = str(credential_data.aaguid)
    backup_eligible = auth_data.is_backup_eligible()

    return RegistrationResult(auth_data, credential_id, aaguid, backup_eligible)


def authenticate(
    challenge: bytes,
    credential_ids: list[bytes],
    rp_id: str = RP_ID,
) -> AuthenticatorAssertionResponse:
    """Sign a challenge using a previously-registered resident key.

    Presents the nonce to the platform authenticator, which prompts for
    biometric verification and returns a signed WebAuthn assertion.  The
    server-generated challenge is **overridden** with the remote nonce
    so that the target can verify the signature against the challenge it
    originally issued.

    Args:
        challenge:      Raw nonce bytes from
                        ``ssh_client.request_challenge()``.
        credential_ids: List of allowed credential IDs (raw bytes) from
                        prior ``register()`` calls.
        rp_id:          FIDO2 relying-party identifier (default
                        ``"uon.local"``).

    Returns:
        An ``AuthenticatorAssertionResponse`` containing
        ``credential_id``, ``authenticator_data``, ``client_data``, and
        ``signature`` -- all the fields needed to build the
        ``__UON_EXEC__`` envelope.

    Raises:
        NoPlatformAuthenticatorError: If no local authenticator is
            available.  The CLI catches this and degrades to the QR
            bridge.

    Security:
        * ``UserVerificationRequirement.REQUIRED`` forces biometric or
          PIN verification on every signing operation.
        * Only the first assertion response is returned (single
          authenticator expected).
    """
    client = _discover_client(rp_id)
    server = _make_server()

    allow_list = [
        PublicKeyCredentialDescriptor(
            type=PublicKeyCredentialType.PUBLIC_KEY,
            id=cid,
        )
        for cid in credential_ids
    ]

    request_options, _state = server.authenticate_begin(
        credentials=allow_list,
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    # Override the server-generated challenge with the remote nonce so that
    # the target can verify the signature against the challenge it issued.
    options_dict = dict(request_options["publicKey"])
    options_dict["challenge"] = challenge
    request_options = {"publicKey": options_dict}  # type: ignore[assignment]

    assertion_response = client.get_assertion(request_options["publicKey"])
    # Return the first assertion (single authenticator expected).
    return assertion_response.get_response(0)  # type: ignore[return-value]
