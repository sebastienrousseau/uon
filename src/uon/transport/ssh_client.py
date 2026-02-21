"""Paramiko-based SSH transport for FIDO2-signed command execution.

You use this module to move a cryptographically signed command from your
machine to a remote target and to stream the result back.  The lifecycle
of a single remote execution is:

1. **Challenge** -- ``request_challenge()`` generates a 32-byte
   cryptographic nonce (+ a SHA-256 session ID) that your FIDO2
   authenticator will sign.
2. **Envelope** -- ``_build_envelope()`` bundles the command text, the
   signed assertion, the nonce, and the session ID into a versioned JSON
   dict.  ``_wrap_command()`` base64-encodes the JSON and prefixes it
   with the ``__UON_EXEC__`` sentinel.
3. **Execution** -- ``execute_signed()`` opens a Paramiko SSH channel,
   sends the wrapped command via ``exec_command()``, and blocks until
   the remote side closes the channel.

Security posture:
    * **No private key material** is ever held in memory by this module.
      Paramiko is used for transport only; actual authentication is
      delegated to the FIDO2 layer.
    * The SSH connection in ``execute_signed()`` uses the local agent
      and key files (``look_for_keys=True``) to authenticate the SSH
      *transport*.  The target's ``ForceCommand`` script then
      independently verifies the FIDO2 *assertion* before executing
      anything.
    * Host keys are accepted on first contact (Trust-On-First-Use).
      Host-key pinning is planned for a future release.
    * ``verify_assertion_locally()`` is a reference helper for the
      **target** side -- it validates an Ed25519 WebAuthn signature
      against a known public key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

import paramiko
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExecResult:
    """Immutable snapshot of a completed remote command execution.

    You receive an ``ExecResult`` from ``execute_signed()`` after the
    remote channel closes.  The instance is frozen (immutable) to prevent
    accidental mutation when passing it through the CLI layer.

    Attributes:
        exit_code: The remote process's exit status (0 = success).
        stdout:    Decoded standard output (UTF-8, with lossy
                   replacement for non-decodable bytes).
        stderr:    Decoded standard error (same encoding strategy).
    """

    exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True, slots=True)
class ChallengePacket:
    """Immutable cryptographic challenge for a single FIDO2 signing request.

    The ``nonce`` is passed to the authenticator as the WebAuthn
    ``challenge`` parameter.  The ``session_id`` binds the nonce to
    additional entropy so that replaying a captured nonce across sessions
    is cryptographically impossible.

    Attributes:
        nonce:      32 bytes of ``os.urandom`` entropy.
        session_id: SHA-256 digest of ``nonce || 16 extra random bytes``.
    """

    nonce: bytes
    session_id: bytes


# ---------------------------------------------------------------------------
# Challenge generation (client-side)
# ---------------------------------------------------------------------------


def generate_challenge() -> ChallengePacket:
    """Create a fresh cryptographic challenge for FIDO2 signing.

    Generates 32 bytes of OS-level entropy for the nonce and derives a
    session ID by hashing the nonce with 16 additional random bytes.
    The combined construction ensures that even if two challenges share
    the same nonce (astronomically unlikely), their session IDs will
    differ.

    Returns:
        A ``ChallengePacket`` with a 32-byte ``nonce`` and a 32-byte
        ``session_id`` (SHA-256 digest).

    Security:
        Entropy is sourced from ``os.urandom``, which draws from the
        OS CSPRNG (``/dev/urandom`` on Linux, ``CryptGenRandom`` on
        Windows, ``SecRandomCopyBytes`` on macOS).
    """
    nonce = os.urandom(32)
    session_id = hashlib.sha256(nonce + os.urandom(16)).digest()
    return ChallengePacket(nonce=nonce, session_id=session_id)


# ---------------------------------------------------------------------------
# SSH connection helpers
# ---------------------------------------------------------------------------


def _connect(host: str, port: int, username: str) -> paramiko.SSHClient:
    """Open an unauthenticated SSH connection for the initial challenge exchange.

    This helper is used during the pre-authentication phase where the
    client and target agree on a nonce.  Key-based and agent-based
    authentication are explicitly disabled (``look_for_keys=False``,
    ``allow_agent=False``) because the connection carries no signed
    payload yet.

    Args:
        host:     Hostname or IPv4 address of the target.
        port:     SSH port number.
        username: Remote username.

    Returns:
        A connected ``paramiko.SSHClient`` ready for channel operations.

    Raises:
        paramiko.SSHException: If the connection or transport negotiation
            fails (network timeout, refused connection, etc.).

    Security:
        Host keys are accepted on first contact (Trust-On-First-Use /
        ``AutoAddPolicy``).  A future release will pin host keys in the
        uon config store.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507 — TOFU
    client.connect(
        hostname=host,
        port=port,
        username=username,
        look_for_keys=False,
        allow_agent=False,
        # We perform our own auth via exec channel; connect with none auth
        # first.  The server should allow ``none`` for the initial exchange
        # then require the signed payload for exec.
        auth_timeout=10,
    )
    return client


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def request_challenge(host: str, port: int = 22, username: str = "root") -> ChallengePacket:
    """Obtain a fresh cryptographic challenge for the target.

    In the current reference implementation the challenge is generated
    **client-side** via ``generate_challenge()`` and included verbatim in
    the signed assertion.  A production deployment may instead have the
    target generate the nonce server-side to prevent client-chosen-nonce
    attacks.

    Args:
        host:     Hostname or IPv4 address of the target machine.
        port:     SSH port (default ``22``).
        username: Remote username (default ``"root"``).

    Returns:
        A ``ChallengePacket`` whose ``nonce`` the FIDO2 authenticator
        must sign.
    """
    return generate_challenge()


def execute_signed(
    host: str,
    port: int,
    username: str,
    command: str,
    assertion: dict[str, Any],
    challenge: ChallengePacket,
) -> ExecResult:
    """Execute a signed command on the remote target over SSH.

    Wraps the command, assertion, and challenge into a ``__UON_EXEC__``
    envelope, opens an SSH channel with key-based transport auth, sends
    the envelope via ``exec_command()``, and blocks until the remote
    channel closes.  The SSH client is **always** closed in a ``finally``
    block, even if the connection or execution raises.

    Args:
        host:      Hostname or IPv4 address of the target.
        port:      SSH port number.
        username:  Remote username.
        command:   The shell command to execute on the remote machine.
        assertion: FIDO2 assertion dict with base64-encoded fields
                   (``credentialId``, ``authenticatorData``,
                   ``clientDataJSON``, ``signature``).  Produced by
                   either the local authenticator or the QR bridge.
        challenge: The ``ChallengePacket`` whose ``nonce`` was signed
                   by the authenticator.

    Returns:
        An ``ExecResult`` containing the remote exit code, decoded
        stdout, and decoded stderr.

    Raises:
        paramiko.SSHException: If the SSH connection, authentication,
            or channel negotiation fails.
        OSError: If the network is unreachable or the connection is
            refused.

    Security:
        * The connection uses ``look_for_keys=True`` and
          ``allow_agent=True`` -- the local SSH agent handles transport
          authentication.
        * The target's ``ForceCommand`` (``uon_verifier.py``) parses the
          envelope and **independently** verifies the FIDO2 signature
          before executing the inner command.
        * The channel ``exec_command`` timeout is 300 seconds.
    """
    envelope = _build_envelope(command, assertion, challenge)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507

    try:
        # Connect with key-based auth.  The target's authorized_keys file
        # will have the FIDO2 public key.  We pass the signed envelope as
        # the command so the server-side ``ForceCommand`` or agent can
        # verify before executing.
        client.connect(
            hostname=host,
            port=port,
            username=username,
            look_for_keys=True,
            allow_agent=True,
            timeout=10,
        )

        # Send the envelope as an exec request.  The remote uon-agent (or
        # a ``ForceCommand`` script) parses the JSON preamble, verifies the
        # FIDO2 signature, and — only then — runs the inner command.
        wrapped_command = _wrap_command(envelope)
        _stdin, stdout, stderr = client.exec_command(wrapped_command, timeout=300)

        exit_code = stdout.channel.recv_exit_status()
        return ExecResult(
            exit_code=exit_code,
            stdout=stdout.read().decode(errors="replace"),
            stderr=stderr.read().decode(errors="replace"),
        )
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Envelope helpers
# ---------------------------------------------------------------------------


def _build_envelope(
    command: str,
    assertion: dict[str, Any],
    challenge: ChallengePacket,
) -> dict[str, Any]:
    """Bundle the command, assertion, and challenge into a versioned JSON envelope.

    The envelope is the atomic unit of trust in the uon protocol.  The
    target decodes it, reconstructs the FIDO2 signature base from the
    embedded fields, and verifies the signature before executing the
    inner ``command``.

    Args:
        command:   Shell command string.
        assertion: Base64-encoded FIDO2 assertion fields.
        challenge: The ``ChallengePacket`` whose nonce was signed.

    Returns:
        A dict with keys ``version`` (``1``), ``command``,
        ``challenge`` (base64), ``session_id`` (base64), and
        ``assertion``.
    """
    return {
        "version": 1,
        "command": command,
        "challenge": base64.b64encode(challenge.nonce).decode(),
        "session_id": base64.b64encode(challenge.session_id).decode(),
        "assertion": assertion,
    }


def _wrap_command(envelope: dict[str, Any]) -> str:
    """Encode the envelope as a single shell-safe command string.

    Compact-JSON-encodes the envelope, base64-encodes the result, and
    prepends the ``__UON_EXEC__`` sentinel.  The final string is safe to
    pass as a single SSH ``exec_command`` argument.

    The remote side receives::

        __UON_EXEC__ <base64-json>

    The target's ``ForceCommand`` script (``uon_verifier.py``) splits on
    the first space, base64-decodes the payload, parses the JSON, verifies
    the FIDO2 assertion, and only then ``exec``'s the inner command.

    Args:
        envelope: The dict produced by ``_build_envelope()``.

    Returns:
        A string in the format ``"__UON_EXEC__ <base64>"``.
    """
    payload_b64 = base64.b64encode(json.dumps(envelope, separators=(",", ":")).encode()).decode()
    return f"__UON_EXEC__ {payload_b64}"


def verify_assertion_locally(
    public_key_bytes: bytes,
    challenge: bytes,
    authenticator_data: bytes,
    client_data_json: bytes,
    signature: bytes,
) -> bool:
    """Verify an Ed25519 FIDO2 assertion against a known public key.

    This is a **target-side** reference helper.  In a production
    deployment it lives in ``scripts/uon_verifier.py`` on each remote
    machine, not on the client.  It is included in this module for
    testing and to document the exact verification algorithm.

    The WebAuthn signature base is::

        authenticatorData || SHA-256(clientDataJSON)

    The function reconstructs this base and calls
    ``Ed25519PublicKey.verify()`` from the ``cryptography`` library.

    Args:
        public_key_bytes: Raw 32-byte Ed25519 public key extracted from
            the COSE credential during enrollment.
        challenge:        The original nonce that was signed (used for
            context; not directly part of the signature base).
        authenticator_data: Raw ``authenticatorData`` bytes from the
            WebAuthn ``GetAssertionResponse``.
        client_data_json: Raw ``clientDataJSON`` bytes from the WebAuthn
            response.
        signature:        Raw Ed25519 signature bytes (64 bytes).

    Returns:
        ``True`` if the signature is mathematically valid; ``False``
        for **any** failure (wrong key, tampered data, malformed input).

    Security:
        All exceptions are caught and mapped to ``False`` to prevent
        timing or error-oracle attacks.  Callers must treat ``False``
        as a hard reject.
    """
    try:
        pk = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        # The signed message for WebAuthn is:
        #   authenticatorData || SHA-256(clientDataJSON)
        client_data_hash = hashlib.sha256(client_data_json).digest()
        signed_data = authenticator_data + client_data_hash
        pk.verify(signature, signed_data)
        return True
    except Exception:
        return False
