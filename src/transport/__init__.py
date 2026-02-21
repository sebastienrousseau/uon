"""SSH transport layer for signed-payload execution.

This package handles every network operation between your machine and the
remote target.  Data flows through three stages:

1. **Challenge** -- ``ssh_client.request_challenge()`` generates a
   cryptographic nonce that the FIDO2 authenticator must sign.
2. **Envelope** -- ``ssh_client._build_envelope()`` bundles the command,
   signed assertion, nonce, and session ID into a JSON document, then
   ``_wrap_command()`` base64-encodes it as ``__UON_EXEC__ <payload>``.
3. **Execution** -- ``ssh_client.execute_signed()`` sends the wrapped
   command over a Paramiko SSH channel.  The target's ``ForceCommand``
   (``uon_verifier.py``) decodes the envelope, verifies the FIDO2
   signature, and only then executes the inner command.

Security posture:

* No private key material is held in memory by this layer.
* Host keys use Trust-On-First-Use (TOFU), consistent with standard
  ``ssh`` behaviour.  Host-key pinning is planned for a future release.
* The SSH connection for ``execute_signed`` uses the local SSH agent
  and key files (``look_for_keys=True``); the connection for
  ``_connect`` (used during initial challenge exchange) does not.
"""
