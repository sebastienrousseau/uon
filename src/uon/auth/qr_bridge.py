"""QR-code fallback bridge for FIDO2 signing via a mobile device.

You use this module when no local platform authenticator is available
(MacBook lid closed, WSL without a Windows Hello bridge, headless Linux
without a USB key).  The CLI spawns an **ephemeral, LAN-only** FastAPI
server that:

1. Displays an ASCII QR code in the terminal pointing your phone to
   ``http://<lan-ip>:8080/sign?token=<bearer>``.
2. Serves a minimal WebAuthn HTML page that invokes
   ``navigator.credentials.get()`` on the phone's Secure Enclave.
3. Receives the signed assertion via a ``POST /callback``.
4. Immediately shuts down.

Network boundary:
    The server binds to ``0.0.0.0:8080`` but enforces **three** layers
    of access control:

    ====================  ================================================
    Layer                 Mechanism
    ====================  ================================================
    CORS origin regex     Only ``10.*``, ``172.16-31.*``, ``192.168.*``
                          origins are allowed.
    Source IP guard        ``_check_private()`` rejects any request whose
                          ``client.host`` is not in an RFC 1918 range.
    Bearer token          A 32-byte ``os.urandom`` token is embedded in
                          the QR URL; the phone must present it as either
                          an ``Authorization: Bearer`` header or a
                          ``?token=`` query parameter.
    ====================  ================================================

Lifecycle:
    The server self-terminates after receiving **one** valid assertion
    **or** after a configurable timeout (default 120 s).  The uvicorn
    server runs in a daemon thread and is joined with a 3-second grace
    period on shutdown.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
from typing import Any

import qrcode  # type: ignore[import-untyped]
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BRIDGE_PORT = 8080
BRIDGE_TIMEOUT_SECONDS = 120

# ---------------------------------------------------------------------------
# Networking helpers
# ---------------------------------------------------------------------------

_PRIVATE_RE = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)")


def _get_lan_ip() -> str:
    """Discover the machine's LAN-facing IPv4 address.

    Opens a UDP socket aimed at a non-routable address (``10.255.255.255``)
    and inspects the socket's own address.  No packets are actually sent.

    Returns:
        The LAN IP as a dotted-quad string (e.g. ``"192.168.1.42"``).
        Falls back to ``"127.0.0.1"`` if the network is unreachable.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        ip: str = sock.getsockname()[0]
    except OSError:
        ip = "127.0.0.1"
    finally:
        sock.close()
    return ip


def _is_private_ip(ip: str) -> bool:
    """Check whether an IPv4 address belongs to a private (RFC 1918) range.

    Uses ``ipaddress.ip_address().is_private`` which covers ``10.0.0.0/8``,
    ``172.16.0.0/12``, ``192.168.0.0/16``, and the loopback range.

    Args:
        ip: Dotted-quad IPv4 string.

    Returns:
        ``True`` if private; ``False`` for public addresses or
        unparseable strings.
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# One-shot QR bridge
# ---------------------------------------------------------------------------


class QrBridgeResult:
    """Thread-safe container for the assertion returned by the mobile device.

    The FastAPI callback handler calls ``set_assertion()`` from the
    uvicorn worker thread; the main thread calls ``wait()`` to block
    until the result arrives.  Synchronisation is via a
    ``threading.Event``.

    Attributes:
        assertion_json: The raw JSON dict POSTed by the phone, or
            ``None`` if no assertion has been received yet.
        error: An error message string, or ``None``.
    """

    def __init__(self) -> None:
        """Initialise an empty result container with an unset ``threading.Event``."""
        self._event = threading.Event()
        self.assertion_json: dict[str, Any] | None = None
        self.error: str | None = None

    def set_assertion(self, data: dict[str, Any]) -> None:
        """Store the signed assertion and unblock any waiting thread.

        Args:
            data: The JSON body from ``POST /callback`` containing
                ``credentialId``, ``authenticatorData``,
                ``clientDataJSON``, and ``signature``.
        """
        self.assertion_json = data
        self._event.set()

    def set_error(self, msg: str) -> None:
        """Store an error message and unblock any waiting thread.

        Args:
            msg: Human-readable error description.
        """
        self.error = msg
        self._event.set()

    def wait(self, timeout: float = BRIDGE_TIMEOUT_SECONDS) -> bool:
        """Block until an assertion (or error) arrives, or timeout elapses.

        Args:
            timeout: Maximum seconds to wait (default 120).

        Returns:
            ``True`` if the event was set (assertion or error received);
            ``False`` if the timeout expired.
        """
        return self._event.wait(timeout=timeout)


def _build_app(
    challenge_b64: str,
    rp_id: str,
    credential_ids_b64: list[str],
    bearer_token: str,
    result: QrBridgeResult,
    shutdown_event: asyncio.Event | None = None,
) -> FastAPI:
    """Construct the ephemeral FastAPI application for the QR bridge.

    The returned app exposes two routes:

    * ``GET /sign`` -- serves a minimal WebAuthn HTML page that calls
      ``navigator.credentials.get()`` on the phone.
    * ``POST /callback`` -- receives the signed assertion JSON, stores
      it in *result*, and signals the server to shut down.

    Both routes are guarded by ``_check_private()`` (source IP must be
    RFC 1918) and ``_check_token()`` (bearer token must match).

    Args:
        challenge_b64:       Base64-encoded challenge nonce.
        rp_id:               FIDO2 relying-party identifier.
        credential_ids_b64:  List of base64-encoded credential IDs.
        bearer_token:        One-time token embedded in the QR URL.
        result:              Thread-safe container to receive the
                             assertion.
        shutdown_event:      Optional ``asyncio.Event`` set after a
                             successful callback to signal the server
                             to stop.

    Returns:
        A configured ``FastAPI`` instance (no ``/docs``, no ``/openapi``).
    """

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    # -- CORS: only private networks --
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"^https?://(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)(:\d+)?$",
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=0,
    )

    # -- Bearer-token guard --
    def _check_token(request: Request) -> None:
        """Reject requests that lack a valid bearer token in header or query param."""
        auth = request.headers.get("Authorization", "")
        query_token = request.query_params.get("token")
        if auth != f"Bearer {bearer_token}" and query_token != bearer_token:
            raise HTTPException(status_code=403, detail="Invalid token")

    # -- Client IP guard --
    def _check_private(request: Request) -> None:
        """Reject requests originating from non-RFC-1918 source IP addresses."""
        client_ip = request.client.host if request.client else "0.0.0.0"  # noqa: S104
        if not _is_private_ip(client_ip):
            raise HTTPException(status_code=403, detail="Non-private source IP rejected")

    # -- Routes --------------------------------------------------------

    @app.get("/sign", response_class=HTMLResponse)
    async def sign_page(request: Request) -> HTMLResponse:
        """Serve the minimal WebAuthn signing page."""
        _check_private(request)
        _check_token(request)

        allow_credentials_js = json.dumps(
            [{"type": "public-key", "id": cid} for cid in credential_ids_b64]
        )

        html = f"""\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>uon — Sign Challenge</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 480px; margin: 2rem auto;
         padding: 1rem; background: #0d1117; color: #c9d1d9; }}
  button {{ font-size: 1.4rem; padding: .8rem 2rem; border: none; border-radius: 8px;
            background: #238636; color: #fff; cursor: pointer; width: 100%; }}
  button:disabled {{ opacity: .5; cursor: wait; }}
  #status {{ margin-top: 1rem; text-align: center; }}
</style>
</head>
<body>
<h2>uon &mdash; FIDO2 Sign</h2>
<p>Tap the button below to sign the challenge with your device&rsquo;s
Secure Enclave.</p>
<button id="signBtn">Sign with Passkey</button>
<div id="status"></div>
<script>
const challenge = Uint8Array.from(atob("{challenge_b64}"), c => c.charCodeAt(0));
const allowCredentials = {allow_credentials_js}.map(c => ({{
    type: c.type,
    id: Uint8Array.from(atob(c.id), b => b.charCodeAt(0)),
}}));
const rpId = "{rp_id}";
const token = "{bearer_token}";

document.getElementById("signBtn").addEventListener("click", async () => {{
    const btn = document.getElementById("signBtn");
    const status = document.getElementById("status");
    btn.disabled = true;
    status.textContent = "Waiting for biometric\u2026";
    try {{
        const cred = await navigator.credentials.get({{
            publicKey: {{
                challenge,
                rpId,
                allowCredentials,
                userVerification: "required",
                timeout: 60000,
            }},
        }});
        const body = {{
            credentialId: btoa(String.fromCharCode(
                ...new Uint8Array(cred.rawId))),
            authenticatorData: btoa(String.fromCharCode(
                ...new Uint8Array(cred.response.authenticatorData))),
            clientDataJSON: btoa(String.fromCharCode(
                ...new Uint8Array(cred.response.clientDataJSON))),
            signature: btoa(String.fromCharCode(
                ...new Uint8Array(cred.response.signature))),
            userHandle: cred.response.userHandle
                ? btoa(String.fromCharCode(...new Uint8Array(cred.response.userHandle)))
                : null,
        }};
        const resp = await fetch("/callback", {{
            method: "POST",
            headers: {{
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token,
            }},
            body: JSON.stringify(body),
        }});
        if (resp.ok) {{
            status.textContent = "Signed! You can close this page.";
            btn.textContent = "Done";
        }} else {{
            status.textContent = "Server rejected the assertion.";
            btn.disabled = false;
        }}
    }} catch (err) {{
        status.textContent = "Error: " + err.message;
        btn.disabled = false;
    }}
}});
</script>
</body></html>"""
        return HTMLResponse(content=html)

    @app.post("/callback")
    async def callback(request: Request) -> JSONResponse:
        """Receive the signed WebAuthn assertion from the mobile device."""
        _check_private(request)
        _check_token(request)
        body = await request.json()

        required_keys = {"credentialId", "authenticatorData", "clientDataJSON", "signature"}
        if not required_keys.issubset(body.keys()):
            raise HTTPException(status_code=422, detail="Missing assertion fields")

        result.set_assertion(body)

        # Signal the server to shut down.
        if shutdown_event is not None:
            shutdown_event.set()

        return JSONResponse({"status": "ok"})

    return app


def _print_qr(url: str) -> None:
    """Render a URL as an ASCII QR code on stderr.

    Uses medium error-correction (``ERROR_CORRECT_M``) for readability
    on phone cameras.  The URL is also printed as plain text below the
    QR code for manual entry.

    Args:
        url: The full URL to encode (e.g.
             ``"http://192.168.1.42:8080/sign?token=..."``).
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=1,
        border=2,
    )
    qr.add_data(url)
    qr.make(fit=True)
    qr.print_ascii(out=sys.stderr)
    print(f"\nOr open: {url}\n", file=sys.stderr)


class _ServerThread(threading.Thread):
    """Run uvicorn in a daemon thread with controlled shutdown.

    The thread is marked ``daemon=True`` so it does not prevent the
    process from exiting if the main thread terminates unexpectedly.
    Call ``shutdown()`` followed by ``join(timeout=3)`` for a graceful
    stop.

    Args:
        app:  The FastAPI application to serve.
        host: Bind address (typically ``"0.0.0.0"``).
        port: Bind port (typically ``BRIDGE_PORT``).
    """

    def __init__(self, app: FastAPI, host: str, port: int) -> None:
        """Configure a daemon thread with a uvicorn server bound to *host:port*."""
        super().__init__(daemon=True)
        config = uvicorn.Config(
            app,
            host=host,
            port=port,
            log_level="error",
            access_log=False,
        )
        self.server = uvicorn.Server(config)

    def run(self) -> None:
        """Start the uvicorn event loop (called automatically by ``Thread.start()``)."""
        self.server.run()

    def shutdown(self) -> None:
        """Signal the uvicorn server to exit after the current request completes."""
        self.server.should_exit = True


def request_signature_via_qr(
    challenge: bytes,
    rp_id: str,
    credential_ids: list[bytes],
    timeout: float = BRIDGE_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Display a QR code and wait for a mobile device to sign the challenge.

    This is the public entry point for the QR bridge fallback.  It
    orchestrates the full lifecycle: generate a bearer token, build the
    ephemeral FastAPI app, start a uvicorn daemon thread, print the QR
    code, wait for the phone to POST the signed assertion, shut down the
    server, and return the assertion dict.

    Args:
        challenge:      Raw nonce bytes from
                        ``ssh_client.request_challenge()``.
        rp_id:          FIDO2 relying-party ID (e.g. ``"uon.local"``).
        credential_ids: Allowed credential IDs (raw bytes) from the
                        ``TargetStore``.
        timeout:        Maximum seconds to wait for the phone
                        (default 120).

    Returns:
        The JSON assertion body POSTed by the phone -- a dict containing
        ``credentialId``, ``authenticatorData``, ``clientDataJSON``,
        ``signature``, and optionally ``userHandle``, all
        base64-encoded strings.

    Raises:
        TimeoutError: If the phone does not respond within *timeout*
            seconds.  The server is shut down before the exception
            propagates.
        RuntimeError: If the phone reports an error (e.g. user
            cancellation or WebAuthn failure).

    Security:
        * The bearer token is 32 bytes of ``os.urandom``, URL-safe
          base64-encoded.
        * The server binds to ``0.0.0.0`` but enforces RFC 1918 source
          IP checks and CORS origin restrictions.
        * The server is shut down and joined (3 s grace) regardless of
          outcome.
    """
    challenge_b64 = base64.b64encode(challenge).decode()
    cred_ids_b64 = [base64.b64encode(c).decode() for c in credential_ids]
    bearer_token = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")

    result = QrBridgeResult()
    shutdown_event = asyncio.Event()

    app = _build_app(
        challenge_b64=challenge_b64,
        rp_id=rp_id,
        credential_ids_b64=cred_ids_b64,
        bearer_token=bearer_token,
        result=result,
        shutdown_event=shutdown_event,
    )

    lan_ip = _get_lan_ip()
    url = f"http://{lan_ip}:{BRIDGE_PORT}/sign?token={bearer_token}"

    server_thread = _ServerThread(app, host="0.0.0.0", port=BRIDGE_PORT)  # noqa: S104
    server_thread.start()

    # Give the server a moment to bind.
    time.sleep(0.4)

    print("\n--- uon QR Bridge ---", file=sys.stderr)
    print("Scan the QR code below with your phone to sign the challenge.\n", file=sys.stderr)
    _print_qr(url)

    got_result = result.wait(timeout=timeout)

    server_thread.shutdown()
    server_thread.join(timeout=3)

    if not got_result:
        raise TimeoutError(f"No assertion received from mobile device within {timeout}s.")

    if result.error is not None:
        raise RuntimeError(f"QR bridge error: {result.error}")

    assert result.assertion_json is not None  # noqa: S101 — guaranteed by event
    return result.assertion_json
