# uon — FIDO2-Signed Remote Terminal Execution

**uon** replaces password- and key-file-based SSH authentication with
hardware-bound FIDO2 passkeys.  Every remote command is cryptographically
signed by your device's Secure Enclave (Touch ID, Windows Hello, or a USB
security key) before the target machine will execute it.  No private key
material ever touches disk.

## Features

- **Zero-disk secrets** — private keys live exclusively inside hardware
  secure enclaves; nothing is written to `~/.ssh` or any config file.
- **Per-command signing** — every remote execution requires a fresh
  biometric or physical-touch approval.
- **QR bridge fallback** — when no local authenticator is available (lid
  closed, headless Linux), a temporary LAN-only web server lets your phone
  sign the challenge via its own Secure Enclave.
- **Challenge-response protocol** — a unique nonce prevents replay attacks
  across sessions.
- **Trust-On-First-Use (TOFU)** — host keys are accepted on first contact,
  consistent with standard SSH behaviour.

## Prerequisites

- Python 3.12+
- A FIDO2-capable authenticator (Touch ID, Windows Hello, YubiKey, SoloKey, etc.)
- SSH access to the target machine

## Installation

```bash
# Clone the repository
git clone <repo-url> && cd uon

# Create a virtual environment and install
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick Start

```bash
# 1. Register a target machine
uon add myserver 192.168.1.50 --user admin

# 2. Enroll a FIDO2 passkey for the target
uon register myserver

# 3. (Optional) Harden the target's SSH config
scp scripts/harden_target.sh admin@192.168.1.50:/tmp/
ssh admin@192.168.1.50 "sudo bash /tmp/harden_target.sh"

# 4. Execute a signed command
uon myserver "uptime"
```

## CLI Reference

### `uon <target> "<command>"`

Execute a signed command on a registered target.

### `uon add <alias> <host> [--port PORT] [--user USER]`

Register a new target machine.

```bash
uon add prod 10.0.0.5 --port 2222 --user deploy
```

### `uon list`

Show all registered targets and their credential counts.

### `uon register <alias> [--user-name NAME]`

Enroll a FIDO2 passkey for a target.  Prompts for biometric verification.

### `uon remove <alias>`

Un-register a target.

## Architecture

```
src/
├── __init__.py              # Package root
├── cli.py                   # Click CLI — entry point, subcommands, exec flow
├── auth/
│   ├── __init__.py
│   ├── fido_local.py        # Platform authenticator (Touch ID / Hello / HID)
│   └── qr_bridge.py         # Ephemeral LAN web server + QR fallback
├── transport/
│   ├── __init__.py
│   └── ssh_client.py        # Paramiko SSH transport + envelope protocol
└── utils/
    ├── __init__.py
    └── config.py            # Target store (JSON persistence)

scripts/
├── harden_target.sh         # Remote SSHD hardening script
├── uon_verifier.py          # Target-side FIDO2 signature verifier
└── setup_uon.py             # Local passkey registration + key export
```

### Authentication Flow

```
┌──────────┐    challenge     ┌──────────┐
│  Client  │ ◄──────────────► │  Target  │
│  (uon)   │                  │  (sshd)  │
└────┬─────┘                  └────┬─────┘
     │                              │
     │  1. request_challenge()      │
     │  2. Sign with FIDO2 HW      │
     │  3. Wrap in __UON_EXEC__     │
     │     envelope                 │
     │  4. SSH exec_command()  ────►│
     │                              │  5. ForceCommand → uon_verifier.py
     │                              │  6. Verify FIDO2 signature
     │                              │  7. Execute inner command
     │  ◄── stdout/stderr/exit ─────│
```

### QR Bridge

When no local authenticator is available, uon spawns an ephemeral FastAPI
server on `0.0.0.0:8080`, displays an ASCII QR code, and waits for a mobile
device on the same LAN to sign the challenge via WebAuthn.  The server
self-terminates after one successful assertion or a 120-second timeout.

### Envelope Protocol

Commands are transmitted as `__UON_EXEC__ <base64-json>`, where the JSON
payload contains the command, FIDO2 assertion, challenge nonce, and session
ID.  The target's `ForceCommand` (or `uon_verifier.py`) decodes and verifies
before executing.

## Security Model

- **Zero-disk** — no private key files.  All signing happens in hardware.
- **Challenge-response** — 32-byte random nonce + SHA-256 session binding
  prevents replay.
- **TOFU** — host keys are accepted on first contact (pinning planned).
- **Network isolation** — the QR bridge restricts CORS to RFC 1918
  addresses and requires a one-time bearer token.
- **ForceCommand** — even if the SSH transport key is stolen, the target
  rejects commands without a valid FIDO2 hardware signature.

## Target Hardening

Run `scripts/harden_target.sh` on each remote machine to:

1. Disable password authentication
2. Require `verify-required` for public-key auth
3. Restrict SSH to your subnet
4. Validate and restart SSHD

Additionally, install `scripts/uon_verifier.py` as the `ForceCommand` to
enforce FIDO2 verification on every incoming SSH command.

## Deployment Guide

### Phase 1: Configure the Controller (Your Laptop)

The controller is the machine where you initiate commands.  It requires
Python 3.12+ and access to your biometric hardware or USB security key.

**Step 1 — Install the package**

```bash
git clone https://github.com/your-username/uon.git
cd uon
pip install -e .
```

**Step 2 — Register your hardware passkey**

Generate a FIDO2 resident key and export the COSE public key:

```bash
python scripts/setup_uon.py
```

- **macOS** — Touch ID or system password prompt.
- **Windows** — Windows Hello (PIN, Face ID, or fingerprint).
- **Linux / WSL** — Insert your physical security key (e.g. YubiKey) and
  touch the metal contact.  For WSL, attach the USB device via `usbipd`
  if you are not using the QR fallback.

Result: `~/.config/uon/authorized_passkeys.json` is created.

**Step 3 — Register the target in uon**

```bash
uon add my-server 192.168.1.50 --user your_user
uon register my-server
```

### Phase 2: Secure the Target (Remote Machine)

The target is the macOS or Linux machine you want to control.

**Step 1 — Transfer the public key**

```bash
ssh user@target_ip "mkdir -p ~/.config/uon"
scp ~/.config/uon/authorized_passkeys.json user@target_ip:~/.config/uon/
```

**Step 2 — Deploy the verifier script**

```bash
sudo cp scripts/uon_verifier.py /usr/local/bin/uon_verifier.py
sudo chmod +x /usr/local/bin/uon_verifier.py
```

**Step 3 — Link the verifier to your SSH key**

Edit `~/.ssh/authorized_keys` on the target.  Prepend the execution
restriction to your existing transport public key:

```
command="/usr/local/bin/uon_verifier.py",no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAAC3...
```

**Step 4 — Execute the hardening script**

```bash
sudo ./scripts/harden_target.sh
```

This disables password authentication, enforces public-key-only SSH,
and restricts access to your local subnet.  The script is idempotent
and validates the sshd config before restarting.

### Phase 3: Test the Execution Loop

```bash
uon my-server "uname -a"
```

- **Prompt** — the CLI asks for Touch ID, Windows Hello, or YubiKey
  touch.
- **QR fallback** — if the lid is closed or the USB bridge is
  disconnected, the terminal renders an ASCII QR code for your phone.
- **Execution** — once signed, the envelope travels over SSH, the
  target mathematically verifies the hardware signature, and the
  command output is streamed back.

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests with coverage (must be 100%)
pytest

# Lint
ruff check .

# Type-check
mypy src/
```

## License

MIT
