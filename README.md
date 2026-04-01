# uon — FIDO2-Signed Remote Command Execution

`uon` runs remote commands only after a fresh FIDO2 approval. It replaces reusable SSH trust for command execution with per-command hardware-backed verification, then routes approved commands through a least-privilege broker on the target.

---

## Quick Answer

| Question | Answer |
|---|---|
| What is `uon`? | A CLI for FIDO2-signed remote command execution. |
| What problem does it solve? | It removes reusable trust for remote execution and requires a new hardware approval for every command. |
| How does it work? | The controller signs a challenge, the target verifies the envelope through `ForceCommand`, then a persistent broker runs the approved command under a restricted identity. |
| Who is this guide for? | Operators setting up a controller on macOS, Linux, or WSL and deploying Linux targets with OpenSSH and systemd. |

## Architecture & Mental Model

`uon` is not a shell replacement. It is a signed command courier. You submit one command, approve one hardware prompt, and the target either verifies and runs that command or rejects it.

### Platform Constraints

* **Controller:** macOS, Linux, and WSL are the primary documented controller environments.
* **Automated target deployment:** Linux with OpenSSH and systemd.
* **Authenticators:** Touch ID, Windows Hello, or a USB security key. If local signing fails, `uon` falls back to the QR bridge.

---

## Table of Contents

1. [Architecture & Mental Model](#architecture--mental-model)
2. [What You Need Before You Start](#what-you-need-before-you-start)
3. [Terminology](#terminology)
4. [Phase 1 — Set Up Your Controller](#phase-1--set-up-your-controller)
5. [Phase 2 — Set Up Each Target](#phase-2--set-up-each-target)
6. [Phase 3 — Test the Full Loop](#phase-3--test-the-full-loop)
7. [CLI Reference](#cli-reference)
8. [Security Model](#security-model)
9. [Troubleshooting](#troubleshooting)
10. [License](#license)

---

### The Execution Lifecycle

Every time you run a command, `uon` enforces this flow:

1. **Local Invocation**: You cast `uon my-server "uptime"` on your laptop (the **controller**).
2. **Hardware Signature**: `uon` drops into native bounds, asking your hardware to **sign** a one-time cryptographic challenge. You confirm with Touch ID, Windows Hello, or a YubiKey tap.
3. **Transport**: The signed command travels over SSH to the **target** server.
4. **Verifiable Telemetry**: The target's OpenSSH `ForceCommand` intercepts the payload. A specialized verifier mathematically confirms the signature originated from your physical hardware.
5. **Execution**: Upon validation, the verifier forwards the command to a persistent Zero Standing Privilege broker. The broker drops to the target UID plus the fixed `uon-exec` group, runs the command, and returns stdout, stderr, and exit code.

> **QR Fallback**: If your laptop lid is closed or you lack USB keys, `uon` automatically displays a **QR code** in your terminal. You scan it with your phone, sign the challenge securely, and the command proceeds.

---

## What You Need Before You Start

You need two things: a **controller** (the machine you type on) and one
or more **targets** (the remote machines you want to control).

### Controller requirements

| Requirement                   | Details                                                                                                    |
|-------------------------------|------------------------------------------------------------------------------------------------------------|
| Operating system              | macOS, Linux, Windows, or WSL (Windows Subsystem for Linux)                                                |
| Python                        | Version 3.12 or newer.  Check with `python3 --version`.                                                   |
| pip                           | Python's package installer.  Ships with Python 3.12+.                                                      |
| git                           | To clone the repository.  Check with `git --version`.                                                      |
| FIDO2 authenticator           | One of: Touch ID (macOS), Windows Hello (Windows), a USB security key (YubiKey, SoloKey, Titan, etc.)      |
| SSH client                    | The standard `ssh` command.  Pre-installed on macOS and Linux.  On Windows, use the built-in OpenSSH.      |

### Target requirements

| Requirement                   | Details                                                                                  |
|-------------------------------|------------------------------------------------------------------------------------------|
| Operating system              | Linux with OpenSSH and systemd for the documented automated install flow                 |
| OpenSSH server                | Version 8.2+ recommended.  Check with `sshd -V`.                                        |
| Python                        | Python 3.12+ is the documented path for the target-side verifier and broker scripts     |
| `fido2` Python package        | Install with `pip3 install fido2>=1.1`.  Only needed on the target.                      |
| Existing SSH access           | You must be able to `ssh user@target` with a key or password today.  uon builds on top.  |
| systemd                       | Required by `install_target.sh` to run `uon-zsp-broker.service`                          |

The codebase contains additional platform work for macOS and WSL-oriented paths, but this README documents the Linux target installation flow because that is the deployable path in the repo today.

### Platform-specific notes

- **WSL users:** Your USB security key is not automatically visible
  inside WSL.  Install [`usbipd-win`](https://github.com/dorssel/usbipd-win)
  on the Windows side and attach the device with
  `usbipd attach --wsl --busid <BUS-ID>`.  Alternatively, skip the USB
  key entirely and use the QR bridge fallback (no extra setup needed).

- **Headless Linux (no display):** You cannot use Touch ID or Windows
  Hello.  Plug in a USB security key, or use the QR bridge with your
  phone.

---

## Terminology

These terms appear throughout this guide:

| Term              | Meaning                                                                                      |
|-------------------|----------------------------------------------------------------------------------------------|
| **Controller**    | The machine you sit at and type commands on.  Your laptop or workstation.                     |
| **Target**        | A remote server that receives and executes your signed commands.                              |
| **Passkey**       | A FIDO2 credential stored inside tamper-resistant hardware.  It cannot be copied or exported. |
| **COSE key**      | The public half of your passkey, encoded in a standard binary format (CBOR Object Signing).   |
| **Verifier**      | A Python script (`uon_verifier.py`) that runs on the target and checks every signature.      |
| **Envelope**      | The signed JSON package (`__UON_EXEC__`) that wraps your command for transport over SSH.     |
| **QR bridge**     | A temporary local web server that lets your phone sign a challenge when your laptop cannot.   |
| **ForceCommand**  | An OpenSSH feature that intercepts every SSH session and routes it through the verifier.      |

---

## Phase 1 — Set Up Your Controller (Your Laptop)

You perform these steps once on the machine you will type commands from.

### Step 1.1 — Install Python 3.12+

If you do not already have Python 3.12 or newer:

- **macOS:** `brew install python@3.12` (or download from [python.org](https://www.python.org/downloads/))
- **Ubuntu / Debian:** `sudo apt update && sudo apt install python3.12 python3.12-venv`
- **Fedora:** `sudo dnf install python3.12`
- **Windows:** Download from [python.org](https://www.python.org/downloads/).
  During install, check **"Add Python to PATH"**.
- **WSL:** Follow the Ubuntu/Debian instructions above inside your WSL terminal.

Verify:

```bash
python3 --version
# Expected output: Python 3.12.x (or newer)
```

### Step 1.2 — Clone and install uon

```bash
# Clone the repository
git clone https://github.com/sebastienrousseau/uon.git

# Enter the project directory
cd uon

# (Recommended) Create a virtual environment to keep your system clean
python3 -m venv .venv

# Activate the virtual environment
# macOS / Linux / WSL:
source .venv/bin/activate
# Windows (Command Prompt):
.venv\Scripts\activate.bat
# Windows (PowerShell):
.venv\Scripts\Activate.ps1

# Install uon and all its dependencies
pip install -e .
```

Verify the installation:

```bash
uon --help
```

You should see the uon help text listing the available commands (`add`,
`list`, `register`, `remove`).

### Step 1.3 — Register your hardware passkey

This step generates a FIDO2 passkey inside your hardware and exports the
public key so you can later install it on target machines.

```bash
python scripts/setup_uon.py
```

**What happens on each platform:**

- **macOS:** A Touch ID prompt appears.  Place your finger on the sensor.
  If Touch ID is unavailable, you will be asked for your system password.
- **Windows:** A Windows Hello prompt appears.  Authenticate with your
  PIN, face, or fingerprint.
- **Linux / WSL:** The terminal prints
  `"Touch your authenticator device …"`.  Tap the metal contact on your
  USB security key (e.g. YubiKey).

**Result:** A file is created at `~/.config/uon/authorized_passkeys.json`.
This file contains your **public** key only — your private key never
leaves the hardware.  You will copy this file to each target server in
Phase 2.

### Step 1.4 — Tell uon about your target servers

For each remote machine you want to control, register it with a
**friendly name** (alias), the server's **IP address** or **hostname**,
and the **username** you SSH with.

```bash
uon add <alias> <host-or-ip> --user <username> --port <port>
```

**Arguments explained:**

| Argument      | Required | Default  | What it is                                                     |
|---------------|----------|----------|----------------------------------------------------------------|
| `<alias>`     | Yes      | —        | A short name you choose.  You will type this every time.       |
| `<host-or-ip>`| Yes      | —        | The target's IP address (e.g. `192.168.1.50`) or hostname.     |
| `--user`      | No       | `root`   | The remote username to SSH as.                                 |
| `--port`      | No       | `22`     | The SSH port if it is not the standard 22.                     |

**Examples:**

```bash
# A home server with default SSH port, logging in as "admin"
uon add home-server 192.168.1.50 --user admin

# A cloud VPS on a non-standard port, logging in as "deploy"
uon add cloud-vps 203.0.113.10 --port 2222 --user deploy

# A Raspberry Pi on your local network
uon add pi 10.0.0.42 --user pi

# A server you reach by hostname
uon add staging staging.internal.example.com --user ubuntu
```

Verify your targets:

```bash
uon list
```

Output:

```
  home-server           admin@192.168.1.50:22  (0 credential(s))
  cloud-vps             deploy@203.0.113.10:2222  (0 credential(s))
```

The `0 credential(s)` is expected — you have not enrolled a FIDO2
credential for these targets yet.  That happens in Step 1.5.

### Step 1.5 — Enroll a FIDO2 credential for each target

For each target you registered, enroll a passkey:

```bash
uon register <alias>
```

This triggers a biometric prompt (Touch ID, Windows Hello, or USB key
tap).  After you approve, the credential ID is stored in your local
config.

```bash
# Example
uon register home-server
# → "Enrolling FIDO2 credential for 'home-server' …"
# → (Touch ID / Hello / key tap)
# → "Credential registered (ID: abc123…)."
```

Verify:

```bash
uon list
```

```
  home-server           admin@192.168.1.50:22  (1 credential(s))
```

The count changed from 0 to 1.  Your controller is now fully
configured for this target.

---

## Phase 2 — Set Up Each Target (Remote Server)

You perform these steps on **every** remote machine you want to control
with uon.  You will need an existing way to access the target (password
SSH, an existing SSH key, or physical console access).

### Step 2.1 — Install the fido2 Python package on the target

Log into the target server and install the `fido2` library that the
verifier script depends on:

```bash
# SSH into the target (using your current access method)
ssh admin@192.168.1.50

# On the target, install the fido2 library
pip3 install "fido2>=1.1"
```

Verify:

```bash
python3 -c "import fido2; print(fido2.__version__)"
# Expected: 1.1.x or newer
```

### Step 2.2 — Create the uon config directory on the target

```bash
# On the target server
mkdir -p ~/.config/uon
```

### Step 2.3 — Copy your public key to the target

From your **controller** (your laptop), copy the public key file to the target:

```bash
# Run this on your CONTROLLER (laptop), not on the target
scp ~/.config/uon/authorized_passkeys.json admin@192.168.1.50:~/.config/uon/
```

*(You should verify the key was copied successfully via `cat ~/.config/uon/authorized_passkeys.json` on the target).*

### Step 2.4 — Execute the Automated Target Deployment

Traditionally, locking down a server involved manually injecting Python verifier hooks into `authorized_keys` and surgically hardening `sshd_config`. To massively accelerate **enterprise zero-trust adoption**, `uon` bundles a highly idempotent fleet-deployment script. 

Run the automated installer on the **target server** as `root` (or via `sudo`):

```bash
curl -sL https://raw.githubusercontent.com/sebastienrousseau/uon/main/scripts/install_target.sh | sudo bash -s -- <user> 
```

*(Replace `<user>` with the username you authenticate to, e.g., `admin` or `pi`).*

**What the install script handles natively:**
1. **Verifier Scaffolding:** Downloads the `uon_verifier.py` hook securely into `/usr/local/bin/`.
2. **Persistent ZSP Broker:** Installs `uon_zsp_broker.py`, provisions the static `uon-exec` least-privilege group, and enables the `uon-zsp-broker.service` systemd unit that owns the execution boundary.
3. **Payload Enforcement:** Idempotently hooks your `~/.ssh/authorized_keys` to intercept all connections natively via `command="/usr/local/bin/uon_verifier.py"`.
4. **Daemon Hardening:** Strips legacy access controls inside `/etc/ssh/sshd_config` (disables password authentication, keyboards, and enforces verification).
5. **Validation/Rollback:** Executes a strict `sshd -t` pre-flight check, immediately restoring target backups if the configuration fails to validate.

> **Warning:** After hardening, traditional password login is permanently disabled.

### Step 2.5 — Verify access before disconnecting

Open a **new terminal window** on your controller (keep the old SSH session open as a safety net) and try:

```bash
uon home-server "whoami"
```

You should see a biometric prompt (Touch ID / Hello / key tap), followed by your output user. If this works, your setup is completely finished.

To manually undo hardening and restore password access (if you locked yourself out from your active session):

```bash
# On the target, in your still-open session
sudo cp /etc/ssh/sshd_config.uon-backup.* /etc/ssh/sshd_config
sudo systemctl restart sshd
```

---

## Phase 3 — Test the Full Loop

With both controller and target configured, you can run commands:

```bash
# Check the remote system info
uon home-server "uname -a"

# View disk usage
uon home-server "df -h"

# Check who is logged in
uon home-server "who"

# Run a longer command
uon home-server "apt list --upgradable 2>/dev/null | head -20"
```

**What you see at each step:**

```
$ uon home-server "uname -a"
Connecting to admin@192.168.1.50:22 …      ← SSH transport opens
                                             ← Touch ID / Hello / key tap
Executing command …                          ← Signed envelope sent
Linux home-server 6.1.0 #1 SMP x86_64 GNU/Linux   ← Remote output
```

### The QR bridge fallback

If your laptop lid is closed, your USB key is unplugged, or you are in
WSL without `usbipd`:

```
$ uon home-server "uptime"
Connecting to admin@192.168.1.50:22 …
No local authenticator found — launching QR bridge …

--- uon QR Bridge ---
Scan the QR code below with your phone to sign the challenge.

█████████████████████████████
█  ▄▄▄  █ ▀▀▄ ██▄█  ▄▄▄  █    ← ASCII QR code appears
█  █ █  █▀▄▄▀▀▀ ██  █ █  █
...

Or open: http://192.168.1.42:8080/sign?token=abc123...
```

1. Scan the QR code with your phone's camera (both iOS and Android work).
2. Your phone opens a webpage with a **"Sign with Passkey"** button.
3. Tap the button and authenticate with your phone's biometric.
4. The terminal prints `"Executing command …"` and the result appears.

The QR bridge only works for devices on the same local network.  It
self-destructs after one use or after 120 seconds.

---

## CLI Reference

### `uon <target> "<command>"`

Run a signed remote command on a registered target.

#### Examples

```bash
uon my-server "uptime"
uon my-server "cat /etc/hostname"
```

#### Common failures

- Exits with the remote command's non-zero exit code if the command itself fails.
- Exits with code `1` if the target is unknown, no credential is enrolled, or the signed execution path fails before the command is run remotely.

### `uon add <alias> <host> [--port PORT] [--user USER]`

Register a target in the local config store.

#### Examples

```bash
uon add prod 10.0.0.5 --port 2222 --user deploy
uon add pi 192.168.1.42 --user pi
```

#### Behavior

- Replaces any existing target with the same alias.

| Option    | Default | Description                          |
|-----------|---------|--------------------------------------|
| `--port`  | `22`    | SSH port on the target.              |
| `--user`  | `root`  | Username to SSH as on the target.    |

### `uon list`

List all registered targets and enrolled credential counts.

#### Example

```bash
$ uon list
  prod                  deploy@10.0.0.5:2222  (1 credential(s))
  pi                    pi@192.168.1.42:22  (0 credential(s))
```

### `uon register <alias> [--user-name NAME]`

Enroll a FIDO2 credential for a target.

#### Example

```bash
uon register prod
```

#### Common failures

- Exits with code `1` if the target does not exist.
- Exits with code `1` if no compatible authenticator is available.
- Exits with code `1` if the active AAGUID policy rejects the credential.

| Option         | Default                        | Description                           |
|----------------|--------------------------------|---------------------------------------|
| `--user-name`  | `uon:<user>@<host>`            | Display name for the credential.      |

### `uon remove <alias>`

Remove a target from the local config store.

#### Example

```bash
uon remove prod
```

#### Common failures

- Exits with code `1` if the alias does not exist.

---

## Architecture

```text
src/uon/
├── __init__.py              # Package root
├── cli.py                   # Click CLI — entry point, subcommands, exec flow
├── auth/
│   ├── __init__.py
│   ├── fido_local.py        # Platform authenticator (Touch ID / Hello / HID)
│   └── qr_bridge.py         # Ephemeral LAN web server + QR fallback
├── contracts/
│   ├── __init__.py
│   └── fido_dto.py          # Signed execution DTOs
├── transport/
│   ├── __init__.py
│   ├── amdns.py             # Discovery beacon helpers
│   └── pqc.py               # PQC helper layer
├── utils/
│   ├── __init__.py
│   ├── config.py            # Target store
│   └── policy.py            # AAGUID policy store
├── core.pyi                 # Typed Rust extension boundary
└── core.*.so                # Compiled PyO3 extension

src/uon_core/
├── lib.rs                   # Python module exports
├── ssh_core.rs              # SSH execution path
└── zsp_core.rs              # Broker client bridge

scripts/
├── benchmark_hot_paths.py   # Hot-path benchmark harness
├── harden_target.sh         # Legacy hardening helper
├── install_target.sh        # Target deployment script
├── setup_uon.py             # Local passkey registration + key export
├── uon_verifier.py          # Target-side FIDO2 signature verifier
└── uon_zsp_broker.py        # Persistent least-privilege broker
```

### Authentication Flow

```text
Controller
1. Generate a fresh challenge
2. Sign it with a local authenticator or the QR bridge
3. Send `__UON_EXEC__ <payload>` over SSH

Target
4. OpenSSH ForceCommand invokes `uon_verifier.py`
5. The verifier decapsulates the payload and validates the FIDO2 assertion
6. Approved commands are forwarded to `uon_zsp_broker.py`
7. The broker drops to the target UID + `uon-exec` group
8. stdout, stderr, and exit code are returned to the controller
```

### Tiered Authentication

When you run `uon my-server "uptime"`, the CLI tries to sign the
challenge in this order:

| Tier | Method                     | When it activates                                    |
|------|----------------------------|------------------------------------------------------|
| 1    | Local biometric            | Always tried first.  Touch ID (macOS), Windows Hello (Windows), USB HID key (any platform). |
| 2    | QR bridge (phone)          | Automatically if Tier 1 fails — no authenticator found, lid closed, USB disconnected, driver error, etc. |
| —    | Hard failure               | If both tiers fail (QR timeout after 120s, or phone error). |

The fallback is automatic and seamless — you do not need to configure
anything.

### Envelope Protocol

Commands are transmitted as `__UON_EXEC__ <payload>`. The outer payload
is base64-encoded and decapsulated on the target before the verifier
parses the inner JSON envelope.

Current decrypted envelope shape:

```json
{
  "session_id": "<base64>",
  "command": "uptime",
  "assertion": {
    "credential_id": "<base64url>",
    "client_data": "<base64url>",
    "auth_data": "<base64url>",
    "signature": "<base64url>"
  }
}
```

The verifier rejects the request if the session is replayed, the RP ID
hash is wrong, the user-presence bit is missing, or no stored public key
verifies the signature.

### Config Storage

`uon` stores target definitions locally in a JSON file. No private key
material is written to disk.

| Platform    | Config file location                                  |
|-------------|-------------------------------------------------------|
| macOS       | `~/Library/Application Support/uon/targets.json`      |
| Windows     | `%APPDATA%\uon\targets.json`                          |
| Linux / WSL | `~/.config/uon/targets.json`                          |

---

## Security Model

| Property             | Implementation |
|----------------------|----------------|
| Zero-disk secrets    | Private keys remain inside hardware authenticators. |
| Per-command signing  | Every execution requires a fresh approval. |
| Replay protection    | The target tracks used `session_id` values and rejects reuse. |
| ForceCommand gate    | Configured SSH sessions are routed through `uon_verifier.py`. |
| Least-privilege exec | Approved commands run through a persistent broker that drops to the target UID plus the fixed `uon-exec` group. |
| TOFU                 | Host keys are accepted on first contact and then pinned in `known_hosts`. |
| QR bridge scope      | The QR fallback is local-network oriented and time-bound. |
| RP ID                | The relying party ID is `uon.local`. |

---

## Troubleshooting

### "Unknown target 'my-server'"

You have not registered the target yet.  Run:

```bash
uon add my-server 192.168.1.50 --user admin
```

### "No FIDO2 credentials for 'my-server'"

You registered the target but did not enroll a passkey.  Run:

```bash
uon register my-server
```

### "No local authenticator found — launching QR bridge …"

This is not an error.  It means uon could not find Touch ID, Windows
Hello, or a USB key, so it is falling back to the QR bridge.  Scan the
QR code with your phone to proceed.

If you expected a local authenticator:

- **macOS:** Is your laptop lid open?  Touch ID requires the built-in
  keyboard.
- **Windows:** Is Windows Hello set up?  Check Settings → Accounts →
  Sign-in options.
- **Linux / WSL:** Is your USB key plugged in?  Check with `lsusb`.
  For WSL, ensure the device is attached via `usbipd`.

### "QR bridge timed out"

No phone signed the challenge within 120 seconds.  Make sure:

- Your phone is on the **same local network** (Wi-Fi) as your laptop.
- You scanned the QR code and tapped **"Sign with Passkey"** on the
  phone.
- Your phone has a registered passkey (the passkey from Phase 1 must
  be synced or the same hardware).

### "UON Verifier Error: Cryptographic signature verification failed"

The target could not verify your signature.  This means the public key
on the target does not match your passkey.  Re-copy the public key:

```bash
scp ~/.config/uon/authorized_passkeys.json admin@target:~/.config/uon/
```

### "Permission denied (publickey)"

The SSH transport layer rejected your connection before uon could send
the signed envelope.  Check:

- Is your standard SSH key (`~/.ssh/id_ed25519` or `~/.ssh/id_rsa`)
  installed in the target's `~/.ssh/authorized_keys`?
- Did you accidentally remove the SSH key line when editing
  `authorized_keys` in Step 2.5?

### Locked out after hardening

If you cannot log in after running `install_target.sh`, you need
console access (physical terminal, cloud provider's web console, or
out-of-band management).  Once in, restore the backup:

```bash
# Find the backup file
ls /etc/ssh/sshd_config.uon-backup.*

# Restore it
sudo cp /etc/ssh/sshd_config.uon-backup.<timestamp> /etc/ssh/sshd_config
sudo systemctl restart sshd
```

---

## Development

### Prerequisites

- Python 3.12+
- [Poetry](https://python-poetry.org/docs/#installation) (install via `pipx install poetry`)

### Setup

```bash
# Clone the repository
git clone https://github.com/sebastienrousseau/uon.git
cd uon

# Install all dependencies (main + dev)
poetry install

# Install pre-commit hooks
poetry run pre-commit install
```

### Common Commands

```bash
# Run the full test suite (must reach 100% branch coverage)
poetry run pytest

# Lint with Ruff
poetry run ruff check .

# Auto-format code
poetry run ruff format .

# Type-check with MyPy (strict mode)
poetry run mypy src/

# Run the CLI locally
poetry run uon <target> '<command>'

# Run all pre-commit hooks against every file
poetry run pre-commit run --all-files
```

---

## License

[GNU Affero General Public License v3.0 (AGPLv3)](LICENSE)

---
Designed by Sebastien Rousseau — https://sebastienrousseau.com
Engineered with Euxis — Enterprise Unified Execution Intelligence System — https://euxis.co
