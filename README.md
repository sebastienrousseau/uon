# uon — FIDO2-Signed Remote Terminal Execution

**uon** replaces password- and key-file-based SSH authentication with
hardware-bound FIDO2 passkeys.  Every remote command is cryptographically
signed by your device's Secure Enclave (Touch ID, Windows Hello, or a USB
security key) before the target machine will execute it.  No private key
material ever touches disk.

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [What You Need Before You Start](#what-you-need-before-you-start)
3. [Terminology](#terminology)
4. [Phase 1 — Set Up Your Controller (Your Laptop)](#phase-1--set-up-your-controller-your-laptop)
5. [Phase 2 — Set Up Each Target (Remote Server)](#phase-2--set-up-each-target-remote-server)
6. [Phase 3 — Test the Full Loop](#phase-3--test-the-full-loop)
7. [CLI Reference](#cli-reference)
8. [Architecture](#architecture)
9. [Security Model](#security-model)
10. [Troubleshooting](#troubleshooting)
11. [Development](#development)
12. [License](#license)

---

## How It Works

Traditional SSH lets anyone with a private key file run commands.  If that
file is stolen, the attacker has full access.  uon eliminates the file
entirely — your private key lives inside tamper-resistant hardware
(your laptop's Secure Enclave or a physical USB key) and can never be
exported.

Every time you run a command, the flow is:

1. You type `uon my-server "uptime"` on your laptop (the **controller**).
2. uon asks your hardware to **sign** a one-time challenge — you confirm
   with Touch ID, Windows Hello, or a tap on your YubiKey.
3. The signed command travels over SSH to the **target** server.
4. The target's verifier script mathematically confirms the signature
   came from your physical hardware before executing anything.
5. The command output streams back to your terminal.

If your laptop lid is closed or you have no USB key plugged in, uon
automatically displays a **QR code** in your terminal.  You scan it with
your phone, sign the challenge there, and the command proceeds.

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
| Operating system              | macOS or Linux (any distribution with OpenSSH server)                                    |
| OpenSSH server                | Version 8.2+ recommended.  Check with `sshd -V`.                                        |
| Python 3.8+                   | For the verifier script.  Check with `python3 --version`.                                |
| `fido2` Python package        | Install with `pip3 install fido2>=1.1`.  Only needed on the target.                      |
| Existing SSH access           | You must be able to `ssh user@target` with a key or password today.  uon builds on top.  |

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

From your **controller** (your laptop), copy the public key file:

```bash
# Run this on your CONTROLLER (laptop), not on the target
scp ~/.config/uon/authorized_passkeys.json admin@192.168.1.50:~/.config/uon/
```

Replace `admin@192.168.1.50` with the actual username and IP of your
target.

Verify (on the target):

```bash
cat ~/.config/uon/authorized_passkeys.json
```

You should see a JSON array containing your key record with
`credential_id_hex` and `cose_key_hex` fields.  These are **public**
data — safe to transfer over the network.

### Step 2.4 — Deploy the verifier script on the target

The verifier is a Python script that intercepts every SSH command,
checks the FIDO2 signature, and only executes the command if the
signature is valid.

From your **controller**, copy the verifier script to the target:

```bash
# Run this on your CONTROLLER
scp scripts/uon_verifier.py admin@192.168.1.50:/tmp/uon_verifier.py
```

Then, on the **target**, move it to a system-wide location:

```bash
# Run these on the TARGET
sudo cp /tmp/uon_verifier.py /usr/local/bin/uon_verifier.py
sudo chmod +x /usr/local/bin/uon_verifier.py
```

Verify:

```bash
/usr/local/bin/uon_verifier.py
# Expected (on stderr): "UON Verifier Error: Missing or invalid UON envelope."
# This is correct — it means the verifier is installed and running, but
# no signed envelope was provided (because you ran it manually).
```

### Step 2.5 — Link the verifier to your SSH key

This is the critical step that tells OpenSSH to route every incoming
command through the verifier.

On the **target**, edit (or create) the `~/.ssh/authorized_keys` file.
Find the line containing your existing SSH public key — it looks
something like:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample... user@laptop
```

**Prepend** the following restriction prefix to that line, so the
complete line becomes:

```
command="/usr/local/bin/uon_verifier.py",no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample... user@laptop
```

**What each restriction does:**

| Restriction                | Effect                                                                     |
|----------------------------|----------------------------------------------------------------------------|
| `command="…/uon_verifier.py"` | Every SSH session runs the verifier instead of a shell.  The original command is passed via `$SSH_ORIGINAL_COMMAND`. |
| `no-port-forwarding`       | Prevents SSH tunnels — the key can only run commands, not forward ports.   |
| `no-X11-forwarding`        | Prevents X11 display forwarding.                                           |
| `no-agent-forwarding`      | Prevents SSH agent forwarding — your laptop's keys are not exposed.        |

**How to edit the file:**

```bash
# On the TARGET
nano ~/.ssh/authorized_keys
# (or use vim, vi, or any editor you prefer)
```

Add the `command="...",...` prefix before `ssh-ed25519` (or `ssh-rsa`),
all on one line.  Save and exit.

> **Do not close your current SSH session yet.**  You will verify access
> in Step 2.7 before disconnecting.

### Step 2.6 — Harden the target's SSH configuration

This step disables password login and other legacy authentication
methods, so the only way to access the machine is through a
FIDO2-signed uon command.

From your **controller**, copy the hardening script:

```bash
# Run this on your CONTROLLER
scp scripts/harden_target.sh admin@192.168.1.50:/tmp/harden_target.sh
```

On the **target**, run it as root:

```bash
# Run this on the TARGET
sudo bash /tmp/harden_target.sh
```

The script:

1. **Backs up** your current `/etc/ssh/sshd_config` (so you can undo if
   needed).
2. **Disables** password authentication, keyboard-interactive auth, and
   empty passwords.
3. **Enables** public-key authentication with physical-presence
   verification (`PubkeyAuthOptions verify-required`).
4. **Restricts** SSH to your local subnet (default `192.168.0.0/16`).
   Pass a custom subnet as an argument:
   `sudo bash /tmp/harden_target.sh 10.0.0.0/24`
5. **Validates** the configuration with `sshd -t`.  If invalid, it
   automatically restores the backup.
6. **Restarts** the SSH daemon.

The script is idempotent — you can safely re-run it.

> **Warning:** After hardening, password login is permanently disabled.
> If you have not set up uon correctly, you may lose access.  Always
> verify access (Step 2.7) from a **second terminal** before closing
> your current session.

### Step 2.7 — Verify access before disconnecting

Open a **new terminal window** on your controller (keep the old SSH
session open as a safety net) and try:

```bash
uon home-server "whoami"
```

You should see:

1. A biometric prompt (Touch ID / Hello / key tap).
2. After approval, the output: `admin` (or whatever user you configured).

If this works, your setup is complete.  You can safely close the old SSH
session.

**If it fails:** Go back to the open SSH session on the target and check:

- Does `/usr/local/bin/uon_verifier.py` exist and is it executable?
- Does `~/.config/uon/authorized_passkeys.json` exist and contain your key?
- Is `~/.ssh/authorized_keys` formatted correctly (all on one line)?

To undo hardening and restore password access:

```bash
# On the target, in your still-open session
sudo cp /etc/ssh/sshd_config.uon-backup.* /etc/ssh/sshd_config
sudo systemctl restart sshd   # or: sudo service sshd restart
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

Execute a signed command on a registered target.

```bash
uon my-server "uptime"
uon my-server "cat /etc/hostname"
```

**Exit code:** Matches the remote command's exit code (0 = success).

### `uon add <alias> <host> [--port PORT] [--user USER]`

Register a new target machine.  The target is stored locally in your
config file.  If a target with the same alias exists, it is overwritten.

```bash
uon add prod 10.0.0.5 --port 2222 --user deploy
uon add pi 192.168.1.42 --user pi
```

| Option    | Default | Description                          |
|-----------|---------|--------------------------------------|
| `--port`  | `22`    | SSH port on the target.              |
| `--user`  | `root`  | Username to SSH as on the target.    |

### `uon list`

Show all registered targets and their enrolled credential counts.

```bash
$ uon list
  prod                  deploy@10.0.0.5:2222  (1 credential(s))
  pi                    pi@192.168.1.42:22  (0 credential(s))
```

### `uon register <alias> [--user-name NAME]`

Enroll a FIDO2 passkey for a target.  Triggers a biometric or
physical-touch prompt.  The target must already exist (via `uon add`).

```bash
uon register prod
```

| Option         | Default                        | Description                           |
|----------------|--------------------------------|---------------------------------------|
| `--user-name`  | `uon:<user>@<host>`            | Display name for the credential.      |

### `uon remove <alias>`

Un-register a target.  Exits with code 1 if the alias does not exist.

```bash
uon remove prod
```

---

## Architecture

```
src/uon/
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
    ├── config.py            # Target store (JSON persistence)
    └── policy.py            # AAGUID attestation policy (allowlist)

scripts/
├── harden_target.sh         # Remote SSHD hardening script
├── uon_verifier.py          # Target-side FIDO2 signature verifier
└── setup_uon.py             # Local passkey registration + key export
```

### Authentication Flow

```
┌──────────────────┐                      ┌──────────────────┐
│   CONTROLLER     │                      │     TARGET       │
│   (your laptop)  │                      │  (remote server) │
└────────┬─────────┘                      └────────┬─────────┘
         │                                         │
         │  1. Generate 32-byte random nonce       │
         │                                         │
         │  2. Sign nonce with FIDO2 hardware      │
         │     (Touch ID / Hello / USB key / QR)   │
         │                                         │
         │  3. Wrap command + signature in          │
         │     __UON_EXEC__ JSON envelope          │
         │                                         │
         │  4. SSH exec_command() ────────────────►│
         │                                         │
         │                              5. ForceCommand triggers
         │                                 uon_verifier.py
         │                                         │
         │                              6. Decode envelope,
         │                                 verify RP ID hash,
         │                                 verify user presence,
         │                                 verify FIDO2 signature
         │                                 against stored public key
         │                                         │
         │                              7. If valid: execute command
         │                                 If invalid: reject (exit 1)
         │                                         │
         │  ◄──── stdout / stderr / exit code ─────│
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

Commands are transmitted as `__UON_EXEC__ <base64-json>`, where the
JSON payload contains:

```json
{
    "version": 1,
    "command": "uptime",
    "challenge": "<base64-nonce>",
    "session_id": "<base64-sha256>",
    "assertion": {
        "credentialId": "<base64>",
        "authenticatorData": "<base64>",
        "clientDataJSON": "<base64>",
        "signature": "<base64>"
    }
}
```

The target's verifier decodes and verifies every field before executing
the inner `command`.

### Config Storage

uon stores target definitions locally in a JSON file.  No secrets are
stored — only hostnames, ports, usernames, and public credential IDs.

| Platform    | Config file location                                  |
|-------------|-------------------------------------------------------|
| macOS       | `~/Library/Application Support/uon/targets.json`      |
| Windows     | `%APPDATA%\uon\targets.json`                          |
| Linux / WSL | `~/.config/uon/targets.json`                          |

---

## Security Model

| Property             | Implementation                                                                          |
|----------------------|-----------------------------------------------------------------------------------------|
| Zero-disk secrets    | Private keys live exclusively inside hardware secure enclaves.  Nothing is written to `~/.ssh` or any config file. |
| Per-command signing  | Every remote execution requires a fresh biometric or physical-touch approval.  There is no session persistence. |
| Challenge-response   | A 32-byte random nonce + SHA-256 session binding prevents replay attacks across sessions. |
| ForceCommand         | Even if the SSH transport key is stolen, the target rejects commands without a valid FIDO2 hardware signature. |
| Network isolation    | The QR bridge restricts CORS to RFC 1918 (private) IP addresses and requires a one-time 32-byte bearer token. |
| TOFU                 | Host keys are accepted on first contact (Trust-On-First-Use), consistent with standard SSH behaviour.  Host-key pinning is planned for a future release. |
| RP ID                | The relying party ID is `uon.local` — a non-routable domain that prevents phishing redirects. |

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

If you cannot log in after running `harden_target.sh`, you need
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

MIT
