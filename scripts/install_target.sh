#!/usr/bin/env bash
# ==============================================================================
# uon — Zero-Trust Target Provisioning Pipeline
# ==============================================================================
# 
# This script automates the rigorous 7-step enterprise onboarding procedure for 
# remote target execution. It is designed to be fully idempotent, suitable for 
# automated fleet deployment (Ansible, Terraform, Chef).
#
# Execution Bound Requirements:
# - Run as `root` (or with `sudo`) to manipulate `/etc/ssh` and `/usr/local/bin`
# - Target must have an existing `~/.ssh/authorized_keys` with the admin's public key
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/sebastienrousseau/uon/main/scripts/install_target.sh | sudo bash -s -- <user> 
# ==============================================================================

set -eo pipefail

TARGET_USER="${1:-root}"
TARGET_HOME=$(eval echo "~$TARGET_USER")
SSH_DIR="$TARGET_HOME/.ssh"
AUTH_KEYS="$SSH_DIR/authorized_keys"
CONFIG_DIR="$TARGET_HOME/.config/uon"

VERIFIER_DEST="/usr/local/bin/uon_verifier.py"
SSHD_CONFIG_FILE="/etc/ssh/sshd_config"

# Optional Subnet Constraint (Archived for future strict `Match Address` parsing)
# SUBNET="${2:-192.168.0.0/16}"

# Textual Output Formatting
RED='\037[0;31m'
GREEN='\037[0;32m'
YELLOW='\037[1;33m'
NC='\037[0m' # No Color

function print_step() { echo -e "${GREEN}==> $1${NC}"; }
function print_warn() { echo -e "${YELLOW}[!] $1${NC}"; }
function fail() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

# Prevent silent failures if the user doesn't exist
if ! id "$TARGET_USER" >/dev/null 2>&1; then
    fail "Target user '$TARGET_USER' does not exist."
fi

# ==============================================================================
# Step 1: Directory Scaffolding
# ==============================================================================
print_step "Scaffolding UON Configuration Directories for $TARGET_USER"

mkdir -p "$CONFIG_DIR"
chown "$TARGET_USER:$TARGET_USER" "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

if [[ ! -f "$AUTH_KEYS" ]]; then
    fail "No authorized_keys found at $AUTH_KEYS. Please copy your public key first."
fi

# ==============================================================================
# Step 2: Verifier Deployment
# ==============================================================================
print_step "Deploying Zero-Trust Verifier Payload to $VERIFIER_DEST"

# In a production pip/curl deployment, we fetch the verifier natively from the release tree.
# For local script execution, we assume it's in the same directory context or already pushed.
VERIFIER_SOURCE="${VERIFIER_SOURCE:-scripts/uon_verifier.py}"

if [[ -f "$VERIFIER_SOURCE" ]]; then
    cp "$VERIFIER_SOURCE" "$VERIFIER_DEST"
else
    # Fallback to GitHub RAW pipeline if run via curl
    curl -sL "https://raw.githubusercontent.com/sebastienrousseau/uon/main/scripts/uon_verifier.py" -o "$VERIFIER_DEST" || fail "Unable to fetch Verifier."
fi

chmod +x "$VERIFIER_DEST"
chown root:root "$VERIFIER_DEST"

# ==============================================================================
# Step 3: Payload Enforcement (OpenSSH `command=` Hooking)
# ==============================================================================
print_step "Injecting Verifier Hooks into $AUTH_KEYS"

# The 2026 strict boundary prefix
PREFIX='command="/usr/local/bin/uon_verifier.py",no-port-forwarding,no-X11-forwarding,no-agent-forwarding'

# Idempotently update the authorized_keys file.
# If a line does not start with `command=`, we prepend our zero-trust hooks.
tmp_keys=$(mktemp)
while IFS= read -r line; do
    if [[ "$line" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) ]]; then
        echo "$PREFIX $line" >> "$tmp_keys"
    elif [[ "$line" =~ ^command=.*uon_verifier.* ]]; then
        # Already hooked; pass through natively
        echo "$line" >> "$tmp_keys"
    elif [[ "$line" =~ ^command= ]]; then
        print_warn "Skipping key with existing conflicting command= restrictor."
        echo "$line" >> "$tmp_keys"
    else
        echo "$line" >> "$tmp_keys"
    fi
done < "$AUTH_KEYS"

cat "$tmp_keys" > "$AUTH_KEYS"
rm -f "$tmp_keys"
chmod 600 "$AUTH_KEYS"
chown "$TARGET_USER:$TARGET_USER" "$AUTH_KEYS"

# ==============================================================================
# Step 4: System Hardening (sshd_config)
# ==============================================================================
print_step "Hardening Host OpenSSH Daemon..."

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_SSHD="${SSHD_CONFIG_FILE}.uon-backup.${TIMESTAMP}"

cp "$SSHD_CONFIG_FILE" "$BACKUP_SSHD"
print_warn "Backed up prior SSH configuration to $BACKUP_SSHD"

# Idempotent replacement logic for SSH restrictions. We enforce Pubkey/Verify constraints.
sed -i -E 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG_FILE"
sed -i -E 's/^#?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' "$SSHD_CONFIG_FILE"
sed -i -E 's/^#?PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSHD_CONFIG_FILE"
sed -i -E 's/^#?PubkeyAuthOptions.*/PubkeyAuthOptions verify-required/' "$SSHD_CONFIG_FILE"

# Validating the execution constraints
if sshd -t; then
    print_step "Configurations Valid. Restarting OpenSSH..."
    if systemctl is-active --quiet sshd; then
        systemctl restart sshd
    elif systemctl is-active --quiet ssh; then
        systemctl restart ssh
    else
        print_warn "Could not determine systemd ssh service name. Please restart sshd manually."
    fi
    print_step "Deployment Complete. Zero-Trust Boundary active for $TARGET_USER."
else
    # Zero-Trust Rollback
    cp "$BACKUP_SSHD" "$SSHD_CONFIG_FILE"
    fail "SSHD configuration failed validation! Rolled back to $BACKUP_SSHD."
fi
