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
BROKER_DEST="/usr/local/libexec/uon_zsp_broker.py"
BROKER_ENV_FILE="/etc/default/uon-zsp-broker"
BROKER_SERVICE_FILE="/etc/systemd/system/uon-zsp-broker.service"
BROKER_SOCKET_PATH="/run/uon/zsp.sock"
EXEC_GROUP="uon-exec"
SSHD_CONFIG_FILE="/etc/ssh/sshd_config"

# Optional Subnet Constraint (Archived for future strict `Match Address` parsing)
# SUBNET="${2:-192.168.0.0/16}"

# Textual Output Formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

function print_step() { echo -e "${GREEN}==> $1${NC}"; }
function print_warn() { echo -e "${YELLOW}[!] $1${NC}"; }
function fail() { echo -e "${RED}[ERROR] $1${NC}" >&2; exit 1; }

# Prevent silent failures if the user doesn't exist
if ! id "$TARGET_USER" >/dev/null 2>&1; then
    fail "Target user '$TARGET_USER' does not exist."
fi

command -v python3 >/dev/null 2>&1 || fail "python3 is required on the target host."
command -v systemctl >/dev/null 2>&1 || fail "systemd is required for the persistent ZSP broker."

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
# Step 2b: Persistent ZSP Broker Deployment
# ==============================================================================
print_step "Deploying Persistent ZSP Broker to $BROKER_DEST"

BROKER_SOURCE="${BROKER_SOURCE:-scripts/uon_zsp_broker.py}"

mkdir -p "$(dirname "$BROKER_DEST")"
if [[ -f "$BROKER_SOURCE" ]]; then
    cp "$BROKER_SOURCE" "$BROKER_DEST"
else
    curl -sL "https://raw.githubusercontent.com/sebastienrousseau/uon/main/scripts/uon_zsp_broker.py" -o "$BROKER_DEST" || fail "Unable to fetch ZSP broker."
fi

chmod +x "$BROKER_DEST"
chown root:root "$BROKER_DEST"

print_step "Provisioning static least-privilege ZSP identities"

if ! getent group "$EXEC_GROUP" >/dev/null 2>&1; then
    groupadd --system "$EXEC_GROUP"
fi

TARGET_UID=$(id -u "$TARGET_USER")
TARGET_GID=$(id -g "$TARGET_USER")
EXEC_GID=$(getent group "$EXEC_GROUP" | cut -d: -f3)

cat > "$BROKER_ENV_FILE" <<EOF
UON_ZSP_SOCKET=$BROKER_SOCKET_PATH
UON_ZSP_TARGET_UID=$TARGET_UID
UON_ZSP_EXEC_GID=$EXEC_GID
UON_ZSP_SOCKET_UID=$TARGET_UID
UON_ZSP_SOCKET_GID=$TARGET_GID
EOF
chmod 600 "$BROKER_ENV_FILE"
chown root:root "$BROKER_ENV_FILE"

cat > "$BROKER_SERVICE_FILE" <<EOF
[Unit]
Description=UON Zero Standing Privilege Broker
After=network.target

[Service]
Type=simple
EnvironmentFile=$BROKER_ENV_FILE
ExecStart=/usr/bin/env python3 $BROKER_DEST
Restart=on-failure
RuntimeDirectory=uon
RuntimeDirectoryMode=0755
UMask=0007
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=CAP_CHOWN CAP_SETGID CAP_SETUID
AmbientCapabilities=CAP_CHOWN CAP_SETGID CAP_SETUID

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now uon-zsp-broker.service

for _ in $(seq 1 20); do
    [[ -S "$BROKER_SOCKET_PATH" ]] && break
    sleep 0.25
done

[[ -S "$BROKER_SOCKET_PATH" ]] || fail "ZSP broker socket did not appear at $BROKER_SOCKET_PATH."

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
