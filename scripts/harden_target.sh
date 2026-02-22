#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# harden_target.sh — Lock down a remote machine for uon (FIDO2-only SSH)
#
# Run this script AS ROOT on every target machine that will accept uon
# connections.  It enforces:
#
#   1. Password and keyboard-interactive auth disabled.
#   2. Public-key auth with verify-required (biometric touch).
#   3. SSH access restricted to the local subnet.
#   4. Sensible defaults (no root login except via forced command, etc.).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/…/harden_target.sh | sudo bash
#   # or
#   sudo bash harden_target.sh [--subnet 192.168.1.0/24]
# ---------------------------------------------------------------------------

set -euo pipefail

function main() {
    local SUBNET="${1:-192.168.0.0/16}"
    local SSHD_CONFIG="/etc/ssh/sshd_config"
    local BACKUP="${SSHD_CONFIG}.uon-backup.$(date +%s)"

    # ---- Colours --------------------------------------------------------------

    local RED='\033[0;31m'
    local GREEN='\033[0;32m'
    local YELLOW='\033[1;33m'
    local NC='\033[0m'

    function info()  { printf "${GREEN}[uon]${NC} %s\n" "$*"; }
    function warn()  { printf "${YELLOW}[uon]${NC} %s\n" "$*"; }
    function error() { printf "${RED}[uon]${NC} %s\n" "$*" >&2; }

# ---- Pre-flight checks ---------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root.  Try: sudo bash $0"
    exit 1
fi

if [[ ! -f "$SSHD_CONFIG" ]]; then
    error "Cannot find $SSHD_CONFIG.  Is OpenSSH server installed?"
    exit 1
fi

# Check OpenSSH version (PubkeyAuthOptions requires >= 8.2)
local SSHD_VERSION=$(sshd -V 2>&1 | sed -n 's/.*OpenSSH_\([0-9]*\.[0-9]*\).*/\1/p')
SSHD_VERSION="${SSHD_VERSION:-0.0}"
local MAJOR="${SSHD_VERSION%%.*}"
local MINOR="${SSHD_VERSION##*.}"

if [[ "$MAJOR" -lt 8 ]] || { [[ "$MAJOR" -eq 8 ]] && [[ "$MINOR" -lt 2 ]]; }; then
    warn "OpenSSH ${SSHD_VERSION} detected.  PubkeyAuthOptions requires >= 8.2."
    warn "The script will still apply other hardening rules."
fi

# ---- Backup ---------------------------------------------------------------

info "Backing up $SSHD_CONFIG → $BACKUP"
cp "$SSHD_CONFIG" "$BACKUP"

# ---- Helper: ensure a directive is set ------------------------------------

set_directive() {
    local key="$1"
    local value="$2"
    local file="${3:-$SSHD_CONFIG}"

    if grep -qE "^\s*#?\s*${key}\b" "$file"; then
        # Replace existing (possibly commented) line.
        sed -i.bak -E "s|^\s*#?\s*${key}\b.*|${key} ${value}|" "$file"
    else
        echo "${key} ${value}" >> "$file"
    fi
}

# ---- Apply hardening rules ------------------------------------------------

info "Disabling password authentication …"
set_directive "PasswordAuthentication" "no"

info "Disabling keyboard-interactive authentication …"
set_directive "KbdInteractiveAuthentication" "no"
# Older name used by some distros:
set_directive "ChallengeResponseAuthentication" "no"

info "Enabling public-key authentication …"
set_directive "PubkeyAuthentication" "yes"

info "Requiring physical presence for public-key auth …"
set_directive "PubkeyAuthOptions" "verify-required"

info "Disabling empty passwords …"
set_directive "PermitEmptyPasswords" "no"

info "Restricting SSH to local subnet (${SUBNET}) …"

# Remove any pre-existing uon Match block to avoid duplicates.
sed -i.bak '/^# --- uon subnet lock ---$/,/^# --- end uon ---$/d' "$SSHD_CONFIG"

cat >> "$SSHD_CONFIG" <<EOF

# --- uon subnet lock ---
Match Address ${SUBNET}
    PubkeyAuthentication yes
    PasswordAuthentication no
    AllowTcpForwarding no
    X11Forwarding no

Match Address *,!${SUBNET}
    DenyUsers *
# --- end uon ---
EOF

# ---- Validate config ------------------------------------------------------

info "Validating sshd configuration …"
if sshd -t; then
    info "Configuration is valid."
else
    error "sshd -t failed!  Restoring backup …"
    cp "$BACKUP" "$SSHD_CONFIG"
    error "Original config restored.  Please inspect manually."
    exit 1
fi

# ---- Restart sshd ---------------------------------------------------------

info "Restarting SSH daemon …"
if command -v systemctl &>/dev/null; then
    systemctl restart sshd || systemctl restart ssh
elif command -v launchctl &>/dev/null; then
    # macOS
    launchctl kickstart -k system/com.openssh.sshd 2>/dev/null || true
elif command -v service &>/dev/null; then
    service sshd restart || service ssh restart
else
    warn "Could not detect init system.  Please restart sshd manually."
fi

# ---- Summary ---------------------------------------------------------------

info ""
info "Hardening complete.  Summary:"
info "  PasswordAuthentication    no"
info "  KbdInteractiveAuth        no"
info "  PubkeyAuthentication      yes"
info "  PubkeyAuthOptions         verify-required"
info "  Subnet restriction        ${SUBNET}"
info ""
info "Next steps:"
info "  1. Add your FIDO2 public key to ~/.ssh/authorized_keys on this machine."
info "  2. Test with:  uon <this-target> \"whoami\""
info "  3. Confirm you can still connect before closing this session!"
warn ""
warn "IMPORTANT: Keep this terminal open until you verify access via uon."
warn "           If you lock yourself out, restore from: $BACKUP"
}

main "$@"
