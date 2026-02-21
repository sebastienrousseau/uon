#!/usr/bin/env python3
"""uon Setup Utility.

Registers a new FIDO2 Passkey and exports the COSE public key for remote targets.
"""

import contextlib
import json
import os
import sys

from fido2 import cbor
from fido2.client import Fido2Client, WindowsClient
from fido2.hid import CtapHidDevice

UON_RP_ID = "uon.local"
UON_DIR = os.path.expanduser("~/.config/uon")


def register_and_extract() -> None:
    """Register a hardware passkey and export the COSE public key to disk."""
    os.makedirs(UON_DIR, exist_ok=True)

    print("[*] Initializing FIDO2 Passkey Registration...")

    # 1. Resolve the best available native FIDO2 client
    if sys.platform == "win32":
        if not WindowsClient.is_available():
            print("[!] Windows Hello not available or not configured.")
            sys.exit(1)
        client = WindowsClient("https://" + UON_RP_ID)
    else:
        devices = list(CtapHidDevice.list_devices())
        if not devices:
            print("[!] No physical FIDO2 keys found on USB bus. Insert a YubiKey/Security Key.")
            sys.exit(1)
        client = Fido2Client(devices[0], "https://" + UON_RP_ID)

    # 2. Trigger hardware generation of the Resident Key
    print("\n[UON] Please authenticate with your biometric or touch your security key...")

    attestation, _client_data = client.make_credential(
        options={
            "challenge": b"uon_setup_initialization_nonce",
            "rp": {"id": UON_RP_ID, "name": "uon Terminal Security"},
            "user": {"id": b"uon_admin_01", "name": "uon_admin"},
            # Algorithm -7 is ES256 (ECDSA w/ SHA-256), widely supported by hardware keys
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "authenticatorSelection": {
                "residentKey": "required",
                "userVerification": "required",
            },
        }
    )

    # 3. Parse the Attestation Object to extract the COSE Public Key
    auth_data = attestation.auth_data
    credential_data = auth_data.credential_data

    # The public key is a CoseKey object. We encode it to CBOR, then to a hex string.
    cose_key = credential_data.public_key
    cose_key_hex = cbor.encode(dict(cose_key)).hex()

    # Extract the credential ID to map the key
    cred_id_hex = credential_data.credential_id.hex()

    # 4. Save to the local authorized_passkeys.json list
    export_path = os.path.join(UON_DIR, "authorized_passkeys.json")

    key_record = {
        "name": "uon_primary_passkey",
        "credential_id_hex": cred_id_hex,
        "cose_key_hex": cose_key_hex,
    }

    keys: list[dict[str, str]] = []
    if os.path.exists(export_path):
        with open(export_path) as f, contextlib.suppress(json.JSONDecodeError):
            keys = json.load(f)

    keys.append(key_record)

    with open(export_path, "w") as f:
        json.dump(keys, f, indent=4)

    print("\n[+] Registration successful!")
    print(f"[+] COSE Public Key extracted and saved to: {export_path}")
    print("\n[!] NEXT STEP: Securely copy this JSON file to your remote machines:")
    print(f"    scp {export_path} user@target_ip:~/.config/uon/authorized_passkeys.json")


if __name__ == "__main__":
    register_and_extract()
