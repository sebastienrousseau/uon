# uon.utils

## Overview
The `uon.utils` package provisions the local infrastructure for the Python components. It handles host storage, data persistence models, and security policy validators.

## Key Components

- **`config.py`**: Exports the `TargetStore` and `Target` dataclasses. This handles the serializing (and deserializing) of JSON / SQLite data tracking registered remote hosts and their enrolled `credential_id` mappings.
- **`policy.py`**: Exports the `PolicyStore`, an enforcement layer determining if a specific hardware FIDO2 `AAGUID` (Authenticator Attestation Global Unique Identifier) is explicitly permitted to mint new Zero-Trust passkeys within the current ecosystem.

## Usage
`uon.utils` is a pure dependency injected layer. It should not pull logic from `transport/` or `ux/` due to cyclic references within the `click` router.
