# uon.contracts

## Overview
The `uon.contracts` module acts as the strict typing perimeter between the Python UI layers and the monolithic Rust (`pyo3`) core execution backend. 

## Key Components

- **`fido_dto.py`**: Defines standard Data Transfer Objects (DTOs) utilizing strong `Pydantic` schema validation. This ensures that hardware-generated buffers (such as `credential_id`, `client_data`, and `signature`) are strictly cast and validated before passing over the Rust Foreign Function Interface (FFI) boundary.

## Architecture Guidelines
To maintain cross-language stability, all structures defined within `contracts/` must remain pure domain aggregators. **Do not** import active execution logic (e.g., from `uon.transport` or `uon.auth`) into this directory.
