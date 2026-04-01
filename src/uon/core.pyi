from __future__ import annotations

Challenge = tuple[bytes, bytes]
SessionResult = tuple[int, str, str]

def generate_challenge() -> Challenge: ...
def execute_session(
    host: str,
    port: int,
    username: str,
    command: str,
    session_id: bytes,
    credential_id: bytes,
    client_data: bytes,
    auth_data: bytes,
    signature: bytes,
) -> SessionResult: ...
def compute_amdns_hmac(ble_secret: bytes, target_alias: str, timestamp: int) -> str: ...
def verify_discovery_beacon(
    ble_secret: bytes,
    target_alias: str,
    reported_hmac: str,
    time_tolerance_seconds: int = 30,
) -> bool: ...
def parse_ssf_event(payload: str) -> str | None: ...
def spawn_zsp_process(command: str) -> int: ...
def freeze_execution(pid: int) -> None: ...
def resume_execution(pid: int) -> None: ...
