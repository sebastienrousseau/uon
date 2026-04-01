"""Benchmark-backed regression checks for cache-sensitive hot paths."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from uon.utils.config import Target, TargetStore


def _import_verifier() -> Any:
    spec = importlib.util.spec_from_file_location(
        "uon_verifier_bench",
        str(Path(__file__).resolve().parents[2] / "scripts" / "uon_verifier.py"),
        submodule_search_locations=[],
    )
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    for name in (
        "fido2",
        "fido2.cbor",
        "fido2.cose",
        "fido2.webauthn",
    ):
        if name not in sys.modules:
            sys.modules[name] = MagicMock()
    spec.loader.exec_module(mod)
    mod._AUTHORIZED_KEYS_CACHE = None
    return mod


def test_load_authorized_keys_warm_cache_skips_reparse(tmp_path: Path) -> None:
    verifier = _import_verifier()
    verifier.AUTHORIZED_KEYS_FILE = str(tmp_path / "authorized_passkeys.json")
    Path(verifier.AUTHORIZED_KEYS_FILE).write_text(
        json.dumps([{"cose_key_hex": "a0"}]),
        encoding="utf-8",
    )
    verifier.CoseKey = MagicMock(parse=MagicMock(return_value=MagicMock()))
    verifier.cbor = MagicMock(decode=MagicMock(return_value={}))
    verifier.load_authorized_keys()
    result = verifier.load_authorized_keys()

    assert len(result) == 1
    assert verifier.CoseKey.parse.call_count == 1


def test_target_store_unchanged_add_preserves_cached_payload(tmp_path: Path) -> None:
    store = TargetStore(path=tmp_path / "targets.json")
    target = Target(alias="prod", host="10.0.0.1", user="root")
    store.add(target)
    cached_payload = store._serialized_payload
    store.add(target)

    assert store.get("prod") == target
    assert store._serialized_payload == cached_payload
