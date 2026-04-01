#!/usr/bin/env python3
"""Micro-benchmark hot paths that were optimized for cache locality and reuse."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import timeit
from pathlib import Path
from statistics import mean
from types import ModuleType
from unittest.mock import MagicMock

from uon.utils.config import Target, TargetStore


def _import_verifier() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "uon_verifier_benchmark",
        str(Path(__file__).resolve().with_name("uon_verifier.py")),
        submodule_search_locations=[],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load uon_verifier benchmark module")
    module = importlib.util.module_from_spec(spec)
    for name in ("fido2", "fido2.cbor", "fido2.cose", "fido2.webauthn"):
        if name not in sys.modules:
            sys.modules[name] = MagicMock()
    spec.loader.exec_module(module)
    module._AUTHORIZED_KEYS_CACHE = None
    return module


def _sample_timings(stmt: callable, iterations: int = 200) -> dict[str, float]:
    samples = timeit.repeat(stmt, number=1, repeat=iterations)
    return {
        "min_us": min(samples) * 1_000_000,
        "avg_us": mean(samples) * 1_000_000,
    }


def benchmark_authorized_key_cache(tmp_dir: Path) -> dict[str, float]:
    verifier = _import_verifier()
    verifier.AUTHORIZED_KEYS_FILE = str(tmp_dir / "authorized_passkeys.json")
    Path(verifier.AUTHORIZED_KEYS_FILE).write_text(
        json.dumps([{"cose_key_hex": "a0"}]),
        encoding="utf-8",
    )
    verifier.CoseKey = MagicMock(parse=MagicMock(return_value=MagicMock()))
    verifier.cbor = MagicMock(decode=MagicMock(return_value={}))

    cold = timeit.timeit(verifier.load_authorized_keys, number=1) * 1_000_000
    warm = _sample_timings(verifier.load_authorized_keys)
    warm["cold_us"] = cold
    warm["parse_calls"] = float(verifier.CoseKey.parse.call_count)
    return warm


def benchmark_target_store_noop_write(tmp_dir: Path) -> dict[str, float]:
    store = TargetStore(path=tmp_dir / "targets.json")
    target = Target(alias="prod", host="10.0.0.1", user="root")
    store.add(target)

    baseline = _sample_timings(lambda: store.add(target))
    baseline["payload_bytes"] = float(len(store._serialized_payload or ""))
    return baseline


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="uon-bench-") as tmp:
        tmp_dir = Path(tmp)
        result = {
            "authorized_key_cache": benchmark_authorized_key_cache(tmp_dir),
            "target_store_noop_add": benchmark_target_store_noop_write(tmp_dir),
        }
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
