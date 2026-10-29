#!/usr/bin/env python3
"""Check the independent keyring reader against the known-answer vectors.

docs/FORMAT.md section 18.8 makes these vectors a normative part of the
specification: an implementation that opens every accepted file to exactly the
keys, tenants and buckets listed, and refuses every other, implements the
section. This is that check.

    python3 ref/python/test_keyring_vectors.py
"""

from __future__ import annotations

import json
import pathlib
import sys

from keyring_ref import Malformed, Tenant, open_keyring

VECTORS = pathlib.Path(__file__).resolve().parents[2] / "testdata" / "vectors" / "keyring_v2.json"


def describe(t: Tenant) -> dict:
    return {
        "active_kid": t.active_kid,
        "keks": {kid: k.hex() for kid, k in t.keks.items()},
        "name_key": t.name_key.hex() if t.name_key else "",
    }


def main() -> int:
    vectors = json.loads(VECTORS.read_text())["vectors"]
    print(f"{VECTORS.name}: {len(vectors)} vectors")

    failures = 0
    for v in vectors:
        roots = {name: bytes.fromhex(h) for name, h in (v.get("tenant_roots") or {}).items()}
        try:
            opened = open_keyring(v["file"].encode(), bytes.fromhex(v["deployment_root"]),
                                  lambda name, _lock: roots.get(name))
        except Malformed as e:
            if v.get("refused"):
                print(f"  ok    {v['name']}: refused ({e})")
                continue
            failures += 1
            print(f"  FAIL  {v['name']}: refused a file it must open: {e}")
            continue
        if v.get("refused"):
            failures += 1
            print(f"  FAIL  {v['name']}: opened a file that breaks {v['refused']!r}")
            continue

        want = v["expect"]
        got = {
            "default": describe(opened.default),
            "tenants": {name: describe(t) for name, t in opened.tenants.items()},
            "unopened": opened.unopened,
            "buckets": {b: dict(zip(("tenant", "destroyed"), opened.tenant_of(b))) for b in want["buckets"]},
        }
        bad = [k for k in got if got[k] != want[k]]
        if bad:
            failures += 1
            print(f"  FAIL  {v['name']}: {', '.join(bad)} differ")
        else:
            print(f"  ok    {v['name']}")

    print("all vectors pass" if not failures else f"{failures} of {len(vectors)} vectors FAIL")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
