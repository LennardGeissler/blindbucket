#!/usr/bin/env python3
"""Check the independent tag sidecar against the known-answer vectors.

docs/FORMAT.md section 17.5 makes these vectors a normative part of the
specification: an implementation that reproduces encoded, sidecar and path byte
for byte implements the section. This is that check, and a few refusals the
section requires of a decoder.

    python3 ref/python/test_tags_vectors.py
"""

from __future__ import annotations

import json
import pathlib
import sys

from tags_ref import TagError, decode, encode, open_, path, seal

VECTORS = pathlib.Path(__file__).resolve().parents[2] / "testdata" / "vectors" / "tags_v1.json"


def main() -> int:
    document = json.loads(VECTORS.read_text())
    vectors = document["vectors"]
    print(f"{VECTORS.name}: {len(vectors)} vectors")

    failures = 0
    for v in vectors:
        tags = [(t["key"], t["value"]) for t in v.get("tags") or []]
        dek, nonce = bytes.fromhex(v["dek"]), bytes.fromhex(v["nonce"])
        checks = {
            "encoded": encode(tags).hex() == v["encoded"],
            "sidecar": seal(dek, nonce, v["bucket"], v["key"], tags).hex() == v["sidecar"],
            "path": path(v["stored_key"], v["wrapped_dek"]) == v["path"],
            "opens": open_(dek, v["bucket"], v["key"], bytes.fromhex(v["sidecar"])) == tags,
        }
        bad = [name for name, ok in checks.items() if not ok]
        if bad:
            failures += 1
            print(f"FAIL {v['name']}: {', '.join(bad)}")

    # What section 17.2 and 17.3 require a reader to refuse.
    first = vectors[1]
    dek = bytes.fromhex(first["dek"])
    sidecar = bytes.fromhex(first["sidecar"])
    refusals = {
        "unsorted keys": lambda: decode(bytes([2]) + b"\x00\x01b\x00\x00\x00\x01a\x00\x00"),
        "a key twice": lambda: decode(bytes([2]) + b"\x00\x01a\x00\x00\x00\x01a\x00\x00"),
        "eleven tags": lambda: decode(bytes([11])),
        "trailing bytes": lambda: decode(b"\x00\x00"),
        "another key": lambda: open_(dek, first["bucket"], first["key"] + "x", sidecar),
        "altered": lambda: open_(dek, first["bucket"], first["key"], sidecar[:-1] + bytes([sidecar[-1] ^ 1])),
    }
    for name, attempt in refusals.items():
        try:
            attempt()
        except TagError:
            continue
        failures += 1
        print(f"FAIL accepted: {name}")

    if failures:
        print(f"{failures} failures")
        return 1
    print("all vectors reproduced, all refusals refused")
    return 0


if __name__ == "__main__":
    sys.exit(main())
