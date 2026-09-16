#!/usr/bin/env python3
"""Check the independent name mapping against the known-answer vectors.

docs/FORMAT.md section 15.6 makes these vectors a normative part of the
specification: "An implementation that reproduces every stored_key character for
character implements this section." This is that check.

Both directions are checked. The stored key is what the specification fixes, so
reproducing it is the real evidence; the round trip back is what catches an
implementation that happens to agree on the ciphertext but not on how to read it.

    python3 ref/python/test_names_vectors.py
"""

from __future__ import annotations

import json
import pathlib
import sys

from names_ref import NameError_, decrypt_key, encrypt_key

VECTORS = pathlib.Path(__file__).resolve().parents[2] / "testdata" / "vectors" / "names_v1.json"


def main() -> int:
    document = json.loads(VECTORS.read_text())
    vectors = document["vectors"]
    print(f"{VECTORS.name}: {len(vectors)} vectors")

    failures = 0
    for vector in vectors:
        name = vector["name"]
        name_key = bytes.fromhex(vector["name_key"])
        plain = vector["plaintext_key"]
        want = vector["stored_key"]

        try:
            got = encrypt_key(name_key, plain)
        except (NameError_, ValueError) as err:
            print(f"  FAIL  {name}: encrypting: {err}")
            failures += 1
            continue
        if got != want:
            print(f"  FAIL  {name}: stored key differs\n          got  {got}\n          want {want}")
            failures += 1
            continue

        try:
            back = decrypt_key(name_key, want)
        except (NameError_, ValueError) as err:
            print(f"  FAIL  {name}: decrypting: {err}")
            failures += 1
            continue
        if back != plain:
            print(f"  FAIL  {name}: round trip gave {back!r}, want {plain!r}")
            failures += 1
            continue

        shown = plain if plain else "(empty)"
        print(f"  ok    {name}: {shown} -> {len(want)} characters")

    if failures:
        print(f"\n{failures} of {len(vectors)} vectors failed")
        return 1
    print(f"\nall {len(vectors)} vectors map as specified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
