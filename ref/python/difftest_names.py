#!/usr/bin/env python3
"""Differential test for the object name mapping: Python against Go.

The companion to difftest.py, for docs/FORMAT.md section 15. It checks the two
implementations in both directions, because the mapping is deterministic and
each direction catches a different kind of mistake.

**Forward.** Go maps a random object key; Python must produce the same stored
key, character for character. A disagreement here means one of them has the
construction wrong -- the context a segment is bound to, the length prefixes,
the counter block, the encoding.

**Reverse, under mutation.** Stored keys are then damaged -- a flipped
character, a truncated segment, two segments swapped, a non-canonical base32
spelling -- and fed to both. The only thing they have to agree on is the
verdict: accepted with this object key, or rejected. Error messages are not part
of the format and are not compared.

A disagreement is always a finding. If one accepts what the other rejects, the
specification is ambiguous or one of them is wrong; if both accept and the keys
differ, one of them is very wrong.

    python3 ref/python/difftest_names.py --count 20000
"""

from __future__ import annotations

import argparse
import json
import pathlib
import random
import subprocess
import sys

from names_ref import NameError_, decrypt_key, encrypt_key

REPO = pathlib.Path(__file__).resolve().parents[2]
B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def go_seeds(count: int) -> list[dict]:
    """Ask the Go implementation for mapped keys."""
    result = subprocess.run(
        ["go", "run", "./test/difftool", "-names", str(count)],
        cwd=REPO, capture_output=True, check=True,
    )
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def go_decrypt(inputs: list[dict]) -> list[dict]:
    """Ask the Go implementation to reverse a batch of stored keys."""
    payload = "".join(json.dumps(item) + "\n" for item in inputs)
    result = subprocess.run(
        ["go", "run", "./test/difftool", "-names-decode"],
        cwd=REPO, input=payload.encode(), capture_output=True, check=True,
    )
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def mutate(rng: random.Random, stored: str) -> str:
    """Damage a stored key in a way that leaves it nearly valid.

    The weights matter more than the mutations. A uniformly random string is
    rejected by both at the base32 check and proves nothing; what separates two
    implementations is an input that is *almost* right.
    """
    if not stored:
        return rng.choice(["A", "=", "/"])
    segments = stored.split("/")
    choice = rng.random()

    if choice < 0.30:
        # One character, to another legal base32 character. Still decodes; the
        # synthetic IV must be what rejects it.
        i = rng.randrange(len(stored))
        replacement = rng.choice(B32_ALPHABET)
        return stored[:i] + replacement + stored[i + 1:]

    if choice < 0.45:
        # Truncate a segment, often below the 16-byte IV.
        i = rng.randrange(len(segments))
        if segments[i]:
            cut = rng.randrange(len(segments[i]))
            segments[i] = segments[i][:cut]
        return "/".join(segments)

    if choice < 0.60 and len(segments) > 1:
        # Swap two segments. Both decrypt, and the position binding of section
        # 15.4 step 5 is the only thing that catches it.
        i, j = rng.sample(range(len(segments)), 2)
        segments[i], segments[j] = segments[j], segments[i]
        return "/".join(segments)

    if choice < 0.72:
        # A character outside the alphabet, including padding and lowercase.
        i = rng.randrange(len(stored))
        return stored[:i] + rng.choice("=abc!*") + stored[i + 1:]

    if choice < 0.84:
        # Append to a segment, so it is no longer a whole number of blocks.
        i = rng.randrange(len(segments))
        segments[i] += rng.choice(B32_ALPHABET)
        return "/".join(segments)

    if choice < 0.92:
        # Add or remove a separator, which changes the segment structure.
        i = rng.randrange(len(stored) + 1)
        return stored[:i] + "/" + stored[i:]

    # Drop a whole segment.
    if len(segments) > 1:
        del segments[rng.randrange(len(segments))]
    return "/".join(segments)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--count", type=int, default=20000, help="inputs to compare")
    parser.add_argument("--seeds", type=int, default=2000, help="mapped keys to draw from")
    parser.add_argument("--seed", type=int, default=0, help="RNG seed, for reproducing a finding")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    print(f"asking Go for {args.seeds} mapped keys...")
    seeds = go_seeds(args.seeds)
    if not seeds:
        print("the Go side produced no seeds", file=sys.stderr)
        return 1

    # Direction one: the stored key is what the specification fixes.
    forward_failures = 0
    for seed in seeds:
        name_key = bytes.fromhex(seed["name_key"])
        try:
            got = encrypt_key(name_key, seed["plain"])
        except Exception as err:  # noqa: BLE001 - any failure is a disagreement
            print(f"  FAIL  mapping {seed['plain']!r}: {err}")
            forward_failures += 1
            continue
        if got != seed["stored"]:
            print(f"  FAIL  mapping {seed['plain']!r}:\n"
                  f"          python {got}\n          go     {seed['stored']}")
            forward_failures += 1
    print(f"forward: {len(seeds) - forward_failures}/{len(seeds)} keys map identically")

    # Direction two: mutated stored keys, compared on the verdict alone.
    inputs: list[dict] = []
    for _ in range(args.count):
        seed = rng.choice(seeds)
        stored = seed["stored"] if rng.random() < 0.15 else mutate(rng, seed["stored"])
        inputs.append({"name_key": seed["name_key"], "stored": stored})

    print(f"comparing {len(inputs)} stored keys through both implementations...")
    go_verdicts = go_decrypt(inputs)
    if len(go_verdicts) != len(inputs):
        print(f"go returned {len(go_verdicts)} verdicts for {len(inputs)} inputs", file=sys.stderr)
        return 1

    accepted = 0
    reverse_failures = 0
    for item, go_verdict in zip(inputs, go_verdicts, strict=True):
        try:
            py_plain = decrypt_key(bytes.fromhex(item["name_key"]), item["stored"])
            py_ok, py_err = True, ""
        except (NameError_, ValueError) as err:
            py_plain, py_ok, py_err = "", False, str(err)

        if py_ok != go_verdict["ok"]:
            side = "python accepted, go rejected" if py_ok else "go accepted, python rejected"
            print(f"  FAIL  {side}: {item['stored']!r}\n"
                  f"          go:     {go_verdict.get('err', go_verdict.get('plain'))!r}\n"
                  f"          python: {py_err or py_plain!r}")
            reverse_failures += 1
            continue
        if py_ok:
            accepted += 1
            if py_plain != go_verdict.get("plain", ""):
                print(f"  FAIL  both accepted, different keys: {item['stored']!r}\n"
                      f"          go     {go_verdict.get('plain')!r}\n"
                      f"          python {py_plain!r}")
                reverse_failures += 1

    print(f"reverse: {len(inputs) - reverse_failures}/{len(inputs)} agree "
          f"({accepted} accepted, {len(inputs) - accepted} rejected by both)")

    if forward_failures or reverse_failures:
        print(f"\n{forward_failures + reverse_failures} disagreements")
        return 1
    print("\nthe two implementations agree on every input")
    return 0


if __name__ == "__main__":
    sys.exit(main())
