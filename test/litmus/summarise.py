#!/usr/bin/env python3
"""Turn litmus JSON lines into a Markdown table: one row per test, one column
per provider, each cell the verdict and how many repetitions agreed.

  summarise.py results/2026-10-07/*.jsonl > results/2026-10-07/results.md
"""
import collections
import json
import sys

ORDER = ["cond-put-inm", "cond-put-im", "cond-complete-im", "cond-complete-inm",
         "copy-source-im", "overlap-mpu-mpu", "overlap-mpu-put", "read-after-write"]

rows = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
err200 = collections.Counter()
providers = []
for path in sys.argv[1:]:
    for line in open(path):
        r = json.loads(line)
        p = r["provider"]
        if p not in providers:
            providers.append(p)
        rows[r["test"]][p][r["verdict"]] += 1
        err200[p] += len(r.get("error_in_200", []))

print("| Test | " + " | ".join(providers) + " |")
print("|---|" + "---|" * len(providers))
for t in ORDER:
    cells = []
    for p in providers:
        c = rows[t][p]
        n = sum(c.values())
        cells.append("; ".join(f"{v} ({k}/{n})" for v, k in c.most_common()) or "—")
    print(f"| `{t}` | " + " | ".join(cells) + " |")
print("| error inside a 200 | " + " | ".join(f"{err200[p]} seen" for p in providers) + " |")
