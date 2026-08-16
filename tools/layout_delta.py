#!/usr/bin/env python3
"""Displacement histogram: (our VA - retail VA) over all matched rows.

Alignment is cumulative, so the useful picture is not "how many rows are
aligned" but "how many distinct displacement plateaus are there, and how big
is each".  A plateau of N rows at delta D means one size correction of D
upstream would align all N at once.

usage: delta.py [report.json] [--save NAME] [--vs NAME]
"""
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPORT = Path("/Users/foxtacles/Projects/isle-build-fin1/LEGO1-report.json")

args = [a for a in sys.argv[1:]]
save = vs = None
if "--save" in args:
    i = args.index("--save")
    save = args[i + 1]
    del args[i:i + 2]
if "--vs" in args:
    i = args.index("--vs")
    vs = args[i + 1]
    del args[i:i + 2]
if args:
    REPORT = Path(args[0])

rep = json.loads(REPORT.read_text())
rows = rep["data"] if isinstance(rep, dict) else rep


def addr(r, k):
    v = r.get(k)
    if isinstance(v, str):
        return int(v, 16)
    return v


pairs = {}
for r in rows:
    a, b = addr(r, "recomp"), addr(r, "address")
    if a is None or b is None:
        continue
    pairs[b] = a - b

print(f"{len(pairs)} rows with both addresses")
c = Counter(pairs.values())
print(f"aligned (delta 0): {c[0]}")
print("top plateaus:")
for d, n in c.most_common(12):
    print(f"  delta {d:+9d}  {n:5d} rows")

if save:
    (HERE / f"delta-{save}.json").write_text(
        json.dumps({hex(k): v for k, v in pairs.items()}))
    print(f"saved delta-{save}.json")

if vs:
    other = {int(k, 16): v
             for k, v in json.loads(
                 (HERE / f"delta-{vs}.json").read_text()).items()}
    common = set(pairs) & set(other)
    moved = {k: (other[k], pairs[k]) for k in common if other[k] != pairs[k]}
    gained = [k for k in common if other[k] != 0 and pairs[k] == 0]
    lost = [k for k in common if other[k] == 0 and pairs[k] != 0]
    print(f"\nvs {vs}: {len(moved)} rows changed delta, "
          f"+{len(gained)} newly aligned, -{len(lost)} de-aligned")
    if moved:
        lo, hi = min(moved), max(moved)
        print(f"  moved-row retail VA range: {lo:#x}..{hi:#x}")
        shifts = Counter(b - a for a, b in moved.values())
        print("  shifts:", dict(shifts.most_common(6)))
