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
REPORT = Path("/Users/foxtacles/Projects/isle-build-lean/LEGO1-report.json")

# The reccmp report scores the /debug link, which carries an 88-byte debug
# directory at the head of .rdata; the terminal (no-/debug) image does not.
# Every .rdata row therefore reads 88 bytes high here and must be corrected,
# or the alignment count is wrong by the whole .rdata population.
#
# This threshold is retail's .rdata VA and nothing else.  It read 0x100d0000
# until 2026-08-20, which wrongly corrected the 46 .text rows in
# [0x100d052c, 0x100d2270] -- the Smack/CRT tail of .text, which runs to
# 0x100d3d66 -- and under-reported the aligned count by exactly those 46.
RDATA_BASE = 0x100d4000
# The /debug link's .rdata head carries an 88-byte debug directory.  That shifts
# lego1's own .rdata by 88, but only by 80 from the CRT block onward: the
# 16-byte section alignment absorbs 8 of it.  Using a blanket 88 under-reports
# every library row by 8.
CRT_RDATA_BASE = 0x100daa70
DEBUG_DIRECTORY_BYTES = 88
CRT_DEBUG_DIRECTORY_BYTES = 80


def terminal_delta(retail_va: int, our_va: int) -> int:
    """(our - retail) as the byte-identical image will see it."""
    delta = our_va - retail_va
    if retail_va >= CRT_RDATA_BASE:
        return delta - CRT_DEBUG_DIRECTORY_BYTES
    if retail_va >= RDATA_BASE:
        return delta - DEBUG_DIRECTORY_BYTES
    return delta

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
    pairs[b] = terminal_delta(b, a)

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
