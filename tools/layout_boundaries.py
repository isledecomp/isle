#!/usr/bin/env python3
"""Classify the 364 displacement boundaries and rank them by rows carried.

A boundary's "reach" is how many rows downstream inherit it before the next
boundary of opposite sign -- but the honest, simple ranking is: how many rows
sit between this boundary and the next one, times nothing else.  What matters
for a work queue is (class, |step|, rows carried until the displacement next
changes).
"""
import json
import re
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent

# The reccmp report scores the /debug link, whose .rdata starts 88 bytes later
# than the terminal image's (an 88-byte debug directory sits at its head), so
# every .rdata displacement read straight from the report is 88 bytes high.
RDATA_BASE = 0x100d0000
DEBUG_DIRECTORY_BYTES = 88


def terminal_delta(retail_va: int, our_va: int) -> int:
    """(our - retail) as the byte-identical image will see it."""
    delta = our_va - retail_va
    return delta - DEBUG_DIRECTORY_BYTES if retail_va >= RDATA_BASE else delta


rep = json.loads(Path("/Users/foxtacles/Projects/isle-build-lean/"
                      "LEGO1-report.json").read_text())["data"]
rows = sorted(((int(r["address"], 16), int(r["recomp"], 16),
                r.get("name", "?"), r.get("matching", 0.0))
               for r in rep if "recomp" in r), key=lambda t: t[0])

pub = {}
for line in open(HERE / "maplink" / "LEGO1.map", errors="replace"):
    m = re.match(r"\s*(\d{4}):([0-9A-Fa-f]{8})\s+(\S+)\s+([0-9A-Fa-f]{8})"
                 r"\s+\S*\s*(\S+)", line)
    if m and m.group(1) == "0001":
        pub[int(m.group(4), 16)] = m.group(5).split("/")[-1]

bounds = []
for i, ((ra, oa, na, ma), (rb, ob, nb, mb)) in enumerate(zip(rows, rows[1:])):
    da, db = terminal_delta(ra, oa), terminal_delta(rb, ob)
    if da != db:
        bounds.append((i, db - da, ra, rb, na, nb,
                       pub.get(oa, "?"), pub.get(ob, "?"), ma, mb))

cls = Counter()
for _, st, _, _, _, _, oa, ob, ma, mb in bounds:
    same = oa == ob and oa != "?"
    if same:
        cls["a  intra-object COMDAT transposition"] += 1
    elif ma < 1.0 or mb < 1.0:
        cls["d  open row at the boundary"] += 1
    else:
        cls["b/c cross-object step"] += 1

print(f"{len(bounds)} displacement boundaries")
for k, v in cls.most_common():
    print(f"  {v:4d}  {k}")

carried = []
for j, b in enumerate(bounds):
    nxt = bounds[j + 1][0] if j + 1 < len(bounds) else len(rows) - 1
    carried.append((nxt - b[0], b))
carried.sort(reverse=True, key=lambda t: t[0])

print("\ntop boundaries by rows carried before the displacement next changes:")
for n, (_, st, ra, rb, na, nb, oa, ob, ma, mb) in carried[:15]:
    kind = "a" if oa == ob and oa != "?" else (
        "d" if min(ma, mb) < 1.0 else "b/c")
    print(f"  {n:4d} rows  step {st:+6d}  [{kind:3s}] {ra:#010x}  "
          f"{oa} -> {ob}")
    print(f"              {na[:52]}")
    print(f"           -> {nb[:52]}")
