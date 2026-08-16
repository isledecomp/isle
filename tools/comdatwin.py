#!/usr/bin/env python3
"""COMDAT-winner screen: for each open row, which object's copy did the
linker actually keep?

Why this exists
---------------
A template body can be emitted into many objects.  The linker keeps exactly
one copy and discards the rest, and which one it keeps is decided by link
order -- not by us.  A carrier sweep that drives some *discarded* object's
copy to a byte-exact match therefore buys nothing: the image never sees it.

That is not hypothetical.  A sweep of `worlds/infocenter.cpp` drove
`_Tree<MxCore*,...>::erase` (0x1001d890) to a masked distance of 0 at the
correct 1106-byte length, and the row did not move one bit, because
`entity/legoworld.cpp` wins that COMDAT and infocenter's exact copy is
dropped on the floor.

So before funding any row, ask this tool which object you have to move.

Verdicts
--------
  SOLE       one object defines the symbol; sweep that TU, no hazard.
  CONTESTED  several objects define it.  The winner is named, and every
             definer is priced against retail, so you can see whether the
             body you need is reachable from the TU that actually wins.
  UNMATCHED  no indexed COMDAT body reproduces the linked bytes.  Normally
             means the row is not a COMDAT at all (an ordinary function in
             a single object, matched by name elsewhere) -- not a defect.

Nothing here is a source change; it reads the build tree and the two images.

usage:
    comdatwin.py [--json OUT.json] [--md OUT.md] [--all]
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import byte_identity as bi  # noqa: E402
import slotmap as SL  # noqa: E402

BUILD = Path("/Users/foxtacles/Projects/isle-build-arch")
REPORT = BUILD / "LEGO1-report.json"
COMPILE_COMMANDS = BUILD / "build/compile_commands.json"

# Longest body we are willing to fingerprint out of the image.
MAX_BODY = 1 << 16
# Bytes of leading body used as a cheap index key.
KEY = 8


def is_comdat_function(coff: bi.CoffObject, symbol: dict) -> bool:
    """The same predicate CoffObject.function_section uses, minus uniqueness."""
    if not (symbol["section"] > 0 and symbol["value"] == 0
            and symbol["type"] == 0x20 and symbol["storage"] in (2, 3)):
        return False
    section = coff.sections[symbol["section"] - 1]
    return (section["name"].startswith(".text")
            and bool(section["characteristics"] & 0x1000))


def mask(buf: bytes, offsets) -> bytes:
    """Zero every relocated field so fix-ups cannot decide a comparison."""
    out = bytearray(buf)
    for off in offsets:
        for i in range(off, min(off + 4, len(out))):
            out[i] = 0
    return bytes(out)


# compile_commands covers all three images.  Objects built for CONFIG and ISLE
# are never linked into LEGO1, so counting them as definers invents contested
# rows -- mxdirectxinfo.cpp is compiled by both lego1 and config, and appeared
# twice under one basename until this filter existed.
FOREIGN_TARGETS = ("CMakeFiles/config.dir/", "CMakeFiles/isle.dir/")


def objects() -> list[Path]:
    entries = json.loads(COMPILE_COMMANDS.read_text())
    found = []
    for entry in entries:
        argv = shlex.split(entry["command"])
        rel = next((a[3:] for a in argv if a.startswith("/Fo")), None)
        if not rel or any(t in rel.replace("\\", "/") for t in FOREIGN_TARGETS):
            continue
        path = Path(entry["directory"]) / rel
        if path.is_file():
            found.append(path)
    return found


def trim_fill(blob: bytes) -> bytes:
    """Strip only the aligner's trailing fill.

    Deliberately not slotmap.body_of, which also truncates at a trailing jump
    table.  That truncation is right for disassembly and wrong here: a COMDAT
    body carries its jump table, so a table-truncated retail body reads as
    ~144 bytes shorter than the object that produced it.
    """
    out = bytearray(blob)
    while out and out[-1] in (0xCC, 0x90):
        out.pop()
    return bytes(out)


def build_index(paths):
    """mangled -> [{obj, body, relocs}], plus a leading-bytes lookup."""
    by_symbol: dict[str, list[dict]] = {}
    by_key: dict[bytes, list[dict]] = {}
    early: list[dict] = []
    for path in paths:
        try:
            coff = bi.CoffObject(path.read_bytes())
        except Exception:
            continue
        for symbol in coff.symbols.values():
            try:
                if not is_comdat_function(coff, symbol):
                    continue
                section = coff.sections[symbol["section"] - 1]
                body = bytes(bi.coff_body(coff, section))
                if not body or len(body) > MAX_BODY:
                    continue
                relocs = sorted(r["offset"] for r in
                                bi.detailed_relocations(coff, section))
            except Exception:
                continue
            rec = {"obj": path, "name": symbol["name"], "body": body,
                   "relocs": relocs}
            by_symbol.setdefault(symbol["name"], []).append(rec)
            if any(off < KEY for off in relocs):
                early.append(rec)
            else:
                by_key.setdefault(body[:KEY], []).append(rec)
    return by_symbol, by_key, early


GENERIC_TOKENS = frozenset("""class struct const unsigned char int long short void
pair map set multiset vector list allocator basic_string first second""".split())


def name_tokens(text: str) -> set:
    return {t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text)
            if t not in GENERIC_TOKENS and len(t) > 2}


def rank_by_name(candidates, row_name):
    """Order masked-equal candidates by agreement with reccmp's annotation.

    Two instantiations that differ only in relocation targets are masked-equal,
    so the bytes cannot choose between them.  The row's demangled name can:
    the distinctive type tokens in it appear in the right symbol's mangled
    name.  Without this, 0x10057180 attributes to `_Tree<MxAtom*>::_Erase` in
    mxmain.cpp when reccmp is tracking `_Tree<LegoAnimPresenter*>::_Erase` --
    and a sweep of the named TU then scores nothing at all.
    """
    if len(candidates) < 2:
        return candidates
    # Substring containment, not token equality: a mangled name encodes the
    # type as `PAVLegoAnimPresenter`, so the row's `LegoAnimPresenter` token
    # is never equal to any mangled token, only contained in one.
    want = name_tokens(row_name)
    return sorted(candidates,
                  key=lambda r: -sum(1 for t in want if t in r["name"]))


def raw_slice(image, va, length) -> bytes:
    """Untrimmed image bytes.

    Deliberately not slotmap.body_of: that trims trailing 0xCC/0x90 fill,
    which is right for disassembly but wrong here, where we are testing
    whether a whole object body reproduces the linked bytes.
    """
    base, data = image
    start = va - base
    if start < 0 or start >= len(data):
        return b""
    return bytes(data[start:start + length])


def identify(image, row, by_key, early):
    """Object COMDATs that reproduce the linked body: (exact, masked-only).

    Returns lists, not one record, because the linker folds identical COMDATs
    (/OPT:ICF).  Structurally unrelated instantiations can compile to the same
    bytes and share one address, and returning the first match would name one
    arbitrary symbol as "the" winner and hide the rest.

    Masked equality alone is NOT evidence of folding: two instantiations can
    differ only in their relocation TARGETS (a different comparator, a
    different allocator), which masking erases.  Those twins are distinct
    bodies at distinct addresses -- `_Tree<LegoAnimStruct>::_Insert` and
    `_Tree<LegoHideAnimStruct>::_Insert` are masked-equal and live at both
    0x1006a7a0 and 0x1006e720.  So take unmasked matches when there are any,
    and fall back to masked only to attribute a body we cannot place exactly.
    """
    va = int(row["recomp"], 16)
    head = raw_slice(image, va, KEY)
    if len(head) < KEY:
        return [], []
    exact, loose = [], []
    for rec in by_key.get(head, []) + early:
        body = rec["body"]
        linked = raw_slice(image, va, len(body))
        if len(linked) != len(body):
            continue
        if body == linked:
            exact.append(rec)
        elif mask(body, rec["relocs"]) == mask(linked, rec["relocs"]):
            loose.append(rec)
    return exact, loose


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=Path)
    ap.add_argument("--md", type=Path)
    ap.add_argument("--all", action="store_true",
                    help="screen every row, not just the open ones")
    args = ap.parse_args()

    all_rows = json.loads(REPORT.read_text())["data"]
    # Retail extents come from the gap to the next annotated symbol, over the
    # WHOLE report -- restricting to open rows would overstate every extent.
    ordered = sorted(all_rows, key=lambda r: int(r["address"], 16))
    extents = {}
    for i, r in enumerate(ordered):
        here = int(r["address"], 16)
        nxt = int(ordered[i + 1]["address"], 16) if i + 1 < len(ordered) \
            else here + MAX_BODY
        extents[r["address"]] = min(max(nxt - here, 0), MAX_BODY)

    rows = ordered if args.all else [r for r in ordered
                                     if r.get("matching", 0) < 1.0]

    paths = objects()
    print(f"# indexing {len(paths)} objects", file=sys.stderr)
    by_symbol, by_key, early = build_index(paths)
    print(f"# {len(by_symbol)} distinct COMDAT function symbols; "
          f"{sum(1 for v in by_symbol.values() if len(v) > 1)} contested",
          file=sys.stderr)

    ours = SL.load_image(SL.OURS_IMAGE)
    retail = SL.load_image(SL.RETAIL_IMAGE)

    out = []
    for row in rows:
        exact, loose = identify(ours, row, by_key, early)
        # Object bodies carry UNRESOLVED relocations while the image carries
        # resolved addresses, so byte equality only ever holds for bodies with
        # no relocations at all (2 of 80 rows).  Masked equality is therefore
        # the working comparison, and it cannot by itself tell two
        # relocation-distinct twins apart.  reccmp's annotation can: prefer the
        # candidate whose mangled name agrees with the row's demangled name.
        matches = rank_by_name(exact or loose, row["name"])
        entry = {"address": row["address"], "name": row["name"],
                 "matching": row["matching"]}
        if not matches:
            entry["verdict"] = "UNMATCHED"
            out.append(entry)
            continue
        # A fold set is only real when several DISTINCT symbols reproduce the
        # linked bytes exactly (/OPT:ICF).  Masked-only agreement means we
        # could not place the body exactly, which is a different situation.
        fold = sorted({m["name"] for m in exact})
        rec = matches[0]
        entry["folded_symbols"] = fold if len(fold) > 1 else []
        entry["attribution"] = "exact" if exact else "masked-only"
        # Objects that could supply these bytes: every definer of every
        # symbol in the fold set, not just of the one we happened to match.
        names = fold or [rec["name"]]
        definers = [d for name in names for d in by_symbol[name]]
        # Retail's TRUE body length.  The extent must come from the next
        # annotated retail symbol -- a window sized from the definers runs
        # straight into the following function, and body_of only strips
        # trailing fill, so it would report every definer as ~32 B short.
        gold = trim_fill(raw_slice(retail, int(row["address"], 16),
                                   extents[row["address"]]))
        supplies = {(m["obj"], m["name"]) for m in matches}
        entry["mangled"] = rec["name"]
        entry["length"] = len(rec["body"])
        entry["retail_length"] = len(gold) if gold else None
        entry["winner"] = rec["obj"].name
        entry["definers"] = []
        for other in definers:
            price = None
            delta = None
            if gold:
                delta = len(other["body"]) - len(gold)
                if delta == 0:
                    a = mask(other["body"], other["relocs"])
                    b = mask(gold, other["relocs"])
                    price = sum(x != y for x, y in zip(a, b))
            entry["definers"].append({
                "object": other["obj"].name,
                "symbol": other["name"],
                "length": len(other["body"]),
                "length_delta_vs_retail": delta,
                "masked_distance_to_retail": price,
                # Any copy that reproduces the linked bytes is a supplier.
                # With folding there can be more than one.
                "is_winner": (other["obj"], other["name"]) in supplies,
            })
        entry["verdict"] = "SOLE" if len(definers) == 1 else "CONTESTED"
        out.append(entry)

    tally: dict[str, int] = {}
    for entry in out:
        tally[entry["verdict"]] = tally.get(entry["verdict"], 0) + 1
    for verdict, count in sorted(tally.items()):
        print(f"{verdict:12s} {count}")

    if args.json:
        args.json.write_text(json.dumps(
            {"rows": out, "summary": tally}, indent=1, default=str) + "\n")
    if args.md:
        args.md.write_text(render(out, tally))
    return 0


def by_winner(out) -> list[str]:
    """Open rows grouped by the object a sweep would actually have to move.

    This is the row->TU map, derived from the link winner rather than from
    which TU looks like it owns the symbol.  For a template body those two
    answers differ, and only the first one can change the image.
    """
    groups: dict[str, list] = {}
    for e in out:
        if e["matching"] < 1.0 and e.get("winner"):
            groups.setdefault(e["winner"], []).append(e)
    if not groups:
        return []
    total = sum(len(v) for v in groups.values())
    lines = [
        "",
        "## Open rows by the object that must move",
        "",
        f"{total} open rows across {len(groups)} objects. To move a row you "
        "must change the codegen of the object named here -- for a template "
        "body that is often not the TU that looks like it owns the symbol.",
        "",
        "| object | open rows | rows |",
        "| --- | ---: | --- |",
    ]
    for obj in sorted(groups, key=lambda o: (-len(groups[o]), o)):
        rows = sorted(groups[obj], key=lambda r: r["matching"])
        listing = " ".join(f"`{r['address']}`" for r in rows)
        lines.append(f"| {obj} | {len(rows)} | {listing} |")
    return lines


def is_exact(definer) -> bool:
    return (definer["length_delta_vs_retail"] == 0
            and definer["masked_distance_to_retail"] == 0)


def fragility(out) -> list[str]:
    """Rows at 1.0 that only one object in the build can hold.

    These are the rows a link-order change can take away: they are contested,
    and exactly one definer reproduces retail.  If reordering makes a different
    object win that COMDAT, the row goes.  Rows with several exact definers are
    safe whichever copy survives.
    """
    ones = [e for e in out
            if e.get("verdict") == "CONTESTED" and e["matching"] >= 1.0]
    if not ones:
        return []
    fragile = [e for e in ones
               if sum(1 for d in e["definers"] if is_exact(d)) == 1]
    lines = [
        "",
        "## Link-order fragility of the rows we already hold",
        "",
        f"{len(ones)} rows at 1.0 are contested. Of those, **{len(fragile)} have "
        "exactly one definer that reproduces retail**, so they are held by the",
        "linker's current choice and a reordering that changes the winner takes",
        "them away. The rest have several exact copies and survive either way.",
        "",
        "This bounds the row risk of a layout change from above -- only rows",
        "whose definer set spans the objects being reordered are actually",
        "exposed -- but it is the list to check a reordering against.",
        "",
        "| row | name | definers | held by |",
        "| --- | --- | ---: | --- |",
    ]
    for e in sorted(fragile, key=lambda x: x["address"]):
        holder = next(d["object"] for d in e["definers"] if is_exact(d))
        lines.append(f"| `{e['address']}` | {e['name'][:64]} | "
                     f"{len(e['definers'])} | {holder} |")
    return lines


def render(out, tally) -> str:
    lines = [
        "# COMDAT-winner screen",
        "",
        "Generated by `tools/comdatwin.py`. For each row, the object whose",
        "COMDAT copy the linker actually kept.",
        "",
        "A sweep only reaches the image through the **winning** object. Driving",
        "a discarded copy to a byte-exact match buys nothing -- see",
        "`0x1001d890` below, which reached masked distance 0 from",
        "`worlds/infocenter.cpp` at the correct length and did not move the row,",
        "because `entity/legoworld.cpp` wins that COMDAT.",
        "",
        "| verdict | rows |",
        "| --- | --- |",
    ]
    for verdict, count in sorted(tally.items()):
        lines.append(f"| {verdict} | {count} |")
    lines += by_winner(out)
    lines += fragility(out)

    contested = [e for e in out if e.get("verdict") == "CONTESTED"
                 and e["matching"] < 1.0]
    lines += ["", f"## Contested open rows ({len(contested)})", ""]
    if not contested:
        lines.append("None: every open row has a single definer.")
    for entry in contested:
        lines += [
            f"### `{entry['address']}` {entry['name']}",
            "",
            f"score {entry['matching']:.4f}, linked {entry['length']} B, "
            f"retail {entry['retail_length']} B",
            "",
            "A definer whose length delta is non-zero cannot be exact "
            "whatever its colouring; one at delta 0 is priced.",
            "",
            "| object | length | delta | masked distance to retail | winner |",
            "| --- | ---: | ---: | ---: | :---: |",
        ]
        for d in entry["definers"]:
            price = "-" if d["masked_distance_to_retail"] is None \
                else str(d["masked_distance_to_retail"])
            delta = "-" if d["length_delta_vs_retail"] is None \
                else f"{d['length_delta_vs_retail']:+d}"
            lines.append(f"| {d['object']} | {d['length']} | {delta} | {price} "
                         f"| {'yes' if d['is_winner'] else ''} |")
        lines.append("")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
