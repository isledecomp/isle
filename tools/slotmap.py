#!/usr/bin/env python3
"""Slot-reachability screen for allocator rows -- no build required.

For a row whose residue is register/stack colour, the question that decides
whether it is fundable is:

    is the divergent frame slot a NAMED LOCAL on both sides, or is it the
    placement of a COMPILER TEMPORARY?

A named local can be named by a source idiom, so the method that closed
``~MxStreamController`` (read the allocation, name the idiom, check it against
BETA10) applies.  A temporary has no source identity, so no declaration-level
lever -- declaration order, block scope, an unused padding local -- can reach
it.  Wave 7 established that distinction on two rows by hand; this screens the
whole open set.

METHOD
  Both bodies are read from the LINKED images: ours at the reccmp report's
  ``recomp`` address, retail at its ``address``.  Reading our side from the
  object is wrong for any COMDAT row, because the object's copy need not be the
  one the linker kept.
  The two bodies are aligned at SHAPE level (frame displacements erased, so the
  alignment survives a permutation of the frame), and the ebp/esp displacement
  is then read off BOTH sides of every aligned pair.  That yields the
  allocator's permutation directly.

VERDICTS (computable; nothing is inferred that the bytes do not show)
  SLOT-CLEAN    every mapped slot maps to itself.  The residue is not a slot
                assignment difference at all -- it is register colour or
                scheduling -- so this screen has nothing to say about it.
  UNREACHABLE   a divergent slot is unaligned on either side, or two slots
                overlap on either side.  Both are packer artifacts by
                construction: an unaligned 4-byte slot means the packer placed
                something 2-mod-4 before it, and an overlap means it coalesced
                two disjoint live ranges.  Neither has a source name.
  REACHABLE     divergent slots are all 4-aligned, non-overlapping, and each is
                touched often enough to look like a variable rather than a
                spill.  These need a human read to name the local; this screen
                only says the question is worth asking.
  AMBIGUOUS     a slot maps two ways, or too few instructions aligned to trust
                the mapping.  Reported, never forced to a verdict.

usage:
  slotmap.py --all [--json OUT]     screen every open row
  slotmap.py <retail-va>            one row, with the full permutation
"""
import argparse
import collections
import difflib
import json
import sys
from pathlib import Path

import capstone
from capstone import x86
import pefile

TOOLS = Path(__file__).resolve().parent
REPORT = Path("/Users/foxtacles/Projects/isle-build-arch/LEGO1-report.json")
RETAIL_IMAGE = Path("/Users/foxtacles/Projects/isle/legobin/LEGO1.DLL")
OURS_IMAGE = Path("/Users/foxtacles/Projects/isle-build-arch/build/LEGO1.DLL")

MIN_ALIGNED_FRACTION = 0.80   # below this the permutation is not trustworthy
MIN_ACCESSES_FOR_LOCAL = 3    # fewer reads/writes than this reads as a spill
MIN_VOTE_RATIO = 2.0          # winner must double the runner-up to resolve

MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
MD.detail = True


def load_image(path):
    pe = pefile.PE(str(path), fast_load=True)
    return pe.OPTIONAL_HEADER.ImageBase, pe.get_memory_mapped_image()


def shape_stream(blob):
    """(normalised text, frame displacement) per instruction.

    SHAPE erases registers and frame displacements so two different frame
    layouts still align; the displacement is kept alongside for the mapping.
    """
    text, disp = [], []
    # In a frameless function the frame is esp-relative, so the SAME variable
    # appears at different displacements depending on how much has been pushed
    # at that point.  Track esp's signed delta from entry and canonicalise
    # every esp displacement to an entry-relative offset, or the mapping
    # aliases and the row reads as ambiguous.
    esp_delta = 0
    for ins in MD.disasm(blob, 0):
        ops = ins.op_str
        d = None
        delta_after = esp_delta
        if esp_delta is not None:
            if ins.mnemonic == "push":
                delta_after = esp_delta - 4
            elif ins.mnemonic == "pop":
                delta_after = esp_delta + 4
            elif ins.mnemonic in ("sub", "add") and ops.startswith("esp,"):
                try:
                    imm = int(ops.split(",")[1].strip(), 0)
                    delta_after = esp_delta + (-imm if ins.mnemonic == "sub"
                                               else imm)
                except ValueError:
                    delta_after = None
        for op in ins.operands:
            if op.type != x86.X86_OP_MEM or op.mem.index != 0:
                continue
            base = ins.reg_name(op.mem.base) if op.mem.base else None
            # ebp-relative locals are NEGATIVE (positive is a parameter);
            # in a frameless function the frame is esp-relative and POSITIVE.
            # Missing the esp case silently classes every frameless row as
            # having no slots at all.
            if base == "ebp" and op.mem.disp < 0:
                d = (base, op.mem.disp, op.size)
            elif base == "esp" and op.mem.disp >= 0:
                d = (None if esp_delta is None
                     else (base, op.mem.disp + esp_delta, op.size))
        # erase frame displacements and register names
        norm = ins.mnemonic
        body = ops
        for reg in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                    "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
                    "ax", "bx", "cx", "dx", "si", "di"):
            body = body.replace(reg, "r")
        out, depth = [], 0
        skip = False
        cleaned = []
        for ch in body:
            if ch == "[":
                depth += 1
                cleaned.append("[")
                skip = True
                continue
            if ch == "]":
                depth -= 1
                cleaned.append("F]")
                skip = False
                continue
            if not skip:
                cleaned.append(ch)
        text.append(f"{norm} {''.join(cleaned)}")
        disp.append(d)
        esp_delta = delta_after
    return text, disp


def body_of(base, data, va, length):
    """Body bytes with inter-function padding trimmed.

    The report's extent runs to the next annotated symbol, which includes the
    aligner's 0xCC (and occasionally 0x90) fill.  Disassembling that fill
    invents instructions and, through them, invents slot pairs.
    """
    blob = bytearray(data[va - base:va - base + length])
    while blob and blob[-1] in (0xCC, 0x90):
        blob.pop()
    return bytes(blob)


def screen(row, retail_img, ours_img, verbose=False):
    rb, rd = retail_img
    ob, od = ours_img
    ra = int(row["address"], 16)
    oa = int(row["recomp"], 16)
    ta, tdisp = shape_stream(body_of(ob, od, oa, row["_olen"]))
    tb, rdisp = shape_stream(body_of(rb, rd, ra, row["_len"]))
    sm = difflib.SequenceMatcher(a=ta, b=tb, autojunk=False)
    matched = sum(bl.size for bl in sm.get_matching_blocks())
    denom = max(len(ta), len(tb), 1)
    frac = matched / denom
    pairs = collections.defaultdict(collections.Counter)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag != "equal":
            continue
        for k in range(i2 - i1):
            x, y = tdisp[i1 + k], rdisp[j1 + k]
            if x and y:
                pairs[x][y] += 1

    if frac < MIN_ALIGNED_FRACTION:
        return {"verdict": "AMBIGUOUS",
                "reason": f"only {frac:.0%} of instructions aligned",
                "aligned": round(frac, 4), "slots": len(pairs),
                "divergent": []}
    if not pairs:
        # Nothing in this row touches a frame slot in an aligned position --
        # register-only code, typically a template walk.  The screen has no
        # question to answer here; it is not ambiguous, it is empty.
        return {"verdict": "NO-SLOTS",
                "reason": "no frame-slot operand in any aligned instruction",
                "aligned": round(frac, 4), "slots": 0, "divergent": []}

    # SHAPE normalisation makes many instructions textually identical
    # ("mov r,[F]"), so difflib can pair the wrong two and invent a slot
    # correspondence.  Resolve each ours-slot by supported majority: accept the
    # winner only when it has at least MIN_VOTE_RATIO times the runner-up's
    # support and more than one vote.  Anything closer is left UNRESOLVED and
    # forces AMBIGUOUS -- a contested slot is exactly where a confident answer
    # would be the wrong one.
    mapping, counts, unresolved = {}, {}, []
    for x, ys in pairs.items():
        ranked = ys.most_common()
        top, top_n = ranked[0]
        runner_n = ranked[1][1] if len(ranked) > 1 else 0
        if runner_n and not (top_n >= 2 and top_n >= MIN_VOTE_RATIO * runner_n):
            unresolved.append(x)
            continue
        mapping[x] = top
        counts[x] = sum(ys.values())

    # A pairing seen once is not evidence against one seen three times, so
    # when several ours-slots claim the same retail slot and exactly one of
    # them is well supported, the singletons are alignment noise.  Dropped
    # explicitly and counted, never silently.
    rev = collections.defaultdict(list)
    for x, y in mapping.items():
        rev[y].append(x)
    dropped = 0
    for y, xs in list(rev.items()):
        if len(xs) < 2:
            continue
        strong = [x for x in xs if counts[x] >= MIN_ACCESSES_FOR_LOCAL]
        weak = [x for x in xs if counts[x] == 1]
        if len(strong) == 1 and weak:
            for x in weak:
                mapping.pop(x, None)
                counts.pop(x, None)
                dropped += 1
    rev = collections.defaultdict(list)
    for x, y in mapping.items():
        rev[y].append(x)
    collide = [y for y, xs in rev.items() if len(xs) > 1]
    if unresolved or collide:
        why = []
        if unresolved:
            why.append(f"{len(unresolved)} slot(s) contested")
        if collide:
            why.append(f"{len(collide)} retail slot(s) claimed twice")
        if dropped:
            why.append(f"{dropped} noise pair(s) dropped")
        return {"verdict": "AMBIGUOUS", "reason": "; ".join(why),
                "aligned": round(frac, 4), "slots": len(pairs),
                "divergent": [fmt((x, mapping[x], counts[x])) for x in mapping
                              if x[1] != mapping[x][1]]}

    divergent = [(x, mapping[x], counts[x]) for x in mapping
                 if x[1] != mapping[x][1]]
    if not divergent:
        return {"verdict": "SLOT-CLEAN", "reason": "identity mapping",
                "aligned": round(frac, 4), "divergent": []}

    reasons = []
    for (ob_, od_, os_), (rb_, rd_, rs_), _n in divergent:
        if os_ == 4 and od_ % 4:
            reasons.append(f"ours {ob_}{od_:+#x} is 4B, not 4-aligned")
        if rs_ == 4 and rd_ % 4:
            reasons.append(f"retail {rb_}{rd_:+#x} is 4B, not 4-aligned")

    def overlaps(slots, side):
        out = []
        by_base = collections.defaultdict(list)
        for base, disp, size in slots:
            by_base[base].append((disp, size))
        for base, items in by_base.items():
            items.sort()
            # Only a PARTIAL overlap is a coalescing artefact.  A byte or
            # word access sitting inside a wider slot is an ordinary
            # sub-object read and must not be flagged.
            for i in range(len(items)):
                d1, s1 = items[i]
                for d2, s2 in items[i + 1:]:
                    if d2 >= d1 + s1:
                        break
                    contained = ((d2 >= d1 and d2 + s2 <= d1 + s1)
                                 or (d1 >= d2 and d1 + s1 <= d2 + s2))
                    if not contained:
                        out.append(f"{side} {base}{d1:+#x}(+{s1}) partially "
                                   f"overlaps {base}{d2:+#x}(+{s2})")
        return out

    reasons += overlaps(set(mapping.keys()), "ours")
    reasons += overlaps(set(mapping.values()), "retail")
    if reasons:
        return {"verdict": "UNREACHABLE",
                "reason": "; ".join(sorted(set(reasons))[:3]),
                "aligned": round(frac, 4), "slots": len(pairs),
                "divergent": [fmt(d) for d in divergent]}

    thick = [d for d in divergent if d[2] >= MIN_ACCESSES_FOR_LOCAL]
    if not thick:
        return {"verdict": "UNREACHABLE",
                "reason": f"all {len(divergent)} divergent slot(s) touched "
                          f"< {MIN_ACCESSES_FOR_LOCAL}x -- spill-shaped",
                "aligned": round(frac, 4), "slots": len(pairs),
                "divergent": [fmt(d) for d in divergent]}
    return {"verdict": "REACHABLE",
            "reason": f"{len(thick)} of {len(divergent)} divergent slot(s) "
                      f"aligned, non-overlapping, >={MIN_ACCESSES_FOR_LOCAL} "
                      f"accesses",
            "aligned": round(frac, 4),
            "divergent": [fmt(d) for d in divergent]}


def fmt(d):
    (ob, odsp, osz), (rb, rdsp, rsz), n = d
    return {"ours": f"{ob}{odsp:+#07x}", "retail": f"{rb}{rdsp:+#07x}",
            "width": osz, "accesses": n, "delta": rdsp - odsp}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("va", nargs="?")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--json")
    args = ap.parse_args()

    data = json.loads(REPORT.read_text())["data"]
    starts = sorted(int(r["address"], 16) for r in data)
    ostarts = sorted(int(r["recomp"], 16) for r in data if r.get("recomp"))
    by_addr = {}
    for r in data:
        a = int(r["address"], 16)
        i = starts.index(a)
        r["_len"] = (starts[i + 1] - a) if i + 1 < len(starts) else 0x200
        if r.get("recomp"):
            o = int(r["recomp"], 16)
            j = ostarts.index(o)
            r["_olen"] = (ostarts[j + 1] - o) if j + 1 < len(ostarts) else 0x200
        by_addr[a] = r

    retail_img = load_image(RETAIL_IMAGE)
    ours_img = load_image(OURS_IMAGE)

    if args.va:
        rows = [by_addr[int(args.va, 16)]]
    else:
        rows = [r for r in data if r["matching"] < 1.0 and r.get("recomp")]

    out = []
    for r in sorted(rows, key=lambda r: -r["matching"]):
        try:
            res = screen(r, retail_img, ours_img)
        except Exception as exc:                      # noqa: BLE001
            res = {"verdict": "AMBIGUOUS", "reason": f"error: {exc}",
                   "aligned": 0.0, "divergent": []}
        res.update(address=r["address"], name=r["name"],
                   score=round(r["matching"], 4))
        out.append(res)

    order = {"REACHABLE": 0, "AMBIGUOUS": 1, "UNREACHABLE": 2,
             "SLOT-CLEAN": 3, "NO-SLOTS": 4}
    out.sort(key=lambda x: (order[x["verdict"]], -x["score"]))
    tally = collections.Counter(x["verdict"] for x in out)
    for x in out:
        print(f"{x['address']} {x['score']:.4f} {x['verdict']:12s} "
              f"{x['name'][:46]:48s} {x['reason'][:60]}")
        if x["verdict"] == "REACHABLE":
            for d in x["divergent"]:
                print(f"      {d['ours']} -> {d['retail']}  w{d['width']} "
                      f"x{d['accesses']}  delta {d['delta']:+d}")
    print(f"\n# {len(out)} rows: " +
          ", ".join(f"{k} {v}" for k, v in tally.most_common()))
    if args.json:
        Path(args.json).write_text(json.dumps(out, indent=1) + "\n")


if __name__ == "__main__":
    main()
