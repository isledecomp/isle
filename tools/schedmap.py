#!/usr/bin/env python3
"""Scheduling screen -- the third residue screen, after slots and registers.

``slotmap.py`` sorts rows by frame layout and ``regmap.py`` by register
assignment.  What is left on a row where both already match retail is
SCHEDULING: the same instructions, emitted in a different order.  This sorts
that residue.

THE DISTINCTION THAT MATTERS
  INTRA-BLOCK   every moved instruction stays inside its own basic block.
                That is the instruction scheduler reordering independent
                operations, and the standing verdict is that it is not a text
                target.
  CROSS-BLOCK   a moved instruction changes basic block, i.e. it is emitted
                amid a different part of the program than on the other side.
                That is the class a source STATEMENT ORDER can reach.
  DIFFERENT     an instruction on one side has no counterpart on the other --
                not a scheduling difference at all; route to another screen.
  CMPDIR        every unmatched pair is a comparison with transposed
                operands -- the sealed allocator class, not scheduling.
  CLEAN         no difference once relocated operands are masked.
  AMBIGUOUS     too little of the body aligns to judge.

Both bodies are read from the LINKED images and aligned at EXACT level:
registers and frame displacements are KEPT (they already match on this
population, so keeping them makes the alignment precise), and only operands
that are relocations -- direct branch targets and image-range immediates or
displacements -- are masked, since our image's layout differs from retail's.

usage:
  schedmap.py --all [--json OUT]
  schedmap.py <retail-va> [-v]
"""
import argparse
import collections
import difflib
import json
import re
import sys
from pathlib import Path

import capstone
from capstone import x86

sys.path.insert(0, str(Path(__file__).resolve().parent))
from slotmap import (REPORT, RETAIL_IMAGE, OURS_IMAGE, load_image, body_of)

MIN_ALIGNED_FRACTION = 0.80
MOVE_WINDOW = 60            # how far a moved instruction may travel and still
                            # be recognised as the same instruction

MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
MD.detail = True
IMAGE_LO, IMAGE_HI = 0x10000000, 0x11000000
NUM = re.compile(r"(?<!\*)0x[0-9a-f]+")


def is_branch(ins):
    return ins.mnemonic[0] == "j" or ins.mnemonic in ("loop", "loope",
                                                      "loopne")


def stream(blob, va):
    """EXACT-level text per instruction, plus branch targets, plus block ids.

    Registers and frame displacements are kept.  A direct branch target is <t>
    and any image-range value is <a>, because our image is laid out at
    different addresses than retail's and those operands are relocations.
    """
    ins_list = list(MD.disasm(blob, va))
    targets = set()
    for ins in ins_list:
        if (is_branch(ins) or ins.mnemonic == "call") and "[" not in ins.op_str:
            try:
                t = int(ins.op_str, 0)
            except ValueError:
                continue
            if va <= t < va + len(blob):
                targets.add(t)
    text, blocks = [], []
    blk = 0
    prev_ended = False
    for ins in ins_list:
        if ins.address in targets or prev_ended:
            blk += 1
        blocks.append(blk)
        prev_ended = is_branch(ins) or ins.mnemonic in ("ret", "retn")
        ops = ins.op_str
        if (is_branch(ins) or ins.mnemonic == "call") and "[" not in ops:
            ops = "<t>"
        else:
            ops = NUM.sub(
                lambda m: "<a>" if IMAGE_LO <= int(m.group(0), 16) < IMAGE_HI
                else m.group(0), ops)
        text.append(f"{ins.mnemonic} {ops}")
    return ins_list, text, blocks


def screen(row, retail_img, ours_img):
    rb, rd = retail_img
    ob, od = ours_img
    ova, rva = int(row["recomp"], 16), int(row["address"], 16)
    oins, ot, oblk = stream(body_of(ob, od, ova, row["_olen"]), ova)
    rins, rt, rblk = stream(body_of(rb, rd, rva, row["_len"]), rva)
    sm = difflib.SequenceMatcher(a=ot, b=rt, autojunk=False)
    matched = sum(bl.size for bl in sm.get_matching_blocks())
    frac = matched / max(len(ot), len(rt), 1)
    base = {"aligned": round(frac, 4), "ours_insn": len(ot),
            "retail_insn": len(rt)}
    if frac < MIN_ALIGNED_FRACTION:
        return dict(base, verdict="AMBIGUOUS",
                    reason=f"only {frac:.0%} of instructions aligned",
                    moves=[], cross_moves=0, moves_total=0)
    deleted, inserted = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("delete", "replace"):
            deleted += [(k, ot[k]) for k in range(i1, i2)]
        if tag in ("insert", "replace"):
            inserted += [(k, rt[k]) for k in range(j1, j2)]
    if not deleted and not inserted:
        return dict(base, verdict="CLEAN", reason="identical once masked",
                    moves=[], cross_moves=0, moves_total=0)

    unmatched_r = list(inserted)
    moves, orphan_o = [], []
    for oi, txt in deleted:
        cands = [(abs(ri - oi), n) for n, (ri, t) in enumerate(unmatched_r)
                 if t == txt and abs(ri - oi) <= MOVE_WINDOW]
        if not cands:
            orphan_o.append((oi, txt))
            continue
        _, n = min(cands)
        ri, _t = unmatched_r.pop(n)
        moves.append({"text": txt, "ours_at": oi, "retail_at": ri,
                      "distance": ri - oi,
                      "ours_block": oblk[oi], "retail_block": rblk[ri],
                      "cross": oblk[oi] != rblk[ri]})
    orphan_r = unmatched_r

    cross = [m for m in moves if m["cross"]]
    base = dict(base, cross_moves=len(cross), moves_total=len(moves))
    if orphan_o or orphan_r:
        # A comparison whose operands are transposed (`cmp A,B` vs `cmp B,A`)
        # is the sealed cmpdir class -- a register-assignment difference, not a
        # scheduling one -- so it gets its own verdict rather than being lumped
        # in with genuinely different instructions.
        cmpdir = 0
        ro = [t for _i, t in orphan_r]
        for _i, t in orphan_o:
            if not t.startswith("cmp "):
                continue
            a, _, b = t[4:].partition(", ")
            mirror = f"cmp {b}, {a}"
            if mirror in ro:
                ro.remove(mirror)
                cmpdir += 1
        if cmpdir and cmpdir == len(orphan_o) and not ro:
            return dict(base, verdict="CMPDIR",
                        reason=f"{cmpdir} comparison(s) with transposed "
                               f"operands; sealed allocator class",
                        moves=moves)
        return dict(base, verdict="DIFFERENT", cmpdir=cmpdir,
                    reason=f"{len(orphan_o)} ours-only and {len(orphan_r)} "
                           f"retail-only instruction(s) with no counterpart"
                           + (f", {cmpdir} of them cmpdir" if cmpdir else "")
                           + (f"; {len(cross)} cross-block move(s)"
                              if cross else ""),
                    moves=moves,
                    orphans={"ours": [t for _i, t in orphan_o][:6],
                             "retail": [t for _i, t in orphan_r][:6]})
    if cross:
        return dict(base, verdict="CROSS-BLOCK",
                    reason=f"{len(cross)} of {len(moves)} moved instruction(s) "
                           f"change basic block",
                    moves=moves)
    return dict(base, verdict="INTRA-BLOCK",
                reason=f"{len(moves)} instruction(s) reordered inside their "
                       f"own block",
                moves=moves)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("va", nargs="?")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--json")
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()

    data = json.loads(Path(REPORT).read_text())["data"]
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

    retail_img, ours_img = load_image(RETAIL_IMAGE), load_image(OURS_IMAGE)
    rows = ([by_addr[int(args.va, 16)]] if args.va
            else [r for r in data if r["matching"] < 1.0 and r.get("recomp")])

    out = []
    for r in rows:
        try:
            res = screen(r, retail_img, ours_img)
        except Exception as exc:                       # noqa: BLE001
            res = {"verdict": "AMBIGUOUS", "reason": f"error: {exc}",
                   "aligned": 0.0, "moves": []}
        res.update(address=r["address"], name=r["name"],
                   score=round(r["matching"], 4))
        out.append(res)

    order = {"CROSS-BLOCK": 0, "INTRA-BLOCK": 1, "DIFFERENT": 2,
             "CMPDIR": 3, "CLEAN": 4, "AMBIGUOUS": 5}
    out.sort(key=lambda x: (order[x["verdict"]], -x["score"]))
    for x in out:
        print(f"{x['address']} {x['score']:.4f} {x['verdict']:12s} "
              f"{x['name'][:44]:46s} {x['reason'][:54]}")
        if args.v or x["verdict"] == "CROSS-BLOCK" or x.get("cross_moves"):
            for m in x["moves"][:8]:
                print(f"      {'CROSS' if m['cross'] else 'intra'} "
                      f"blk {m['ours_block']}->{m['retail_block']} "
                      f"dist {m['distance']:+d}  {m['text'][:52]}")
    print("\n# " + ", ".join(f"{k} {v}" for k, v in collections.Counter(
        x["verdict"] for x in out).most_common()))
    if args.json:
        Path(args.json).write_text(json.dumps(out, indent=1) + "\n")


if __name__ == "__main__":
    main()
