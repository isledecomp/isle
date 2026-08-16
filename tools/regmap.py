#!/usr/bin/env python3
"""Register-assignment screen for colour rows -- no build required.

``slotmap.py`` showed that 55 of the open rows already carry retail's exact
frame layout, so what is left on those rows is the *register* assignment.  This
sorts that population.

THE DISTINCTION
  A physical register is not a value: the same register holds different values
  in different parts of a function.  So the meaningful question is not "does
  esi differ" but whether ONE global renaming explains the whole body.

  PERMUTATION   a single bijection pi maps our registers onto retail's across
                (nearly) every aligned instruction.  The same live ranges were
                given different physical registers -- an allocator tie, with no
                source correlate.  This is the register analogue of the
                compiler-temporary finding in wave 7.
  REGIONAL      no global pi works, but the body splits into a few maximal runs
                each of which has its own consistent bijection.  The colouring
                is re-decided at a boundary; still usually a tie, but a small
                number of large regions is worth a look.
  SCATTERED     disagreement admits neither a global nor a few-region
                explanation.  The live ranges themselves differ -- a value is
                born, dies or spills at a different point -- which is the class
                with a source correlate and the one the ~MxStreamController
                method is aimed at.
  IDENTITY      registers already agree everywhere; the residue is scheduling
                or encoding, not colour.
  AMBIGUOUS     too little of the body aligns to trust any of the above.

usage:
  regmap.py --all [--json OUT]
  regmap.py <retail-va> [-v]
"""
import argparse
import collections
import difflib
import json
import sys
from pathlib import Path

import capstone
from capstone import x86

sys.path.insert(0, str(Path(__file__).resolve().parent))
from slotmap import (REPORT, RETAIL_IMAGE, OURS_IMAGE, load_image, body_of)

MIN_ALIGNED_FRACTION = 0.80
GLOBAL_EXPLAIN = 0.98      # a global bijection must explain this share
REGIONAL_MAX_RUNS = 4      # more maximal runs than this reads as scattered

MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
MD.detail = True

CANON = {}
for wide, parts in (
        ("eax", ("eax", "ax", "al", "ah")),
        ("ebx", ("ebx", "bx", "bl", "bh")),
        ("ecx", ("ecx", "cx", "cl", "ch")),
        ("edx", ("edx", "dx", "dl", "dh")),
        ("esi", ("esi", "si")),
        ("edi", ("edi", "di")),
        ("ebp", ("ebp", "bp")),
):
    for p in parts:
        CANON[p] = wide


def stream(blob):
    """(SHAPE text, ordered canonical register operands) per instruction."""
    text, regs = [], []
    for ins in MD.disasm(blob, 0):
        rs = []
        # The prologue saves and the epilogue restores callee-saved registers
        # in a CANONICAL order (push ebx/esi/edi, pop edi/esi/ebx) whatever the
        # allocator did with them, so those operands do not follow the
        # renaming and would otherwise break an otherwise perfect bijection.
        # Measured on TextureImpl::SetImage: 4 of 35 pairs, all push/pop.
        structural = (ins.mnemonic in ("push", "pop")
                      and len(ins.operands) == 1
                      and ins.operands[0].type == x86.X86_OP_REG
                      and CANON.get(ins.reg_name(ins.operands[0].reg))
                      in ("ebx", "esi", "edi", "ebp"))
        for op in (() if structural else ins.operands):
            if op.type == x86.X86_OP_REG:
                rs.append(CANON.get(ins.reg_name(op.reg)))
            elif op.type == x86.X86_OP_MEM:
                for r in (op.mem.base, op.mem.index):
                    if r:
                        rs.append(CANON.get(ins.reg_name(r)))
        # SHAPE: erase register names and every bracketed displacement
        body, out, skip = ins.op_str, [], False
        for ch in body:
            if ch == "[":
                out.append("[")
                skip = True
                continue
            if ch == "]":
                out.append("F]")
                skip = False
                continue
            if not skip:
                out.append(ch)
        flat = "".join(out)
        for name in sorted(CANON, key=len, reverse=True):
            flat = flat.replace(name, "r")
        text.append(f"{ins.mnemonic} {flat}")
        regs.append([r for r in rs if r])
    return text, regs


def bijection_from(votes):
    """Majority mapping, plus whether it is injective."""
    m = {a: c.most_common(1)[0][0] for a, c in votes.items()}
    injective = len(set(m.values())) == len(m)
    return m, injective


def explained(pairs, m):
    ok = tot = 0
    for a, b in pairs:
        tot += 1
        if m.get(a) == b:
            ok += 1
    return (ok / tot) if tot else 1.0


def screen(row, retail_img, ours_img, verbose=False):
    rb, rd = retail_img
    ob, od = ours_img
    ta, ra = stream(body_of(ob, od, int(row["recomp"], 16), row["_olen"]))
    tb, rr = stream(body_of(rb, rd, int(row["address"], 16), row["_len"]))
    sm = difflib.SequenceMatcher(a=ta, b=tb, autojunk=False)
    matched = sum(bl.size for bl in sm.get_matching_blocks())
    frac = matched / max(len(ta), len(tb), 1)
    if frac < MIN_ALIGNED_FRACTION:
        return {"verdict": "AMBIGUOUS",
                "reason": f"only {frac:.0%} of instructions aligned",
                "aligned": round(frac, 4), "pairs": 0, "map": {}}

    seq = []            # (index-in-aligned-order, our_reg, retail_reg)
    n = 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag != "equal":
            continue
        for k in range(i2 - i1):
            x, y = ra[i1 + k], rr[j1 + k]
            if len(x) != len(y):
                continue
            for p, q in zip(x, y):
                seq.append((n, p, q))
            n += 1
    if not seq:
        return {"verdict": "AMBIGUOUS", "reason": "no register operands",
                "aligned": round(frac, 4), "pairs": 0, "map": {}}

    votes = collections.defaultdict(collections.Counter)
    for _i, p, q in seq:
        votes[p][q] += 1
    m, injective = bijection_from(votes)
    pairs = [(p, q) for _i, p, q in seq]
    share = explained(pairs, m)
    ident = all(a == b for a, b in m.items())

    if share >= GLOBAL_EXPLAIN and injective:
        if ident:
            return {"verdict": "IDENTITY",
                    "reason": f"registers agree on {share:.1%} of "
                              f"{len(pairs)} operand pairs",
                    "aligned": round(frac, 4), "pairs": len(pairs), "map": {}}
        moved = {a: b for a, b in m.items() if a != b}
        return {"verdict": "PERMUTATION",
                "reason": f"one bijection explains {share:.1%} of "
                          f"{len(pairs)} operand pairs",
                "aligned": round(frac, 4), "pairs": len(pairs), "map": moved}

    # regional: greedily cut where a running local bijection breaks
    # A single conflicting pair is alignment noise; a region boundary is a
    # conflict that PERSISTS.  Cut only when two conflicts occur within a
    # short window, and never on the same instruction index twice.
    runs, cur = [], {}
    start, pending, last_conflict = seq[0][0], 0, None
    for i, p, q in seq:
        conflict = cur.get(p, q) != q
        if conflict:
            if last_conflict is not None and i - last_conflict <= 4:
                pending += 1
            else:
                pending = 1
            last_conflict = i
            if pending >= 2:
                runs.append((start, i))
                cur, start, pending = {}, i, 0
                continue
        else:
            cur[p] = q
    runs.append((start, seq[-1][0] + 1))
    if len(runs) <= REGIONAL_MAX_RUNS:
        return {"verdict": "REGIONAL",
                "reason": f"{len(runs)} region(s), best global bijection "
                          f"explains {share:.1%}"
                          + ("" if injective else ", not injective"),
                "aligned": round(frac, 4), "pairs": len(pairs),
                "map": {a: b for a, b in m.items() if a != b},
                "regions": [{"from": a, "to": b} for a, b in runs]}
    return {"verdict": "SCATTERED",
            "reason": f"{len(runs)} region(s), best global bijection explains "
                      f"{share:.1%}" + ("" if injective else ", not injective"),
            "aligned": round(frac, 4), "pairs": len(pairs),
            "map": {a: b for a, b in m.items() if a != b},
            "regions": len(runs)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("va", nargs="?")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--json")
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

    retail_img = load_image(RETAIL_IMAGE)
    ours_img = load_image(OURS_IMAGE)
    rows = ([by_addr[int(args.va, 16)]] if args.va
            else [r for r in data if r["matching"] < 1.0 and r.get("recomp")])

    out = []
    for r in rows:
        try:
            res = screen(r, retail_img, ours_img)
        except Exception as exc:                      # noqa: BLE001
            res = {"verdict": "AMBIGUOUS", "reason": f"error: {exc}",
                   "aligned": 0.0, "pairs": 0, "map": {}}
        res.update(address=r["address"], name=r["name"],
                   score=round(r["matching"], 4))
        out.append(res)

    order = {"SCATTERED": 0, "REGIONAL": 1, "PERMUTATION": 2, "IDENTITY": 3,
             "AMBIGUOUS": 4}
    out.sort(key=lambda x: (order[x["verdict"]], -x["score"]))
    for x in out:
        mp = " ".join(f"{a}->{b}" for a, b in sorted(x["map"].items()))
        print(f"{x['address']} {x['score']:.4f} {x['verdict']:12s} "
              f"{x['name'][:44]:46s} {x['reason'][:52]}")
        if mp:
            print(f"      {mp}")
    print("\n# " + ", ".join(
        f"{k} {v}" for k, v in
        collections.Counter(x["verdict"] for x in out).most_common()))
    if args.json:
        Path(args.json).write_text(json.dumps(out, indent=1) + "\n")


if __name__ == "__main__":
    main()
