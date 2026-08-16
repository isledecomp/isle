# Wave 14 — `0x1003cf20 ~LegoCacheSoundManager`: solved, priced, not landed

The row **can be closed**, and this wave closed it: `258/258, masked nd 0`,
with the callee's own exact row preserved. It is **not landed**, because a
full gated A/B prices it at **+1 GAIN, −48 LOST**.

Everything below is measured on `isle-build-bt04`. Baseline for this
worktree is **4853/4934, gate green**.

## 1. The body axis is inert — with a positive control

The per-site hypothesis was that the caller's accumulated state decides the
inline bit. It does not.

| generator | cells | positions | result |
|---|---:|---:|---|
| `empty_scopes` 1..256 | 252 | 9 | one body length (274) in every cell |
| `noop_assign` 1..64 | 189 | 9 | one body length (274) in every cell |

441 cells, one **byte-identical** destructor. The insertions were verified
present in the rendered source at the exact site, so this is inertness, not
a broken harness.

**General finding: `inline_budget_noop_statements_v1` cannot perturb an
inline budget in MSVC 4.2.** Its form is `<id> = <id> + 0;`, a
self-assignment folded away before any size accounting — even at
`p07_after_site`, where the target is live across the insertion.
`empty_compound_statements_v1` emits no IL at all. Neither is a cost ladder.
This reproduces Lane ARCH's result independently.

## 2. The callee-cost axis is refuted — also with a positive control

Ten callee body forms, compiled through a privately staged header (probe
only; never a landing path).

* Three forms **demonstrably added live cost** — the caller's *inlined
  expansion* grew 274 → 282 / 287 / 286 bytes.
* Three forms produced a **byte-identical callee body** from different IL.
* **The site declined in zero of the ten.** Added cost makes the inlined
  expansion bigger; it does not make the compiler stop inlining.

There is also an arithmetic reason never to use this axis here: **the callee
is itself a scored exact row** (`0x1003d030`, matching 1.0), so live cost
injection trades the row we want for one we have. Every form that added live
cost moved the callee's body hash.

## 3. The per-site vector — measured, not inferred

Read from the linked image, per the instrument note.

| | |
|---|---|
| annotated functions compared | **4934** |
| agree, neither calls the callee | **4933** |
| agree, both call | 0 |
| **disagree** | **1** — `~LegoCacheSoundManager` |
| retail sites calling the callee | **1**, the same function |

This is **stronger than the "uniformly call" case** hoped for: there is no
site anywhere where retail expands and we call. The disjointness that killed
`0x1009f490` cannot arise — there is no second window to thread.

**This refutes the stated mechanism for the −47.** De-inlining was said to
cost rows by forcing *every* site to call, including sites in the 16
includers that retail expands. Measured: only **one object in the entire
build** references the symbol, and no other site in the image calls it.
De-inlining disturbs no other site's inlining. The −47 is real, but its
cause is different — see §5.

### Two attribution traps, both of which produced confident wrong answers

1. **Naive `0xE8` scanning invents call sites.** Byte-scanning `.text` for
   `E8` matches operand bytes inside other instructions; it reported calls to
   negative addresses and three phantom sites. Disassemble.
2. **Object relocation counts are not per-body site counts.** A non-COMDAT
   `.text` holds many functions, so charging its relocations to the section's
   first symbol is wrong — and even attributed correctly by offset, the counts
   include **EH unwind funclets** in the function tail. That is why the object
   showed `ManageSoundEntry` calling the callee three times while the image,
   where it scores 1.0, shows zero. **Ask the question in the linked image.**

## 4. The fix, and that it genuinely works

Declare `~LegoCacheSoundEntry` in the class, define it in the .cpp — the
source's own `TODO`. Placement is not arbitrary: **retail's address order is
`0x1003cf20` → `0x1003d030` → `0x1003d050`**, so the original source defined
it between the destructor and `Tickle`.

Seed lane, masked (relocation operands zeroed both sides):

| function | before | after |
|---|---|---|
| `~LegoCacheSoundManager` | 274 B, masked nd 99 | **258/258, masked nd 0** |
| `~LegoCacheSoundEntry` | 22 B | **22 B byte-identical** (row 1.0 kept) |
| `Stop` | 187 B, nd 127 | 181/181 |
| `FindSoundByKey` | 282 B | unchanged |

All four placements tried reach masked nd 0, so placement was chosen for
authenticity, not score. The gated build confirms the row:
**`GAIN 0x1003cf20 LegoCacheSoundManager::~LegoCacheSoundManager`.**

## 5. The price — and what actually causes it

13 pinned donor bodies across 5 compose units stopped reproducing. **All 13
were re-dialled successfully** (`redial_sweep.py` / `redial_apply.py`, pins
never move). Two initially read as MISS purely because their original cells,
`extern (12,59)` and `(18,12)`, sat outside the swept grid — widening `k` to
99 found both. One further cell reproduced its pin but the **composer refused
the splice**; six `pad_shape` cells were accepted instead — the first
productive use of `pad_shape` as a donor kind anywhere in the manifest.

With every re-dial applied, the honest A/B against a green 4853 baseline is:

> **GAIN 1** — `LegoCacheSoundManager::~LegoCacheSoundManager`
> **LOST 48** — spread over `legoact2`, `act3actors`, `legoextraactor`,
> `legopathactor`, `legoworld`, `legobuildingmanager`, `legojetski`,
> `legoracecar`, `legoraceactor`, `legoloadcachesoundpresenter`, plus seven
> `_Tree<LegoCacheSoundEntry,…>` instantiations in the TU itself.
> **Net −47**, reproducing the historical figure exactly.

The 48 are **unpinned, previously-exact rows that changed colour**. The cost
is the header's *text* radius over its 16 includers, not anything to do with
inlining.

**Tested and refuted: it is the token stream, not line numbering.** Padding
the header so every physical line number in all 16 includers is byte-for-byte
unchanged (declaration + reserved blank lines, 128 lines before and after)
produced **exactly the same 4806 and exactly the same 48-row loss set**. So
`line_reservation_v1` cannot rescue this, and neither can any edit that keeps
the body out of the header — removing those tokens is the whole cost.

## 6. Verdict

**Do not land.** Same judgement as wave 10: a +1 that costs 48 is a loss.
The tree is reverted and re-verified green at **4853/4934**.

The row is no longer a mystery, which is the actual deliverable:

* it is **closable**, exactly and reproducibly, by one authentic source edit;
* its per-site vector is **ideal** — one disagreeing site, no disjointness;
* the blocker is **not** inlining, cost, the caller, or the callee. It is
  that `legocachesoundmanager.h` has 16 includers and any change to its token
  stream re-colours them.

What would make it landable is a way to price or repair that re-colouring —
48 rows across ~12 TUs, most of which already have compose units, and 7 of
which are template instantiations in the touched TU itself that a single
carrier cell might restore together. That is a bounded, mechanical piece of
work, and it is the only thing standing between this row and +1.
