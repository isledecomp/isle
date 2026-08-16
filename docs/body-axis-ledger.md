# Lane FRESH — the body-insertion axis, measured (wave 3)

The first axis in the project that perturbs tokens INSIDE a function body:
`source_overlay` insertions of the two typed generators

    empty_scopes  (empty_compound_statements_v1)   "\t{\n\t}\n" x N
    noop_assign   (inline_budget_noop_statements_v1) "\tx = x + 0;\n" x N

swept by KIND x COUNT x POSITION over six open colour/schedule rows, with a
**live positive control in every cell block** (a volatile store through the
same identifier — the compiler cannot eliminate it, so it must move the body;
this separates "the axis has no purchase" from "these generators emit too
little"). Harness: `<scratchpad>/fresh3/bodysweep.py`, isle-build-nova,
current tip. Counts: empty {1,2,4,8,13,32}, noop {1,2,4,8,16,32}, positions =
every statement boundary in the body (≤24, bracketing each row's divergent
region on both sides).

## The result: 0 of 6 rows moved, in any cell — and every null is control-validated

| row | class | generator cells | controls moved | cells that changed the target body |
|---|---|---:|---:|---:|
| `0x100b26f0` AlphaMask::IsHit | colour, nd=8 | 72 | 6/6 | **0** |
| `0x100c6fa0` MxDSBuffer::FUN_100c6fa0 | PERMUTED, nd=4 | 288 | 24/24 | **0** |
| `0x100ba2c0` MxStillPresenter::Clone | +1 encoding | 414 | 23/23 | **0** |
| `0x10080be0` CalculateSpline | +1 encoding | 282 | 21/23 | **0** |
| `0x100ba7f0` MxDisplaySurface::Create | schedule, nd=9 | 282 | 21/23 | **0** |
| `0x1009a8c0` LinkEdgesAndFaces | colour, nd=4 | 282 | 23/23 | **0** |

**1,620 generator cells, 0 compile failures, 0 target-body changes of any
kind** — not "same nd", literally the same body sha in every cell — while
the live controls moved the body in 118 of 124 positions (the six that did
not are late positions where the control's identifier is dead, i.e. the
control behaved exactly as liveness predicts).

**Verdict: the body axis, as these two generators, has ZERO purchase on
register allocation, scheduling, and cmp direction.** The six rows include
both pure-colour, PERMUTED-schedule, and encoding-length classes, with
insertions placed before, between, and after each divergent region. This is a
decisive negative for the axis as a colour lever.

## But the axis is NOT dead — it is an INLINE-BUDGET lever, proven end to end

The contrary datum (13 `empty_scopes` LANDED inside
`LegoPathController::FindPath`, op#11) was differentially tested
(`fpprobe.py`, probe compiles only):

    with the 13 scopes    FindPath = 2337 bytes
    without them          FindPath = 2329 bytes

and the relocation census names the mechanism exactly: **with scopes, the
`_Tree<LegoBEWithMidpoint*>` constructor is INLINED into FindPath** (its
inner `_Init` call surfaces in the reloc list); without them it is a plain
ctor call. The scopes are caller-IL units — they raise `2*C` in the planner's
`R = 2*C − consumedBefore` and flip an inline ACCEPT at a site within a few
units of threshold. Nothing else in the function changes.

This explains every observation in one stroke:

* FindPath moved (a threshold site inside the reach of +13 units, in the
  ACCEPT direction — which is what its landing needed);
* lane ARCH's `CalculateCameraTransform` nulls (432 cells): that site needs
  R to FALL (retail declines); adding caller units only raises R — wrong
  direction, so inert, exactly as the planner algebra predicts;
* all six colour rows here: no inline threshold in reach, so nothing at all.

## `noop_assign` is stranger than its name — and NOT logic-state-only

At FindPath's proven-sensitive position (`fpnoop.py`):

    no insertion            2329
    noop_assign x13         2373   (+44 — EMITS CODE)
    noop_assign x26         2428
    noop_assign x52         2526
    empty_scopes x13        2337

`p_grec = p_grec + 0;` on a live pointer parameter in this (EH-carrying)
function is **not folded — it emits real instructions**, i.e. as landed
bytes it would diverge from retail. Yet the same shape (`p_data = p_data+0`,
also a pointer param) was byte-inert in all 144 cells on `FUN_100c6fa0`, and
integer/local targets folded everywhere. Consequences:

1. `noop_assign` must never be treated as a non-emitting carrier; whether it
   emits depends on the target's liveness/EH context. Audit any landed use.
2. Where it does emit, it is an IL-weight PROBE (evidence only), not a donor.
3. Where it folds, it contributes nothing — not even budget units.

## Doctrine

* **Do not scale the body axis over the colour/schedule rows** — six diverse
  specimens, ~1,400 control-validated cells, zero effect.
* **Re-aim it at the inline-budget-gated rows whose deficit is in the ACCEPT
  direction.** `empty_scopes` are exactly the "+n caller IL units with zero
  blast radius" lever the planner ledger priced sites in units of
  (FindPath's own landing is the precedent). Candidate class: any site the
  planner table lists with a positive caller-unit deficit toward ACCEPT
  (e.g. the E3 shape at `0x10061010` — needs R to rise; owner lane's call).
* A positive control belongs in every body-axis cell block, permanently; a
  null without one is unreadable (ARCH's rule, confirmed here).
