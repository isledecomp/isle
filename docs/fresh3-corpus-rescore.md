# Lane FRESH (fresh-eyes 3) — tree-wide corpus re-score, 2026-08-16

Baseline reproduced cold from this worktree before any work:
`ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE: LEGO1 4853/4934, ISLE 172/172,
CONFIG 111/111` (isle-build-nova, 107.4 s).

## What was run

`<scratchpad>/fresh3/rescore.py` — every retained `.obj` on disk (389,288
objects: this session's `bench/` + all lane dirs `fin/ nm/ stl/ arch/ b10w4/
inl/`, plus the aa9d0cc1 `sweep-bench`) scored against **all 81 currently-open
rows** with the corrected v2 oracles. Unlike every sweep driver, it scores
every open-row symbol an object contains, not the sweep stem's target list,
and it only reports `nd` at exact retail length (flex = CC-tail separately).
Oracle bytes for the three nominations below were re-verified byte-for-byte
against `legobin/LEGO1.DLL` before anything else was done.

## Three verified, hand-off-ready nd=0 donors (would take 4853 → 4856)

All three were **re-derived on today's HEAD shadow** (isle-build-nova, fresh
cold build of `entropy-stabilization` @ `25902aae`) and reproduce exactly;
relocation symbol sequences are identical to today's seed objects (0
mismatches, 0 `$L`/`$T` renumbers). Evidence dirs with `o.obj`+`s.cpp`:
`<scratchpad>/fresh3/rd-*`.

| row | m | state (landable kind) | owner |
|---|---|---|---|
| `0x10069e90` `_Tree<…LegoAnimStruct>::erase` | .7745 | `forward_run_with_shape`: shape(6,60) force-included + `MxUnkRecVC` run, width 3, count **422**, placement **suffix** (`stack_6_60_S-422`) | legoanimpresenter.cpp — Lane ARCH |
| `0x10068b20` `_Tree<…AnimSubst>::erase` | .7680 | `forward_declaration_run`: `MxUnkRecVC`, width 3, count **211** (or 467), placement **suffix** (`fCS-211`) | legoanimpresenter.cpp — Lane ARCH |
| `0x100495b0` `_Tree<LegoBEWithMidpoint*>::insert` | .6532 | `extern_run_pair`: g_h=**17** (post-include), g_p=**20** (EOF), width 2 (`extern-17-20`) | legopathcontroller.cpp — Lane B10 (link winner verified: only lpc emits this COMDAT) |

Where they came from, and why nobody had them:

* `stack_6_60_S-422` was **recorded by the L660 sweep's own `results.json`**
  (`stl/sw-all2-legoanimpresenter_L660`) but never harvested — the ledger's
  §8 table still says best nd=348 for this row.
* `fCS-211` sits in the k=97..999 long strip (`_LONG`) that §12.5 says was
  *still running when the wave closed*; its `results.json` records the hit,
  no ledger ever read it.
* `extern-17-20` was compiled by lane FIN's **goal-2** sweep
  (`fin/sw-fin-lpc6rect`), whose oracle stem did not include `0x100495b0` at
  all — the hit existed in the object and no scorer ever looked.

Both failure modes are systematic, not accidents; see "doctrine" below.

## Re-discoveries that are NOT landings (cross-checked, do not re-chase)

| row | scan | why blocked |
|---|---|---|
| `0x10084030` CreateActorROI | nd=0 (shape-5-26 et al.) | the S72 relocation-target FALSE POSITIVE class — `docs/nearmiss-wave4-ledger.md` §3/§20 |
| `0x10083500` GetActorROI | nd=0 (`nm/probes/chm-h12-ins2/insf-20-21`) | known complete recipe; needs interior-seat records (not in the composer grammar, only landable as effective text) + costs a victim — nearmiss ledger §7/§12 |
| `0x100574a0` LegoPathBoundary::RemoveActor | nd=0 (pad-10-12, old shadow) | STALE — floor nd=2 on later shadows (open-set-triage); NM has the pad_shape plan |
| `0x1003cf20` ~LegoCacheSoundManager | nd=0 (`b10w4/hprobes/lcsm-ool`) | the out-of-line text state; −12 pinned donors / 16 includers (memory top block) |
| `0x1002bff0` `_Tree<LegoPathActor*>::erase` | nd=0 (`nm/probes/lpb-stk2/stkE-11-1-3`) | donor object is **legopathboundary.cpp**, but the link winner is legoextraactor (rsp #33 < #82) — supplier-blocked; value is diagnostic (the body IS reachable from this source text) |
| `0x100a66f0` ManageVisibility… | nd=1 (a4 text × extern-3-1) | inliner-ledger §11.3a: text-invariant, carrier-invariant single-byte floor at +517; a4 perturbs a 1.0 row |

## Corpus-wide floor map

`<scratchpad>/fresh3/rescore.json` records, for every open row, the minimum
masked nd over the whole retained corpus at exact retail length, with state
provenance. Fifteen rows never reach retail's length in any retained state —
they coincide almost exactly with the triage's TEXT/INLINE channel
(CalculateCameraTransform, OrientableROI ctor, FUN_10061010, LegoLOD::Read,
MxStillPresenter::Clone, SetupCopyRect, PlaceActor(3-arg), LegoOmni::Destroy,
Infocenter::Create/HandleKeyPress, CalculateSpline, CreateMesh, CopyTransform,
UpdateEnabledChild, SetTransformAndDestinationFromPoints).

## Doctrine (the transferable part)

1. **Sweep drivers must score every open-row symbol present in the object,
   not the stem's target list.** The `0x100495b0` donor existed for weeks in
   a goal-2 sweep that never looked at it.
2. **Harvest `results.json` of every long-running sweep at wave close** —
   two nd=0 hits sat in recorded result tables that no ledger transcribed.
3. Re-running this scan costs ~10 minutes with no compiles; it should open
   every wave (this is the third time the corpus paid — fresh-eyes-2 C1,
   lane FIN §0, and now).
