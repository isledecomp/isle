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

## Three verified nd=0 donors — ALL THREE LANDED (4853 → 4856)

Landed one at a time by this lane under the coordinator's exclusion lift,
gating between each; every landing showed its GAIN with an **empty LOST
list**, ISLE/CONFIG stayed MD5-identical, the accepted set was repinned after
each, and the suite is 53 passed / 3 skipped:

* `5699f646` — 0x10069e90 (same_slot_resize 1104→1096, span unchanged) → 4854
* `81b641f9` — 0x10068b20 (same_slot_resize 1104→1096, span unchanged) → 4855
* `bbc99b77` — 0x100495b0 (equal_body_eh_reloc_layout 648/648; link winner
  re-verified at the tip: lpc is the only rsp object defining the COMDAT) → 4856

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
provenance.

## The hard core: 15 rows that never reach retail's length in ANY retained state

"Never" is corpus-relative (389,288 objects), but for most of these the TU
has thousands of retained states. Classifications from the triage +
archaeology ledgers:

**(a) The three inline-bit rows** — the only wrong call graphs in the open set
(census-exact), all sealed against the carrier axis (~24k cells across three
TUs this session) and against per-TU de-inline by the framework ruling:

| row | Δ | direction |
|---|---|---|
| `0x1009f490` CalculateCameraTransform | −47 | retail CALLS `Interpolate`, we expand+DCE |
| `0x100a4420` OrientableROI ctor | +6 | retail calls `Vector3::Vector3` (this+0xa8), we expand |
| `0x10061010` FUN_10061010 | −5, −3 frame slots | **opposite**: retail INLINES the `MxListEntry` ctor; flip alone leaves −11 unexplained |

**(b) Proven colour/encoding rows whose length delta is the ModRM/remat cost
of a register tie that has never flipped** in any swept state — the "one
shared allocator decision" signature, now archaeology targets per the adopted
doctrine (read the allocation → name the idiom → BETA10-check):

| row | Δlen | reading |
|---|---|---|
| `0x100aa510` LegoLOD::Read | +1 | retail's packer overlaps `numNormals`/`numPolys` by 2 bytes — allocator artifact in its purest form |
| `0x1006b140` CopyTransform | −7 | `mn` at `ebp-0x14` vs retail `ebp-0x90`; disp8-vs-disp32; declaration set beta-confirmed |
| `0x1006fda0` Infocenter::HandleKeyPress | −8 | eax↔ecx remat + jump-table pad; retail longer by register choice |
| `0x1006ed90` Infocenter::Create | −1 | register-role swap around the `GetState` result |
| `0x10080be0` CalculateSpline | +1 | identical instruction multiset — pure encoding |
| `0x100ba2c0` MxStillPresenter::Clone | +1 | identical multiset — pure encoding |

**(c) Small instruction-count deltas, not yet deep-read** — the cheapest next
reads (±1–2 instructions at a matching call graph is nearly always remat/
spill colour or one statement spelling):

| row | Δlen / Δinsn |
|---|---|
| `0x10046050` PlaceActor(actor, presenter) | −10 / −2 |
| `0x10058c30` LegoOmni::Destroy | −3 / −1 |
| `0x100293c0` UpdateEnabledChild | −4 / −1 |
| `0x1002de10` SetTransformAndDestinationFromPoints | +3 / +0 |
| `0x100a3840` MeshBuilderImpl::CreateMesh | +3 / +1 |
| `0x1004c580` SetupCopyRect | +1 / +1 (the nd-collapse cautionary row) |

Notable absentee: `0x100998e0` GetCached (a TEXT slot-budget row) DID reach
retail's length in 14 states (best nd=59) — its extra slot is reachable from
compile state alone, which slightly weakens the "must remove a named local"
reading.

## Doctrine (the transferable part)

1. **Sweep drivers must score every open-row symbol present in the object,
   not the stem's target list.** The `0x100495b0` donor existed for weeks in
   a goal-2 sweep that never looked at it.
2. **Harvest `results.json` of every long-running sweep at wave close** —
   two nd=0 hits sat in recorded result tables that no ledger transcribed.
3. Re-running this scan costs ~10 minutes with no compiles; it should open
   every wave (this is the third time the corpus paid — fresh-eyes-2 C1,
   lane FIN §0, and now).
