# BETA10 transcription foundry — per-row ledger

Baseline at session start: LEGO1 4817/4933 (worktree at entropy-stabilization d462f067).
Method: read BETA10.DLL (/Od, June 1997) disassembly per annotated open row, transcribe the
evident original source structure into checked C++, verify with the full pipeline
(zero-loss gate). BETA10 is evidence; retail codegen is the target.

Row states: FLIPPED (1.0 reached) · TEXT-LANDED/SWEEP-PENDING (text matches BETA10, residue
is carrier-state class) · STATE-CLASS (text already verified, no text lever) ·
OUT-OF-SCOPE (vendor-template instantiation, no first-party source) · CONTRADICTION
(BETA10 differs from retail; retail preferred).

## legopathboundary.cpp

| row | name | m | evidence | edit | outcome |
|---|---|---|---|---|---|
| 0x10057260 | ~LegoPathBoundary | .8780 | BETA10 0x100b140d loop condition calls 2-arg cdecl free `operator!=` (not member `==`): original spelling `it != m_actors.end()`. Matches recorded verdict "exact at 380B with !=". | dtor loop `!(it == ...)` -> `it != ...` | pending build |
| 0x100574a0 | RemoveActor | .6527 | Retail diff: pure register-role permutation (edx/ebp/ebx ties) inside inlined `set::erase(key)` vendor code; source is a single call, matches BETA10 0x100b156f. | none possible | STATE-CLASS |
| 0x10057fe0 | AddPresenterIfInRange | .9000 | BETA10 0x100b2220 confirms operand order `p_presenter->m_boundingRadius + m_boundingRadius` (fld [p_presenter+0x260]; fadd [this+0x44]) — checked source already has it. Residue: /O2 commuted the fadd + operator= inline scheduling. | none (text verified) | STATE-CLASS (sweep candidate) |
| 0x100586e0 | RemovePresenter | .9346 | Retail diff: CMPDIR (`cmp ebp,[eax]` vs `cmp [eax],ebp`) in inlined find/end compare + eax/ecx register tie + scheduling. Text structure matches BETA10 0x100b22d1. | none | STATE-CLASS (CMPDIR class has written closure) |
| 0x10056d30 | LegoAnimPresenterSet::erase(it) | .7260 | vendor xtree instantiation; no first-party source. Known exact donor body exists (span-rule reject, PLAN 3.1). | n/a | OUT-OF-SCOPE (composer/span work) |
| 0x10057180 | LegoAnimPresenterSet::_Erase | .6522 | vendor xtree instantiation | n/a | OUT-OF-SCOPE |

Landing notes for 0x10057260 (probe-verified this session):
- With `it != m_actors.end()`, the plain seed compile produces the dtor at 380 B with exactly
  ONE byte of residue vs retail (offset 195: retail `3b 45 e8` cmp eax,[ebp-0x18] vs ours
  `39 45 e8` cmp [ebp-0x18],eax — the end()/_L compare inside the inlined vendor
  erase(first,last); STEP-3.5 class, not source-reachable). Span shrinks 400 -> 384 = retail.
- Collateral: the TU's composition op (retail-exact `_Tree<LegoAnimPresenter*>::insert` via
  declaration_shape(2,3) donor) had expected_seed_line_count 15 -> now 16 (updated in
  manifest); the (2,3) donor still produces the pinned retail insert body 3265be15... but now
  ALSO perturbs the dtor (385 B, +5) so verify_non_emitting_donor fails. Searching the full
  shape space for a cell with insert==pin AND dtor untouched (see outcome below).

## legoanimpresenter.cpp (one TU: LegoAnim/LegoLooping/LegoLocomotion/LegoHideAnimPresenter)

Recorded levers reproduced by probe compiles this session (out-of-tree, no landings):
- AssignIndiciesWithMap 0x1006dc10 (.9032): `it++` -> `++it` at the line-1639 loop gives the
  body at 412 B, 0 diffs vs retail (relocs masked) = BYTE-EXACT. Matches s39 record.
- BuildROIMap 0x10069b10 (.8842): `it++` -> `++it` (line 458) gives 617 B / 15 diffs
  (retail-exact length). BETA10 0x1004f976 shows `!(it == end())` + `++it, m_roiMapSize++`
  in the for-clause, but the probe shows that spelling REGRESSES retail codegen
  (622/116 + Assign broken) — post-BETA edit; retail kept `!=`. CONTRADICTION noted.
- BLOCKER (both edits, and even Assign-only): dropping the operator++(int) instantiation
  record(s) recolours OTHER functions in the TU. Probe matrix (byte diffs vs retail,
  relocs masked):
  - both edits, no compensation: PutFrame 62, ReadyTickle 7, Intersect 12, LoopPutFrame 81,
    CreateROIAndBuildMap 8 — five currently-1.0 rows break.
  - +1 forward-declaration record after BuildROIMap (`class X;` at the MxUnkRecordCN
    junction): restores PutFrame/ReadyTickle/Intersect/LoopPutFrame AND keeps Assign 0 /
    BuildROIMap 15 — but CreateROIAndBuildMap stays broken (8 B = pure ebx<->edi tie),
    invariant across 8 further record kind/position cells (def vs fwd vs typedef, SW-run +-1,
    QC/QK junctions, pre-0x1006d680).
  - Assign-only edit: single loss CheckedAdd 0x1006e470 (1.0 -> 2 B diff), also invariant
    across 3 compensation cells. BETA10 0x10053520 confirms our CheckedAdd declaration order
    (`it` first) — no text lever.
- VERDICT: TEXT-PROVEN / SWEEP-PENDING for the whole family. The zero-loss gate forbids the
  exchange (+1 flip vs -1 exact row). Needs a carrier-state retune of the TU (sweep bench),
  not more text. Do NOT re-derive: the probe scripts are in the session scratchpad
  (anim_probe.py) with all measured cells.
- UpdateStructMapAndROIIndex 0x1006a3c0 (.8673): donor-recipe debt row (PLAN 3.5 git-history
  bisect); BETA10 frame read-off shows same local set as ours (und2,data,count,i,und,name,roi,
  child) — position-only differences are inert. SKIP here.
- VerifyAnimationNode 0x1006abb0 (.9753): donor-debt row; decl-rotation lever already landed
  historically. SKIP.
- ParseExtra 0x1006bac0 (.9372): s64 measured-closed (no cell makes it exact; beta-backed
  shared-`i` correction does not land). SKIP.
- CopyTransform 0x1006b140 (.7674): body length changes with TU record state (941 fixed) but
  941 != retail span; residue class unresolved; row moved BETTER under the edits (748 vs 758
  byte-diff) — folds into the same sweep retune.
- The six _Tree rows in this batch (0x10068b20 0x10069e90 0x1006a7a0 0x1006c200 0x1006dec0
  0x1006e720): vendor instantiations, OUT-OF-SCOPE for text; their bodies shift with the same
  record state (observed in probes) — sweep-coupled.
