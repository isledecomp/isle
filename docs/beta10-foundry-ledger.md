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
| 0x10057260 | ~LegoPathBoundary | .8780 | BETA10 0x100b140d loop condition calls 2-arg cdecl free `operator!=` (not member `==`): original spelling `it != m_actors.end()`. Matches recorded verdict "exact at 380B with !=". | dtor loop `!(it == ...)` -> `it != ...` | TEXT-PROVEN / SWEEP-PENDING (see follow-up section: landing refused net -10/+7, reverted) |
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

## legopathboundary follow-up: the != landing measured and reverted

The `it != m_actors.end()` dtor spelling WAS landed once through the full pipeline
(with the composition donor re-derived to shape(4,4), which passes compose+nonemit with
the new source): the gate refused at 4813/4933 with 10 LOST / 7 GAIN. Losses included
4 in-TU rows (SwitchBoundary 0x10057720, ~_Tree<LegoAnimPresenterSet> 0x10056c20,
iterator::_Dec 0x10058330, _Distance 0x100589a0) — the record-dial ripple from ADDING the
free operator!= instantiation — plus cross-TU losses (GasStation::HandleEndAction,
_Tree<LegoPathActorSet>::find/_Copy at 0x1002c440/0x1002c5b0, UpdateStructMapAndROIIndex,
VerifyAnimationNode, GetActorROI) via link-level COMDAT/supplier shifts. Reverted; the
worktree holds the original text. VERDICT: TEXT-PROVEN (380 B body, 1 residual CMPDIR
byte at offset 195) / SWEEP-PENDING — needs a TU carrier retune like legoanimpresenter.
The shape(4,4) donor derivation (insert pin 3265be15... reproduced, seed line-count 16)
is recorded here for the sweep session: manifest fields to change are
translation_units[0].donors[0].recipe{classes:4, functions:4, generated_header_sha256:
6230255937df0bd54a4f5a674c99f96a9a955c966950859bf946c53fdaf45790} and
functions[0].expected_seed_line_count: 16.

## mxdisplaysurface.cpp — LANDED d46ebb6f

| row | name | m before | m after | edit |
|---|---|---|---|---|
| 0x100bacc0 | VTable0x28 | .9269 | .9426 | `MxS32 j;` hoisted above the 16-bit blit row loop (both identical sites) |
| 0x100bb1d0 | VTable0x30 | .8294 | .8611 | same edit (textually shared site) |

Probe evidence: only these two COMDATs changed in the object (25 others bit-identical);
hoist_i/hoist_ij/hoist_ji and all term-order/imul-order/paren-barrier variants of the
`surface =` expressions are BIT-INERT (integer + chains are fully canonicalized; the
s46 paren barrier does NOT apply to int/pointer arithmetic — measured this session).
Remaining V28 94 B / V30 68 B: prologue GetBmiHeightAbs register tie, the imul first-load
order at the surface= sites, and loop-bottom CMPDIR mirrors — all state-class.
VTable0x44/VTable0x2c are exact at 1.0 with the SAME surface= spelling, proving the
canonical order is compile-state, not source. BETA10 0x1014012b read-off confirms our
counter structure (shared height/i in 16-bit scaled; i/j split in unscaled) and the
June surface= term order `lPitch*p_bottom + lpSurface + p_right`, which is emission-
equivalent under canonicalization.

## legonavcontroller.cpp — LANDED 231e335c

| row | name | m before | m after | edit |
|---|---|---|---|---|
| 0x10055a60 | LegoNavController::Notify | .9438 | .9482 | swap `m_keyPressed = TRUE;` after `MxU8 key = ...GetKey();` per BETA10 0x1009c712 statement order |

Remaining residue: p_param register naming (eax vs edx), a key rematerialization at the
g_currentInput compare, g_animationCalcStep store scheduling (interleave — same source
order both sides), CMPDIR bits — state-class.

## Rows triaged to STATE-CLASS / CLOSED this session (no text lever exists; do not re-read)

- Act3::TriggerHitSound 0x10072ad0 (.9302): residue is 5x table-load register (retail ecx,
  ours eax). BETA10 0x10015eec one-step form `objectId = table[counter++]` measured WORSE
  (11 -> 41 B) — June-drift trap; decl-swap time/objectId inert. Also BETA10 has a
  since-removed time-threshold guard at [this+0x4020].
- LegoAnimationManager::FUN_10062e20 0x10062e20 (.8856): esi/ebx tie between `i` and the
  characterId*24 CSE temp; i-first and i-hoist variants bit-inert; BETA10 0x100444cb
  local set matches ours.
- MxVideoPresenter::AlphaMask::IsHit 0x100b26f0 (.9348): single CMPDIR + xor slot;
  comparison text measured inert historically.
- MxVideoPresenter::AlphaMask ctor 0x100b24f0 (.9612): 100% effective match; dx/ax tie +
  one reload — state.
- MxVideoPresenter::Destroy 0x100b27b0: no named locals (structurally out of reach).
- MxVideoPresenter::PutFrame 0x100b2a70: recorded closed (this-pointer permutation).
- TglImpl::TextureImpl::SetImage 0x100a12a0 (.6667): pure ebx/ebp swap between `result`
  and the vtbl temp; BETA10 0x10169113 confirms our decl order (result at -4). The low
  score is only because the function is tiny.
- TglImpl::MeshBuilderImpl::Clone 0x100a3b40 (.7971): esi/edi swap in tglimpl.h inline
  (multi-supplier header) — supplier treatment, not TU text.
- ViewLODListManager::~ViewLODListManager 0x100a7130 (.9281): CMPDIR + temp-slot order in
  inlined map dtor walk.
- LegoOmni::Destroy 0x10058c30 (.9827): `add edi,8` addressing-mode hoist inside inlined
  container dtor — callee-side, recorded KILLED for legomain source.
- LegoPathController::PlaceActor 0x10045c20 (.9442): GetElapsedTime inline emits a direct
  `fild [g_lastTimeTimerStarted]` where retail spills through the frame slot — inline-shape
  family + CMPDIR at the _Nil walk; the mxtimer.h text is shared by many exact rows.
- OrientableROI::UpdateTransformationRelativeToParent / GetLocalTransform: x87 stack
  scheduling under depth pressure; float trees already retail's (recorded exhaustion),
  operand order in * inert. vec.h text verified by the x87 fingerprint — no vec.h debt
  is resolvable from these two rows.
- LegoPathController::FindPath 0x10048310: recorded HELD (decl move costs 5 template
  COMDAT rows, net -4).
- JetskiRace::HandlePathStruct, Isle::Enable, LegoWEGEdge::LinkEdgesAndFaces,
  MxDSBuffer::FUN_100c6fa0, Act3::Enable (dated Aug->Sep edit), Act1State ctor (BETA10
  layout differs), ParseExtra (s64): all previously closed with mechanisms — confirmed
  not re-opened.

## Parked leads for dedicated sessions

- LegoLOD::Read 0x100aa510 (.7268): the recorded frame-delta lead (retail 0x174 vs our
  0x170 = one missing USED named local). Our source already transcribes the BETA10-only
  local (`local4c`); if the whole June local set is present, the extra retail slot is
  post-BETA — likeliest at the "TODO: Can't get this one right" numVerts/numNormals
  extraction (a named intermediate would give both the slot and a cleaner shape).
  Needs its own session (143 slot permutations, slow TU).
- ~MxStreamController 0x100c1290 (.6082): known 566-byte call-first/inline-last form
  (diff205) + the recorded need=-48 joint-satisfiability blocker — composer/link-input
  work, not text.
- MxDisplaySurface::Create 0x100ba7f0 (.9953): single scheduling slot recorded; state.

## Session summary (2026-08-15)

- Landings: d46ebb6f (VTable0x28 .9269->.9426, VTable0x30 .8294->.8611),
  231e335c (Notify .9438->.9482). Rows flipped: 0. Baseline stays 4817/4933; all
  gates green; tests green (56 tests OK).
- Text-proven, sweep-pending (byte-exact or retail-length bodies in hand, blocked by
  TU carrier retunes): AssignIndiciesWithMap (412 B EXACT), BuildROIMap (617 B, 15 B),
  ~LegoPathBoundary (380 B, 1 B).
- BETA10-contradicts-retail (retail wins, recorded): BuildROIMap loop spelling,
  TriggerHitSound one-step form + removed time guard, CreateROIAndBuildMap key local,
  Act1State layout (prior), Notify c_notificationKeyPress value (0xa in June vs 7).
- Method finding (new, measured): integer/pointer `+` chains are FULLY canonicalized by
  MSVC 4.2 /O2 — term order, imul operand order, and even explicit parens are
  BIT-INERT (the s46 float paren barrier does not extend to int). Emission order of
  such chains is compile-state; do not spend text probes on them.
- Method finding: single-variable scope hoists are sharply non-monotonic
  (hoist_j hit, hoist_i/hoist_ij/hoist_ji inert or worse) — sweep the four forms per
  loop nest, they cost one compile each out-of-tree.
