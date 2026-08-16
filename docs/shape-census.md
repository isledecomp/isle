# The corrected SHAPE/STRUCT census — every open LEGO1 row

Measured 2026-08-16 at **LEGO1 4853/4934, 81 open**, base `cd8692bb`.
Regenerate with `<session scratchpad>/fin/census.py --json census.json --md
census.md`; machine-readable copy alongside it as `census.json`.

This is the map every lane should plan from. It replaces "which rows look
close" (a byte count that is blind to program shape) with **which channel each
row is in**, and for one bucket it is a *proof* rather than an estimate.

## What the three numbers mean

`adiff` aligns our compiled COMDAT against the retail body with `difflib` and
scores it at three levels of erasure:

| level | erases | answers |
|---|---|---|
| **SHAPE** | registers, frame displacements, relocated/absolute operands | does our source emit retail's *operations*? |
| **STRUCT** | registers only | …and does it put values in retail's *frame slots*? |
| **EXACT** | nothing but relocation/branch operands | …and retail's *colouring*? |

## Method, and how it differs from the first census

`docs/inliner-ledger.md` §12.8 published the first SHAPE census. This one:

* runs on the **corrected** instrument — Lane FIN wave 2 found nine
  normalisation asymmetries, every one inflating the gap
  (`docs/finish-line-ledger.md` §26, §26.1);
* reads our side from the compiled **object** and retail's body from
  `oracles-v2.json` (the true body, padding stripped) rather than a slice to
  the next annotated address, so neither side inherits a length guess;
* reports **STRUCT**, which the first census did not have;
* **classifies each divergence**, because two different things masquerade as
  "different operations" (below).

### Cross-validation: the first census was mostly right

Of its 20 published numbers, **19 reproduce to the second decimal**. Only one
moves:

| addr | published | corrected | Δ | row |
|---|---|---|---|---|
| `0x10055a60` | 88.44 | **94.42** | **+5.98** | `LegoNavController::Notify` |

That is the whole numeric disagreement. The reason the rest agree is
structural: the first census reads **linked images**, where relocations are
resolved on both sides, so five of my nine defects (all relocation-side) cannot
reach it, and it had already fixed `fs:[0]` and the disp/imm attribution. What
it could not avoid is defect 1 — **a `.text` COMDAT that carries switch jump
tables has them disassembled as code** — and `Notify` is the open set's
biggest switch.

So the value added here is *not* a wholesale re-rating. It is one corrected
row, the STRUCT column, and the divergence classification.

## The two things that masquerade as an operation-sequence gap

Both were reported against the metric in wave 2 and are now detected
automatically:

1. **`cmpdir`.** `cmp eax,[x]` versus `cmp [x],eax` is the same operation with
   exchanged operands — and exchanging them *inverts the branch*, so it appears
   as `[cmp X,Y ; ja]` against `[cmp Y,X ; jb]`. SHAPE does not erase operand
   order, so it scores as a gap at **all three levels**. The project's own
   canonicalisation law says comparison direction is not source-addressable,
   and `docs/finish-line-ledger.md` §28 closed the one text lever that was
   documented as live for it. **Seven open rows are entirely this.**
2. **Permutation.** The same instructions in a different order score SHAPE 100
   when they differ only in frame slots (`Helicopter::HandleControl`) and score
   a SHAPE gap when they differ in anything SHAPE keeps (`ReadData`,
   `PizzeriaState`, `Act1State`). SHAPE alone is therefore *not* a
   source/not-source discriminator.

## The verdicts

| verdict | rows | test | what to do |
|---|---|---|---|
| **TEXT-CLOSED (proof)** | **10** | SHAPE 100 **and** STRUCT 100 | Never send another source variant. Our source emits retail's program *and* retail's frame layout; the residue is register colour by construction. |
| **FRAME (decl-set)** | **3** | STRUCT < SHAPE **and** `sub esp` differs | A genuine declaration-set defect. `(ours − retail)/4` is the slot budget. The strongest text signal in the set. |
| **ENREG (same frame)** | **10** | STRUCT < SHAPE **and** `sub esp` equal | The two sides agree on every operation and on the frame *size*, but reference different slots — a different choice of which value to keep in a register. A new class; see below. |
| **cmpdir (allocator)** | **7** | every divergence is a compare with exchanged operands | Not a text target. Allocator/scheduler. |
| **SHAPE gap (text target)** | **51** | real operation differences remain | Worth reading — with the caveat that a spill also adds a `mov`, so this means "read it", not "source defect confirmed". |

### TEXT-CLOSED — the ten rows that are provably done with the text channel

`0x1002a1b0` `_Tree<LegoCacheSoundEntry>::_Erase` · `0x1002f770`
`LegoPathActor::UpdatePlane` · `0x1004bd10`
`MxTransitionManager::DissolveTransition` · **`0x1004d330`
`TowTrack::HandlePathStruct`** · `0x100720d0`
`Act3List::RemoveByObjectIdOrFirst` · `0x10080be0`
`LegoCarRaceActor::CalculateSpline` · `0x100a3b40`
`TglImpl::MeshBuilderImpl::Clone` · `0x100b24f0`
`MxVideoPresenter::AlphaMask::AlphaMask` · `0x100ba2c0`
`MxStillPresenter::Clone` · `0x100c3750` `MxRegion::AddRect`

Three membership changes against the first census's eleven:

* **`0x1004d330 TowTrack::HandlePathStruct` is new** — it was not in the first
  list and is SHAPE 100 / STRUCT 100 here.
* **`0x100035e0 Helicopter::HandleControl` is demoted.** SHAPE is 100.00 but
  **STRUCT is 99.05**, so it fails the proof: its three permuted stores land in
  different frame slots. It belongs in ENREG.
* `0x10038b10 Pizza::HandleEndAction` was in the first list and has since
  **landed**, so it is no longer open.

Two independent confirmations that the bucket is sound: `MxRegion::AddRect` is
the row `docs/inliner-ledger.md` §11.6 found **six** source variants
bit-identical on, and `MxStillPresenter::Clone` is SHAPE 100 / STRUCT 100
while carrying a **−1 length defect** — the encoding cost of `and al,1` (2
bytes) against our `and cl,1` (3).

### FRAME (decl-set) — and an independent reproduction of the frame census

| row | `sub esp` ours/retail | slot budget | SHAPE | STRUCT |
|---|---|---|---|---|
| `0x10061010 LegoAnimationManager::FUN_10061010` | 0x2c / 0x38 | **−3** | 93.08 | 68.26 |
| `0x100aa510 LegoLOD::Read` | 0x170 / 0x174 | **−1** | 97.90 | 76.88 |
| `0x100998e0 LegoTextureContainer::GetCached` | 0xfc / 0xf8 | **+1** | 98.52 | 90.24 |

`docs/open-set-triage.md`'s frame census found **exactly four** rows in the
open set with a differing `sub esp`; the fourth,
`MxStreamController::~MxStreamController`, has since landed. This census
rediscovers the other three from a completely different measurement — an
aligned instruction diff, not a prologue read — and assigns them the same slot
budgets. Two instruments, one answer.

### ENREG (same frame) — a class nobody had

Ten rows where **every operation agrees and the frame size agrees**, but
aligned instructions reference different slots:

| row | SHAPE | STRUCT | Δ |
|---|---|---|---|
| `0x1006b140 LegoAnimPresenter::CopyTransform` | 98.31 | **87.84** | 10.47 |
| `0x10048310 LegoPathController::FindPath` | 96.75 | 91.33 | 5.42 |
| `0x100a84a0 LegoROI::Read` | 97.99 | 96.50 | 1.49 |
| `0x100293c0 LegoControlManager::UpdateEnabledChild` | 96.89 | 95.65 | 1.24 |
| `0x10069b10 LegoAnimPresenter::BuildROIMap` | 99.47 | 98.42 | 1.05 |
| `0x100035e0 Helicopter::HandleControl` | 100.00 | 99.05 | 0.95 |
| `0x10040360 Act3Cop::FUN_10040360` | 97.97 | 97.16 | 0.81 |
| `0x100a3840 TglImpl::MeshBuilderImpl::CreateMesh` | 98.46 | 98.02 | 0.44 |
| `0x10055a60 LegoNavController::Notify` | 94.42 | 94.08 | 0.34 |
| `0x100417c0 Act3Brickster::FUN_100417c0` | 98.08 | 97.96 | 0.12 |

Two of them were read by hand in `docs/finish-line-ledger.md` §26.3 and share
one mechanism across two TUs: **retail spends a callee-saved register on a
parameter and holds it across a region where we leave it in memory and
reload.** In both, that single decision is the row's entire length delta.

`0x1006b140 CopyTransform` is the specimen worth reading next, and it also
**corrects the frame census's own law**: `docs/open-set-triage.md` names
CopyTransform as the clean example of *"identical `sub esp` ⇒ COLOUR. Do not
transcribe."* Its `sub esp` is indeed identical — and its slot assignment
disagrees by more than ten points. An equal frame **size** does not imply an
equal frame **layout**.

### cmpdir — seven rows that are not text targets

`0x1001d890` · `0x10029d50` · `0x10057180` · `0x1007ca30` · `0x10083500` ·
`0x10083890` · `0x100166a0`

**`0x10057180 _Tree<LegoAnimPresenter*>::_Erase` is the consequential one.**
The first census ranks it third-worst in the open set and therefore among the
best text targets. Its entire SHAPE gap is two `cmp reg,[_Nil]` sites where
retail has `cmp [_Nil],reg`:

```
+11  ours cmp r, dword ptr [R]     retail cmp dword ptr [R], r
+43  ours cmp r, dword ptr [R]     retail cmp dword ptr [R], r
```

That is the same defect, in the same inlined `_Tree` walk, as
`LegoPartPresenter::Read` — where five line-neutral text cells were run and
every one was strictly worse (`docs/finish-line-ledger.md` §28). **Do not send
a lane at `_Erase` for a text answer.**

### The largest *real* operation-sequence gaps, corrected

| SHAPE | m | addr | ours/ret | row |
|---|---|---|---|---|
| 90.13 | .8696 | `0x100a46b0` | 2515/2515 | `OrientableROI::UpdateTransformationRelativeToParent` |
| 92.31 | .8227 | `0x1004c580` | 413/412 | `MxTransitionManager::SetupCopyRect` |
| 94.13 | .8856 | `0x10062e20` | 1098/1098 | `LegoAnimationManager::FUN_10062e20` |
| 94.23 | .8896 | `0x1009f490` | 1074/1121 | `LegoAnimScene::CalculateCameraTransform` |
| 94.27 | .8848 | `0x100a66f0` | 557/561 | `ViewManager::ManageVisibilityAndDetailRecursively` |
| 94.69 | .9552 | `0x10046050` | 693/703 | `LegoPathController::PlaceActor` |
| 94.87 | .6667 | `0x100a12a0` | 83/83 | `TglImpl::TextureImpl::SetImage` |
| 95.04 | .9504 | `0x100a4420` | 520/514 | `OrientableROI::OrientableROI` |

**`LegoNavController::Notify` is no longer the largest gap in the open set.**
At 94.42 it ranks behind at least six rows. It is still a legitimate text
target — its divergences classify as `real` and we emit 1,183 instructions
against retail's 1,147 — but the ranking that made it "the single
best-evidenced next target" was an artefact of its switch tables being
disassembled as code. The top of the list is
`UpdateTransformationRelativeToParent`, which `docs/inliner-ledger.md` §12.2
has already shown has **no source lever** (its differing operations are
permuted FP addend spans produced inside `3rdparty/vec/vec.h`), so the honest
top of the *actionable* list is `SetupCopyRect` at 92.31.

## Caveats

* **A `cmpdir` is invisible to the three levels** — it scores identically at
  SHAPE, STRUCT and EXACT. The classifier catches it; a human reading only the
  numbers will not.
* **A permutation scores either way** (SHAPE 100 or a gap) depending on whether
  the reordered instructions differ in something SHAPE keeps.
* **`SHAPE < 100` means "read it", not "source defect confirmed"** — an
  allocator that spills where retail keeps a register also adds a `mov`.
* **`STRUCT < SHAPE` splits two ways**, and `sub esp` separates them for free.
* The `TEXT-CLOSED` direction is the only one that is a *proof*, and it is the
  one worth acting on hardest: ten rows can leave every text queue permanently.

### Auditable: the six rows whose COMDAT carries a switch jump table

Defect 1 is the only one that reaches an image-level census, so these are
exactly the rows whose first-census score was wrong. `code_len()` finds the
trailing run of DIR32 relocations to `$L` labels at 4-byte stride (>= 3
entries, one gap bridged for the byte index table) and scores only the code;
retail is trimmed by the same number of trailing bytes, which is correct
because the table has one entry per case on both sides.

| addr | body | code | table | row |
|---|---|---|---|---|
| `0x100035e0` | 1148 | 1120 | 28 | `Helicopter::HandleControl` |
| `0x10031820` | 3580 | 3436 | 144 | `Isle::Enable` |
| `0x1004d330` | 856 | 836 | 20 | `TowTrack::HandlePathStruct` |
| `0x10055a60` | 4120 | 4100 | 20 | `LegoNavController::Notify` |
| `0x1006fda0` | 264 | 200 | 64 | `Infocenter::HandleKeyPress` |
| `0x10072ad0` | 348 | 324 | 24 | `Act3::TriggerHitSound` |

`TowTrack::HandlePathStruct` is the one this promoted into `TEXT-CLOSED`, and
it is worth stating how that was checked: a naive spot-check of the row scores
**95.65**, and chasing that disagreement is what confirmed the trimming rather
than the census. The 20 trailing bytes are five jump-table entries at 836–855;
the two other `$L` relocations in the body (offsets 12 and 598) are ordinary
label references in code and are correctly excluded by the stride rule.

## The full census

| SHAPE | STRUCT | EXACT | m | addr | ours/ret | verdict | row |
|---|---|---|---|---|---|---|---|
| 100.00 | 100.00 | 70.59 | 0.7059 | `0x1002a1b0` | 82/82 | TEXT-CLOSED (proof) | `_Tree<LegoCacheSoundEntry,LegoCacheSoundEntry,set<Lego` |
| 100.00 | 100.00 | 93.15 | 0.9315 | `0x1002f770` | 188/188 | TEXT-CLOSED (proof) | `LegoPathActor::UpdatePlane` |
| 100.00 | 100.00 | 96.08 | 0.9608 | `0x1004bd10` | 438/438 | TEXT-CLOSED (proof) | `MxTransitionManager::DissolveTransition` |
| 100.00 | 100.00 | 95.24 | 0.9536 | `0x1004d330` | 856/856 | TEXT-CLOSED (proof) | `TowTrack::HandlePathStruct` |
| 100.00 | 100.00 | 94.17 | 0.9417 | `0x100720d0` | 323/323 | TEXT-CLOSED (proof) | `Act3List::RemoveByObjectIdOrFirst` |
| 100.00 | 100.00 | 95.87 | 0.9545 | `0x10080be0` | 779/778 | TEXT-CLOSED (proof) | `LegoCarRaceActor::CalculateSpline` |
| 100.00 | 100.00 | 79.71 | 0.7971 | `0x100a3b40` | 197/197 | TEXT-CLOSED (proof) | `TglImpl::MeshBuilderImpl::Clone` |
| 100.00 | 100.00 | 96.12 | 0.9612 | `0x100b24f0` | 346/346 | TEXT-CLOSED (proof) | `MxVideoPresenter::AlphaMask::AlphaMask(class MxBitmap ` |
| 100.00 | 100.00 | 94.65 | 0.9251 | `0x100ba2c0` | 577/576 | TEXT-CLOSED (proof) | `MxStillPresenter::Clone` |
| 100.00 | 100.00 | 97.39 | 0.9739 | `0x100c3750` | 1157/1157 | TEXT-CLOSED (proof) | `MxRegion::AddRect` |
| 100.00 | 99.05 | 99.05 | 0.9907 | `0x100035e0` | 1148/1148 | ENREG (same frame) | `Helicopter::HandleControl` |
| 99.73 | 99.73 | 94.40 | 0.9212 | `0x10029d50` | 1117/1119 | cmpdir (allocator) | `_Tree<LegoCacheSoundEntry,LegoCacheSoundEntry,set<Lego` |
| 99.73 | 99.73 | 90.27 | 0.9027 | `0x1001d890` | 1106/1106 | cmpdir (allocator) | `_Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,al` |
| 99.73 | 99.73 | 96.48 | 0.9498 | `0x10081840` | 1163/1168 | SHAPE gap (text target) | `LegoCarRaceActor::CheckPresenterAndActorIntersections` |
| 99.70 | 99.70 | 96.36 | 0.9636 | `0x1007b770` | 1089/1089 | SHAPE gap (text target) | `LegoVideoManager::Tickle` |
| 99.61 | 99.61 | 99.21 | 0.9921 | `0x1009a8c0` | 1494/1494 | SHAPE gap (text target) | `LegoWEGEdge::LinkEdgesAndFaces` |
| 99.60 | 99.60 | 85.02 | 0.8205 | `0x1006dec0` | 1113/1104 | SHAPE gap (text target) | `_Tree<char const *,pair<char const * const,LegoHideAni` |
| 99.53 | 99.53 | 99.53 | 0.9953 | `0x1007ca30` | 2633/2633 | cmpdir (allocator) | `LegoPartPresenter::Read` |
| 99.53 | 99.53 | 99.53 | 0.9953 | `0x100ba7f0` | 660/660 | SHAPE gap (text target) | `MxDisplaySurface::Create` |
| 99.47 | 98.42 | 90.53 | 0.8842 | `0x10069b10` | 622/617 | ENREG (same frame) | `LegoAnimPresenter::BuildROIMap` |
| 99.37 | 99.37 | 84.99 | 0.7983 | `0x1006a7a0` | 686/690 | SHAPE gap (text target) | `_Tree<char const *,pair<char const * const,LegoAnimStr` |
| 99.36 | 99.36 | 85.22 | 0.8051 | `0x1004f9b0` | 681/679 | SHAPE gap (text target) | `_Tree<char const *,pair<char const * const,LegoTexture` |
| 99.36 | 99.36 | 83.51 | 0.7828 | `0x1006c200` | 678/682 | SHAPE gap (text target) | `_Tree<char const *,pair<char const * const,char const ` |
| 99.32 | 99.32 | 85.21 | 0.7680 | `0x10068b20` | 1104/1096 | SHAPE gap (text target) | `_Tree<char const *,pair<char const * const,char const ` |
| 99.17 | 99.17 | 98.90 | 0.9752 | `0x100170e0` | 1391/1391 | SHAPE gap (text target) | `CarRace::HandlePathStruct` |
| 99.14 | 99.14 | 99.14 | 0.9827 | `0x10058c30` | 568/571 | SHAPE gap (text target) | `LegoOmni::Destroy` |
| 99.10 | 99.10 | 69.37 | 0.6532 | `0x100495b0` | 648/648 | SHAPE gap (text target) | `_Tree<LegoBEWithMidpoint *,LegoBEWithMidpoint *,multis` |
| 99.10 | 99.10 | 74.21 | 0.7075 | `0x10083890` | 652/653 | cmpdir (allocator) | `_Tree<char *,pair<char * const,LegoCharacter *>,map<ch` |
| 98.94 | 98.94 | 88.37 | 0.8475 | `0x1006e720` | 686/689 | SHAPE gap (text target) | `_Tree<char const *,pair<char const * const,LegoHideAni` |
| 98.94 | 98.94 | 93.95 | 0.9365 | `0x10084030` | 2294/2294 | SHAPE gap (text target) | `LegoCharacterManager::CreateActorROI` |
| 98.92 | 98.92 | 92.14 | 0.8780 | `0x100a7960` | 1101/1100 | SHAPE gap (text target) | `_Tree<char const *,pair<char const * const,ViewLODList` |
| 98.91 | 98.91 | 98.91 | 0.9891 | `0x100334b0` | 843/843 | SHAPE gap (text target) | `Act1State::Act1State` |
| 98.91 | 98.91 | 92.73 | 0.9273 | `0x1003f540` | 854/854 | SHAPE gap (text target) | `WriteDefaultTexture` |
| 98.82 | 98.82 | 98.82 | 0.9882 | `0x100c6fa0` | 234/234 | SHAPE gap (text target) | `MxDSBuffer::FUN_100c6fa0` |
| 98.81 | 98.81 | 90.91 | 0.8893 | `0x10073a90` | 930/929 | SHAPE gap (text target) | `Act3::Enable` |
| 98.80 | 98.80 | 86.75 | 0.8675 | `0x100166a0` | 645/645 | cmpdir (allocator) | `JetskiRace::HandlePathStruct` |
| 98.73 | 98.73 | 92.41 | 0.9302 | `0x10072ad0` | 348/348 | SHAPE gap (text target) | `Act3::TriggerHitSound` |
| 98.71 | 98.71 | 90.99 | 0.8966 | `0x1006ed90` | 380/381 | SHAPE gap (text target) | `Infocenter::Create` |
| 98.64 | 98.64 | 84.51 | 0.7745 | `0x10069e90` | 1104/1096 | SHAPE gap (text target) | `_Tree<char const *,pair<char const * const,LegoAnimStr` |
| 98.56 | 98.56 | 98.56 | 0.9426 | `0x1002de10` | 746/743 | SHAPE gap (text target) | `LegoPathActor::SetTransformAndDestinationFromPoints` |
| 98.52 | 90.24 | 86.69 | 0.8698 | `0x100998e0` | 987/987 | FRAME (decl-set) | `LegoTextureContainer::GetCached` |
| 98.46 | 98.60 | 95.53 | 0.9476 | `0x10054050` | 2665/2666 | SHAPE gap (text target) | `Act3Ammo::Animate` |
| 98.46 | 98.02 | 82.20 | 0.8176 | `0x100a3840` | 667/664 | ENREG (same frame) | `TglImpl::MeshBuilderImpl::CreateMesh` |
| 98.31 | 87.84 | 86.15 | 0.8149 | `0x1006b140` | 941/948 | ENREG (same frame) | `LegoAnimPresenter::CopyTransform` |
| 98.25 | 98.25 | 96.84 | 0.9684 | `0x10083500` | 822/822 | cmpdir (allocator) | `LegoCharacterManager::GetActorROI` |
| 98.22 | 98.22 | 92.44 | 0.9244 | `0x10085500` | 653/653 | SHAPE gap (text target) | `_Tree<char *,pair<char * const,LegoCharacter *>,map<ch` |
| 98.21 | 98.21 | 87.50 | 0.7933 | `0x1006fda0` | 264/272 | SHAPE gap (text target) | `Infocenter::HandleKeyPress` |
| 98.20 | 98.20 | 97.08 | 0.9725 | `0x10031820` | 3580/3580 | SHAPE gap (text target) | `Isle::Enable` |
| 98.10 | 98.10 | 82.38 | 0.7913 | `0x10059dc0` | 1103/1102 | SHAPE gap (text target) | `_Tree<char const *,pair<char const * const,LegoTexture` |
| 98.08 | 97.96 | 94.96 | 0.9496 | `0x100417c0` | 2875/2875 | ENREG (same frame) | `Act3Brickster::FUN_100417c0` |
| 97.99 | 96.50 | 93.51 | 0.9277 | `0x100a84a0` | 2061/2058 | ENREG (same frame) | `LegoROI::Read` |
| 97.97 | 97.16 | 96.89 | 0.9730 | `0x10040360` | 2496/2496 | ENREG (same frame) | `Act3Cop::FUN_10040360` |
| 97.90 | 76.88 | 73.38 | 0.7268 | `0x100aa510` | 1694/1693 | FRAME (decl-set) | `LegoLOD::Read` |
| 97.83 | 97.83 | 75.27 | 0.7092 | `0x1002bff0` | 1104/1096 | SHAPE gap (text target) | `_Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActo` |
| 97.80 | 97.80 | 87.91 | 0.8791 | `0x100b27b0` | 247/247 | SHAPE gap (text target) | `MxVideoPresenter::Destroy(unsigned char)` |
| 97.77 | 97.77 | 93.32 | 0.9048 | `0x100b2a70` | 1254/1260 | SHAPE gap (text target) | `MxVideoPresenter::PutFrame` |
| 97.67 | 97.67 | 76.74 | 0.7442 | `0x10038380` | 110/110 | SHAPE gap (text target) | `Pizza::StopActions` |
| 97.22 | 97.22 | 97.22 | 0.9722 | `0x100d0d80` | 424/424 | SHAPE gap (text target) | `ReadData` |
| 97.18 | 97.18 | 88.73 | 0.8873 | `0x10017af0` | 264/264 | SHAPE gap (text target) | `PizzeriaState::PizzeriaState` |
| 97.12 | 97.12 | 90.65 | 0.9101 | `0x10051ac0` | 1115/1115 | SHAPE gap (text target) | `LegoAct2::SpawnBricks` |
| 96.89 | 95.65 | 93.17 | 0.8625 | `0x100293c0` | 282/286 | ENREG (same frame) | `LegoControlManager::UpdateEnabledChild` |
| 96.81 | 96.81 | 81.91 | 0.7527 | `0x100574a0` | 253/258 | SHAPE gap (text target) | `LegoPathBoundary::RemoveActor` |
| 96.75 | 91.33 | 88.08 | 0.8629 | `0x10048310` | 2337/2338 | ENREG (same frame) | `LegoPathController::FindPath` |
| 96.72 | 96.72 | 87.09 | 0.8446 | `0x1004ebd0` | 745/739 | SHAPE gap (text target) | `LegoTexturePresenter::Read` |
| 96.43 | 96.43 | 73.81 | 0.8611 | `0x100bb1d0` | 811/811 | SHAPE gap (text target) | `MxDisplaySurface::VTable0x30` |
| 96.39 | 96.39 | 78.92 | 0.7470 | `0x100bd020` | 415/415 | SHAPE gap (text target) | `MxBitmap::BitBltTransparent` |
| 96.26 | 96.26 | 79.44 | 0.7757 | `0x100586e0` | 314/314 | SHAPE gap (text target) | `LegoPathBoundary::RemovePresenter` |
| 96.13 | 96.13 | 93.92 | 0.8950 | `0x1003cf20` | 274/258 | SHAPE gap (text target) | `LegoCacheSoundManager::~LegoCacheSoundManager` |
| 95.65 | 95.65 | 93.48 | 0.9348 | `0x100b26f0` | 101/101 | SHAPE gap (text target) | `MxVideoPresenter::AlphaMask::IsHit` |
| 95.52 | 95.52 | 95.52 | 0.9552 | `0x1003d170` | 282/281 | SHAPE gap (text target) | `LegoCacheSoundManager::FindSoundByKey` |
| 95.04 | 95.04 | 95.04 | 0.9504 | `0x100a4420` | 520/514 | SHAPE gap (text target) | `OrientableROI::OrientableROI` |
| 94.87 | 94.87 | 66.67 | 0.6667 | `0x100a12a0` | 83/83 | SHAPE gap (text target) | `TglImpl::TextureImpl::SetImage` |
| 94.69 | 94.69 | 94.69 | 0.9552 | `0x10046050` | 693/703 | SHAPE gap (text target) | `LegoPathController::PlaceActor(class LegoPathActor *, ` |
| 94.42 | 94.08 | 92.96 | 0.9482 | `0x10055a60` | 4120/4112 | ENREG (same frame) | `LegoNavController::Notify` |
| 94.27 | 94.27 | 92.71 | 0.8848 | `0x100a66f0` | 557/561 | SHAPE gap (text target) | `ViewManager::ManageVisibilityAndDetailRecursively` |
| 94.23 | 94.23 | 93.59 | 0.8896 | `0x1009f490` | 1074/1121 | SHAPE gap (text target) | `LegoAnimScene::CalculateCameraTransform` |
| 94.13 | 94.13 | 88.56 | 0.8856 | `0x10062e20` | 1098/1098 | SHAPE gap (text target) | `LegoAnimationManager::FUN_10062e20` |
| 93.08 | 68.26 | 63.48 | 0.5411 | `0x10061010` | 717/731 | FRAME (decl-set) | `LegoAnimationManager::FUN_10061010` |
| 92.31 | 92.31 | 84.95 | 0.8227 | `0x1004c580` | 413/412 | SHAPE gap (text target) | `MxTransitionManager::SetupCopyRect` |
| 91.30 | 91.30 | 65.22 | 0.6522 | `0x10057180` | 57/57 | cmpdir (allocator) | `_Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<Lego` |
| 90.13 | 90.13 | 88.83 | 0.8696 | `0x100a46b0` | 2515/2515 | SHAPE gap (text target) | `OrientableROI::UpdateTransformationRelativeToParent` |
