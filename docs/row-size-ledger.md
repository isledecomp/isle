# Row size ledger — the length defect reccmp cannot see

Measured 2026-08-15 night at LEGO1 4831/4933. Machine-readable copies:
`<session scratchpad>/bench/sizeledger.json` (this table) and
`<session scratchpad>/bench/oracles-v2.json` (the corrected sweep oracle).
Regenerate with `bench/sizeledger.py` / `bench/oraclecheck.py`.

## The defect

reccmp has no retail PDB, so it does not know how long an original function is.
`reccmp/compare/functions.py` falls back to

```python
orig_size = match.size(ImageId.ORIG)          # None: no retail symbols
if orig_size is None:
    orig_max = match.max_size(ImageId.ORIG)   # distance to the next known entity
    orig_size = min(orig_max, recomp_size) if orig_max else recomp_size
```

so it reads `orig[addr : addr + min(max_size, OUR size)]` and compares that
against our whole function. Two consequences, both load-bearing for this
project:

1. **A row can score 1.0 while our body is shorter than retail's.** Everything
   past our last byte is never compared. Row score is therefore *not* a proof
   of byte identity — only the MD5 gate is.
2. **A row that is longer than retail's is scored against a window that stops
   inside it**, so the trailing residue is invisible in the score too.

## The corrupted oracle (fixed)

`sweep-bench/wave2-oracles.json` recorded each target's `retail_hex` as
`retail_image[addr : addr + seed_len]` — that is, **cut to OUR body's length**,
not retail's. 92 of its 184 bodies were the wrong length or the wrong bytes.

That silently poisons the sweeps. `sweep2.py`'s hit test is
`len(body) != len(retail) -> skip`, so for any row whose true length differs
from the length baked into the oracle, **no carrier state could ever be a hit**:
the row was a permanent negative by construction, and its "closed" sweeps are
void. `fresh2/nearmiss.py` used a different rule (accept a shorter body when the
oracle's tail is all 0xCC) and was accidentally immune for the shorter cases.

`oracles-v2.json` rebuilds every retail body from the image: the row's address
window, cut at the first run of three `0xCC` bytes (LINK's inter-function
padding), then stripped of trailing padding. The three-`0xCC` cut matters —
`LegoROI::Intersect`'s window carries 15 pad bytes *plus a whole unannotated
28-byte function* after the real body.

**Validation: for the 26 oracled rows that are already exact, our body length
equals the recomputed retail length in 26/26 cases, byte-for-byte.**

## There is no hidden class of exact-but-short rows

The obvious fear this defect raises is that some of the 4,387 rows already at
1.0 are short of retail and nobody could tell. Measuring every one of them
(`bench/sizeledger.py --all`) says no: **exactly two disagree, and both are
artifacts of the measurement, not defects.** `__read_lk` is a CRT member, and
`LegoColor::Read` is the last function in `.text`, where the trailing-zero fill
swallows the final `00` of its `ret 4`. So the row score is trustworthy on the
length axis, and the whole `.text` shortfall lives in the open rows.

That shortfall is **+107 bytes across the 52 length-defect rows** (net; the
positive and negative deltas largely cancel). It is the reason the terminal
LEGO1 image currently lands one 512-byte file-alignment block below retail's
1,135,616. Closing those rows is therefore the same work as closing the image
size — goal 1 and goal 2 coincide on exactly this set.

Note the measurement's own edge cases, since the next reader will hit them: a
row's window can run past the end of its section (the next row may live in
`.rdata`), the tail of `.text` is zero-filled rather than `0xCC`-filled, and a
short trailing zero run is real code (a zero displacement, `mov reg, 0`, a
`rel32` with zero high bytes) — only a run of eight or more is alignment fill.

## What it says about the 102 open rows

52 rows carry a length defect; 50 are already the right size.

A length defect can only be fixed by changing what the source *says* — the
carrier/donor axis (declaration shapes, forward-declaration runs, extern runs,
pad grids, include order) moves register allocation and instruction selection,
not statement count. So:

* **length defect → text channel only.** The signed delta is the budget: `+n`
  means retail has `n` more bytes of code than we emit (a statement, a
  temporary, an inlined call we are calling out to), `-n` means we emit `n`
  bytes too many.
* **size clean → the carrier axis is live**, and near-miss `nd` is meaningful.

Do not spend a carrier sweep on a length-defect row until its text is right.

### The 52 length-defect rows (a carrier state cannot close these)

| address | m | ours | retail | delta | row |
|---|---|---|---|---|---|
| `0x1009f490` | 0.8896 | 1074 | 1121 | **+47** | LegoAnimScene::CalculateCameraTransform |
| `0x10058e70` | 0.9510 | 2616 | 2648 | **+32** | LegoOmni::Create |
| `0x100c1290` | 0.6082 | 586 | 566 | **-20** | MxStreamController::~MxStreamController |
| `0x1006bac0` | 0.9613 | 1746 | 1763 | **+17** | LegoAnimPresenter::ParseExtra |
| `0x1003cf20` | 0.8950 | 274 | 258 | **-16** | LegoCacheSoundManager::~LegoCacheSoundManager |
| `0x10046050` | 0.9552 | 693 | 703 | **+10** | LegoPathController::PlaceActor(class LegoPathActor *, class Lego |
| `0x1006dec0` | 0.8205 | 1113 | 1104 | **-9** | _Tree<char const *,pair<char const * const,LegoHideAnimStruct>,m |
| `0x100c8540` | 0.9059 | 236 | 245 | **+9** | MxDiskStreamController::FUN_100c8540 |
| `0x1002bff0` | 0.7092 | 1104 | 1096 | **-8** | _Tree<LegoPathActor *,LegoPathActor *,set<LegoPathActor *,LegoPa |
| `0x10055a60` | 0.9482 | 4120 | 4112 | **-8** | LegoNavController::Notify |
| `0x10068b20` | 0.7680 | 1104 | 1096 | **-8** | _Tree<char const *,pair<char const * const,char const *>,map<cha |
| `0x10069e90` | 0.7745 | 1104 | 1096 | **-8** | _Tree<char const *,pair<char const * const,LegoAnimStruct>,map<c |
| `0x1006fda0` | 0.7933 | 264 | 272 | **+8** | Infocenter::HandleKeyPress |
| `0x10082ca0` | 0.6848 | 1104 | 1096 | **-8** | _Tree<char *,pair<char * const,LegoCharacter *>,map<char *,LegoC |
| `0x100998e0` | 0.8571 | 995 | 987 | **-8** | LegoTextureContainer::GetCached |
| `0x10045c20` | 0.9442 | 331 | 338 | **+7** | LegoPathController::PlaceActor(class LegoPathActor *, char const |
| `0x1006b140` | 0.8149 | 941 | 948 | **+7** | LegoAnimPresenter::CopyTransform |
| `0x1004ebd0` | 0.8446 | 745 | 739 | **-6** | LegoTexturePresenter::Read |
| `0x100a4420` | 0.9504 | 520 | 514 | **-6** | OrientableROI::OrientableROI |
| `0x100b2a70` | 0.9048 | 1254 | 1260 | **+6** | MxVideoPresenter::PutFrame |
| `0x100574a0` | 0.7527 | 253 | 258 | **+5** | LegoPathBoundary::RemoveActor |
| `0x10061010` | 0.5481 | 726 | 731 | **+5** | LegoAnimationManager::FUN_10061010 |
| `0x10069b10` | 0.8842 | 622 | 617 | **-5** | LegoAnimPresenter::BuildROIMap |
| `0x10081840` | 0.9498 | 1163 | 1168 | **+5** | LegoCarRaceActor::CheckPresenterAndActorIntersections |
| `0x100293c0` | 0.8625 | 282 | 286 | **+4** | LegoControlManager::UpdateEnabledChild |
| `0x10041050` | 0.9610 | 1628 | 1632 | **+4** | Act3Brickster::Animate |
| `0x1006a7a0` | 0.7983 | 686 | 690 | **+4** | _Tree<char const *,pair<char const * const,LegoAnimStruct>,map<c |
| `0x1006c200` | 0.7828 | 678 | 682 | **+4** | _Tree<char const *,pair<char const * const,char const *>,map<cha |
| `0x100a66f0` | 0.8848 | 557 | 561 | **+4** | ViewManager::ManageVisibilityAndDetailRecursively |
| `0x100a83c0` | 0.9538 | 206 | 210 | **+4** | LegoROI::~LegoROI |
| `0x100af7e0` | 0.7273 | 1103 | 1107 | **+4** | _Tree<MxAtom *,MxAtom *,set<MxAtom *,MxAtomCompare,allocator<MxA |
| `0x1002de10` | 0.9426 | 746 | 743 | **-3** | LegoPathActor::SetTransformAndDestinationFromPoints |
| `0x10058c30` | 0.9827 | 568 | 571 | **+3** | LegoOmni::Destroy |
| `0x1006e720` | 0.8475 | 686 | 689 | **+3** | _Tree<char const *,pair<char const * const,LegoHideAnimStruct>,m |
| `0x100a3840` | 0.8176 | 667 | 664 | **-3** | TglImpl::MeshBuilderImpl::CreateMesh |
| `0x100a7130` | 0.9281 | 395 | 398 | **+3** | ViewLODListManager::~ViewLODListManager |
| `0x100a84a0` | 0.9277 | 2061 | 2058 | **-3** | LegoROI::Read |
| `0x10029d50` | 0.9212 | 1117 | 1119 | **+2** | _Tree<LegoCacheSoundEntry,LegoCacheSoundEntry,set<LegoCacheSound |
| `0x1004f9b0` | 0.8051 | 681 | 679 | **-2** | _Tree<char const *,pair<char const * const,LegoTextureInfo *>,ma |
| `0x100ac990` | 0.9246 | 597 | 599 | **+2** | MxNotificationManager::FlushPending |
| `0x1003d170` | 0.9552 | 282 | 281 | **-1** | LegoCacheSoundManager::FindSoundByKey |
| `0x10048310` | 0.8629 | 2337 | 2338 | **+1** | LegoPathController::FindPath |
| `0x1004c580` | 0.8227 | 413 | 412 | **-1** | MxTransitionManager::SetupCopyRect |
| `0x10054050` | 0.9476 | 2665 | 2666 | **+1** | Act3Ammo::Animate |
| `0x10059dc0` | 0.7913 | 1103 | 1102 | **-1** | _Tree<char const *,pair<char const * const,LegoTextureInfo *>,ma |
| `0x1006ed90` | 0.8966 | 380 | 381 | **+1** | Infocenter::Create |
| `0x10073a90` | 0.8893 | 930 | 929 | **-1** | Act3::Enable |
| `0x10080be0` | 0.9545 | 779 | 778 | **-1** | LegoCarRaceActor::CalculateSpline |
| `0x10083890` | 0.7075 | 652 | 653 | **+1** | _Tree<char *,pair<char * const,LegoCharacter *>,map<char *,LegoC |
| `0x100a7960` | 0.8780 | 1101 | 1100 | **-1** | _Tree<char const *,pair<char const * const,ViewLODList *>,map<ch |
| `0x100aa510` | 0.7268 | 1694 | 1693 | **-1** | LegoLOD::Read |
| `0x100ba2c0` | 0.9251 | 577 | 576 | **-1** | MxStillPresenter::Clone |

### The 50 size-clean rows (byte-level residue only - the carrier axis applies)

| address | m | len | row |
|---|---|---|---|
| `0x100a9410` | 0.9981 | 1553 | LegoROI::Intersect |
| `0x1007ca30` | 0.9953 | 2633 | LegoPartPresenter::Read |
| `0x100ba7f0` | 0.9953 | 660 | MxDisplaySurface::Create |
| `0x1009a8c0` | 0.9921 | 1494 | LegoWEGEdge::LinkEdgesAndFaces |
| `0x100035e0` | 0.9907 | 1148 | Helicopter::HandleControl |
| `0x1002e8d0` | 0.9892 | 561 | LegoPathActor::CheckPresenterAndActorIntersections |
| `0x100334b0` | 0.9891 | 843 | Act1State::Act1State |
| `0x100c6fa0` | 0.9882 | 234 | MxDSBuffer::FUN_100c6fa0 |
| `0x1002aba0` | 0.9791 | 1617 | LegoExtraActor::HitActor |
| `0x100170e0` | 0.9752 | 1391 | CarRace::HandlePathStruct |
| `0x100c3750` | 0.9739 | 1157 | MxRegion::AddRect |
| `0x10040360` | 0.9730 | 2496 | Act3Cop::FUN_10040360 |
| `0x10031820` | 0.9725 | 3580 | Isle::Enable |
| `0x100d0d80` | 0.9722 | 424 | ReadData |
| `0x10083500` | 0.9684 | 822 | LegoCharacterManager::GetActorROI |
| `0x1007b770` | 0.9636 | 1089 | LegoVideoManager::Tickle |
| `0x100b24f0` | 0.9612 | 346 | MxVideoPresenter::AlphaMask::AlphaMask(class MxBitmap const &) |
| `0x1004bd10` | 0.9608 | 438 | MxTransitionManager::DissolveTransition |
| `0x10038b10` | 0.9538 | 1232 | Pizza::HandleEndAction |
| `0x1004d330` | 0.9536 | 856 | TowTrack::HandlePathStruct |
| `0x100417c0` | 0.9496 | 2875 | Act3Brickster::FUN_100417c0 |
| `0x100bacc0` | 0.9426 | 1288 | MxDisplaySurface::VTable0x28 |
| `0x100720d0` | 0.9417 | 323 | Act3List::RemoveByObjectIdOrFirst |
| `0x10084030` | 0.9365 | 2294 | LegoCharacterManager::CreateActorROI |
| `0x100b26f0` | 0.9348 | 101 | MxVideoPresenter::AlphaMask::IsHit |
| `0x1002f770` | 0.9315 | 188 | LegoPathActor::UpdatePlane |
| `0x1002a720` | 0.9314 | 876 | LegoExtraActor::StepState |
| `0x10027910` | 0.9303 | 802 | ReadModelDbWorlds |
| `0x10072ad0` | 0.9302 | 348 | Act3::TriggerHitSound |
| `0x1003f540` | 0.9273 | 854 | WriteDefaultTexture |
| `0x10085500` | 0.9244 | 653 | _Tree<char *,pair<char * const,LegoCharacter *>,map<char *,LegoC |
| `0x10051ac0` | 0.9101 | 1115 | LegoAct2::SpawnBricks |
| `0x1001d890` | 0.9027 | 1106 | _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCompare,allocator<Mx |
| `0x10017af0` | 0.8873 | 264 | PizzeriaState::PizzeriaState |
| `0x10062e20` | 0.8856 | 1098 | LegoAnimationManager::FUN_10062e20 |
| `0x100b27b0` | 0.8791 | 247 | MxVideoPresenter::Destroy(unsigned char) |
| `0x100166a0` | 0.8675 | 645 | JetskiRace::HandlePathStruct |
| `0x100bb1d0` | 0.8611 | 811 | MxDisplaySurface::VTable0x30 |
| `0x10057fe0` | 0.8571 | 214 | LegoPathBoundary::AddPresenterIfInRange |
| `0x100796b0` | 0.8125 | 106 | LegoCarBuildAnimPresenter::FindNodeDataByName |
| `0x100a3b40` | 0.7971 | 197 | TglImpl::MeshBuilderImpl::Clone |
| `0x100a50a0` | 0.7900 | 2122 | OrientableROI::GetLocalTransform |
| `0x100586e0` | 0.7757 | 314 | LegoPathBoundary::RemovePresenter |
| `0x100a46b0` | 0.7747 | 2515 | OrientableROI::UpdateTransformationRelativeToParent |
| `0x100bd020` | 0.7470 | 415 | MxBitmap::BitBltTransparent |
| `0x10038380` | 0.7442 | 110 | Pizza::StopActions |
| `0x1002a1b0` | 0.7059 | 82 | _Tree<LegoCacheSoundEntry,LegoCacheSoundEntry,set<LegoCacheSound |
| `0x100a12a0` | 0.6667 | 83 | TglImpl::TextureImpl::SetImage |
| `0x100495b0` | 0.6532 | 648 | _Tree<LegoBEWithMidpoint *,LegoBEWithMidpoint *,multiset<LegoBEW |
| `0x10057180` | 0.6522 | 57 | _Tree<LegoAnimPresenter *,LegoAnimPresenter *,set<LegoAnimPresen |
