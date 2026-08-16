# Residue-run classification — which rows are scheduling rows

Measured 2026-08-16 at LEGO1 4850/4934, over the size-clean open rows.
Regenerate with `bench/runs.py`; machine-readable copy in `bench/runs.json`.
No compiles — this reads the objects the last build already produced.

## Why this exists

Lane NM found that `LegoPathController::FindPath`'s residue is not register
colouring at all. Of its 72 differing offsets, 62 are fixed by no state ever
compiled, and they occur in **contiguous runs where both sides carry the same
instructions in a different order and re-converge a few bytes later**:

```
+1674 retail: lea ecx,[ebp-0x6c] ; mov esi,[ebp-0x144] ; mov [ebp-0x6c],3f000000h
      ours:   mov [ebp-0x6c],3f000000h ; lea ecx,[ebp-0x6c] ; mov esi,[ebp-0x144]
              — same three instructions, permuted, re-converging exactly at +1690
```

That is one statement-level hoist, not 66 bytes of anything. Which gives the
rule this file exists to apply:

> **`nd` is the wrong ruler for a scheduling residue.** A three-instruction
> permutation reads as ~16 wrong bytes; a whole-body one reads as hundreds.
> Both are one source edit. A row whose residue is contiguous runs that
> re-converge should be **read, not swept** — and MSVC 4.2's local scheduling
> follows statement order, so the source is the channel.

`FindPath` went 1741 → 491 → 159 → 87 → 66 on carrier state alone before this
was noticed. Every one of those cells was spent on the wrong channel.

## Method

For each open row, walk the aligned body, collect maximal divergent regions
that re-converge on a shared instruction boundary, and compare the two sides'
instruction *multisets* over each region:

| verdict | meaning | what to do |
|---|---|---|
| `PERMUTED` | every divergent region is the same instructions reordered | **read it** — statement order, not compile state |
| `MIXED` | some regions permuted, some not | read the permuted regions first; they are the structural part |
| `COLOUR` | every region is a single instruction differing only in a register | sweep it — this is what the carrier axis moves |
| `OTHER` | real instruction differences remain | text, inlining, or a genuine defect |

Caveat: the classifier sees only the *current* build's body. A row whose best
carrier state has a different residue should be re-run against that state's
object, not the default one — the same trap that put 27 rows in the wrong
bucket of the frame census.

## Results

| verdict | address | m | residue bytes | regions | region kinds | row |
|---|---|---|---|---|---|---|
| **PERMUTED** | `0x100ba7f0` | 0.9953 | 9 | 4 | colour=3 permuted=1 | MxDisplaySurface::Create |
| **PERMUTED** | `0x100c6fa0` | 0.9882 | 4 | 1 | permuted=1 | MxDSBuffer::FUN_100c6fa0 |
| **MIXED** | `0x100035e0` | 0.9907 | 19 | 40 | colour=35 other=4 permuted=1 | Helicopter::HandleControl |
| **MIXED** | `0x100417c0` | 0.9496 | 132 | 80 | colour=63 other=16 permuted=1 | Act3Brickster::FUN_100417c0 |
| **MIXED** | `0x10085500` | 0.9244 | 29 | 26 | colour=22 other=3 permuted=1 | _Tree<char *,pair<char * const,LegoCharacter * |
| **MIXED** | `0x10062e20` | 0.8856 | 72 | 44 | colour=29 other=14 permuted=1 | LegoAnimationManager::FUN_10062e20 |
| **MIXED** | `0x100a46b0` | 0.8696 | 99 | 38 | colour=6 other=28 permuted=4 | OrientableROI::UpdateTransformationRelativeToP |
| **OTHER** | `0x1007ca30` | 0.9953 | 4 | 104 | colour=100 other=4 | LegoPartPresenter::Read |
| **OTHER** | `0x1009a8c0` | 0.9921 | 4 | 29 | colour=25 other=4 | LegoWEGEdge::LinkEdgesAndFaces |
| **OTHER** | `0x100334b0` | 0.9891 | 24 | 48 | colour=42 other=6 | Act1State::Act1State |
| **OTHER** | `0x100170e0` | 0.9752 | 111 | 47 | colour=41 other=6 | CarRace::HandlePathStruct |
| **OTHER** | `0x100c3750` | 0.9739 | 10 | 40 | colour=36 other=4 | MxRegion::AddRect |
| **OTHER** | `0x10040360` | 0.9730 | 68 | 73 | colour=59 other=14 | Act3Cop::FUN_10040360 |
| **OTHER** | `0x10031820` | 0.9725 | 214 | 186 | colour=151 other=35 | Isle::Enable |
| **OTHER** | `0x100d0d80` | 0.9722 | 18 | 14 | colour=12 other=2 | ReadData |
| **OTHER** | `0x10083500` | 0.9684 | 9 | 28 | colour=25 other=3 | LegoCharacterManager::GetActorROI |
| **OTHER** | `0x1007b770` | 0.9636 | 19 | 28 | colour=24 other=4 | LegoVideoManager::Tickle |
| **OTHER** | `0x100b24f0` | 0.9612 | 5 | 4 | colour=3 other=1 | MxVideoPresenter::AlphaMask::AlphaMask(class M |
| **OTHER** | `0x1004bd10` | 0.9608 | 6 | 11 | colour=10 other=1 | MxTransitionManager::DissolveTransition |
| **OTHER** | `0x10038b10` | 0.9538 | 14 | 56 | colour=46 other=10 | Pizza::HandleEndAction |
| **OTHER** | `0x1004d330` | 0.9536 | 11 | 33 | colour=27 other=6 | TowTrack::HandlePathStruct |
| **OTHER** | `0x100720d0` | 0.9417 | 7 | 8 | colour=6 other=2 | Act3List::RemoveByObjectIdOrFirst |
| **OTHER** | `0x10084030` | 0.9365 | 80 | 86 | colour=70 other=16 | LegoCharacterManager::CreateActorROI |
| **OTHER** | `0x100b26f0` | 0.9348 | 8 | 1 | other=1 | MxVideoPresenter::AlphaMask::IsHit |
| **OTHER** | `0x1002f770` | 0.9315 | 5 | 6 | colour=4 other=2 | LegoPathActor::UpdatePlane |
| **OTHER** | `0x10072ad0` | 0.9302 | 11 | 11 | colour=9 other=2 | Act3::TriggerHitSound |
| **OTHER** | `0x1003f540` | 0.9273 | 33 | 25 | colour=18 other=7 | WriteDefaultTexture |
| **OTHER** | `0x10051ac0` | 0.9101 | 58 | 29 | colour=24 other=5 | LegoAct2::SpawnBricks |
| **OTHER** | `0x1001d890` | 0.9027 | 36 | 29 | colour=20 other=9 | _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCo |
| **OTHER** | `0x10017af0` | 0.8873 | 18 | 12 | colour=7 other=5 | PizzeriaState::PizzeriaState |
| **OTHER** | `0x100b27b0` | 0.8791 | 25 | 8 | colour=6 other=2 | MxVideoPresenter::Destroy(unsigned char) |
| **OTHER** | `0x100166a0` | 0.8675 | 22 | 36 | colour=25 other=11 | JetskiRace::HandlePathStruct |
| **OTHER** | `0x100bb1d0` | 0.8611 | 68 | 15 | colour=4 other=11 | MxDisplaySurface::VTable0x30 |
| **OTHER** | `0x100796b0` | 0.8125 | 16 | 7 | colour=4 other=3 | LegoCarBuildAnimPresenter::FindNodeDataByName |
| **OTHER** | `0x100a3b40` | 0.7971 | 14 | 16 | colour=10 other=6 | TglImpl::MeshBuilderImpl::Clone |
| **OTHER** | `0x100586e0` | 0.7757 | 41 | 9 | colour=4 other=5 | LegoPathBoundary::RemovePresenter |
| **OTHER** | `0x100bd020` | 0.7470 | 89 | 20 | colour=11 other=9 | MxBitmap::BitBltTransparent |
| **OTHER** | `0x10038380` | 0.7442 | 15 | 9 | colour=5 other=4 | Pizza::StopActions |
| **OTHER** | `0x1002a1b0` | 0.7059 | 10 | 8 | colour=4 other=4 | _Tree<LegoCacheSoundEntry,LegoCacheSoundEntry, |
| **OTHER** | `0x100a12a0` | 0.6667 | 25 | 7 | colour=2 other=5 | TglImpl::TextureImpl::SetImage |
| **OTHER** | `0x100495b0` | 0.6532 | 337 | 16 | colour=5 other=11 | _Tree<LegoBEWithMidpoint *,LegoBEWithMidpoint  |
| **OTHER** | `0x10057180` | 0.6522 | 10 | 4 | colour=2 other=2 | _Tree<LegoAnimPresenter *,LegoAnimPresenter *, |

Counts: **OTHER 35, MIXED 5, PERMUTED 2**.

The two clean `PERMUTED` rows are both main-loop rows that had resisted the
carrier axis completely — `MxDSBuffer::FUN_100c6fa0` at nd=4 across 827 states
and `MxDisplaySurface::Create` at nd=9. Both were being swept when they should
have been read.
