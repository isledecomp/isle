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

## Following the classifier on the two PERMUTED rows — both negative so far

Recorded with extent, because "read it, don't sweep it" is a claim about the
*channel*, not a promise that the statement is easy to find.

**`MxDSBuffer::FUN_100c6fa0`** (nd=4, one permuted region). Retail reads
`current` into `eax` *before* the comparison reads it again; we compare first.
Both reads are real ordered accesses — `current` is `volatile` — so the source
order should decide it. Measured, all in the seed lane:

| variant | body | nd |
|---|---|---|
| base | 234 | 4 |
| remove `volatile` | 162 | 225 — `volatile` is load-bearing and correct |
| `p_data == current` | 234 | 4 — inert |
| invert the `if` | 234 | 4 — inert |
| fold `+= (size & 1) + size + 8` | 232 | 59 — the two separate `+=` are correct |
| `MxU8* chunk` at function scope, assigned in the case | 238 | 13 |
| `MxU32 size` at function scope, assigned before the `if` | 238 | 18 |

A declaration at case scope needs a block (`C2361`), and hoisting either name to
function scope costs 4 bytes — so the extra ordered read cannot be bought with a
named local. Consistent with the standing law that naming a value does not
create a lifetime; here it does not create a *read* either, it creates a slot.

**`MxDisplaySurface::Create`** (nd=9, one permuted region among three colour
regions). Retail emits `inc eax` before the `ddsd.ddsCaps.dwCaps = 0x6040`
store; we emit it after. The store carries no line annotation on either side —
the scheduler has hoisted it out of its own statement into the width
computation, and retail hoisted it one instruction less far. All four
statement orderings of the `dwFlags` / `dwWidth` / `dwHeight` / `dwCaps` block
are **worse** (nd 15, 18, 22, 23 against the baseline 9), so the current source
order is already the closest one. The position *within* a hoist is not
source-addressable at this granularity.

So for both rows the channel verdict stands and the lever is still missing.
What this rules out is spending more carrier cells on them.

## `UpdateTransformationRelativeToParent` — the vec.h-debt row, bounded

The near-miss lane found this row's residue is six permuted spans of the same
shape — same FP products, summed starting from a different term — and pointed
at it as the first direct evidence of what the `3rdparty/vec/vec.h` vendor-edit
debt actually is. Everything below is measured against the composed carrier
state (`declaration_shape(5,27)`, body 2515 = retail's length), because the
bare seed is 2473 and its distances are not comparable.

Baseline **nd=99**. Every source-level lever tested is worse:

| lever | cells | best nd |
|---|---|---|
| local declaration order (all 6 array orders × 4 positions for `int i, j`, plus 6 with `parent2world` hoisted into the block) | 29 | 107 |
| `MXM4` operand order swapped | 1 | 156 |
| `MXM4d` — the `double`-typed variant, consistent with the `INVERTMAT4d` already used | 1 | 115 |
| `MXM4d` + operands swapped | 1 | 172 |
| copy-loop statement order (`local2parent` assigned first) | 1 | 131 |
| copy loop with `j` outer | 1 | 2190 |
| `unsigned int i, j` | 1 | 2281 |

So the current source is the closest form on every axis available, and the
addend order lives inside `_DOTcol4` — vendor code, which the mandates forbid
editing and which the discharged entropy edit used to reach.

That leaves exactly one honest reading: **if retail's term order is different,
1997's source did not go through `MXM4`.** Writing the product explicitly in
first-party source would reach it, but only as a hypothesis about what the
original wrote, and it should not be attempted without an oracle for the
original's shape. The row remains a *layout* restoration in the manifest, which
its unit already says.
