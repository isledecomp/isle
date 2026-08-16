# State of goal 1 — every open row, with its disposition

Generated in the main loop by joining the four screens plus the coverage
matrix against the live reccmp report. **LEGO1 4864/4934 — 70 open rows.**
ISLE is 172/172 and CONFIG is 111/111. Current terminal measurement keeps
ISLE and CONFIG byte-identical; LEGO1 is equal-sized with 595,723 differing
bytes (MD5 `1b828d1b68ed19650728d1d43a1048b2`). Byte distance is a layout-sensitive
diagnostic, not a monotonic goal-1 metric.

The diagnostic reccmp summary also counts known-but-unmatched runtime entries:
LEGO1 has three CRT initializers (`0x10092350`, `0x10092360`, `0x10096450`);
ISLE has `_write_multi_char`, `_write_string`, and three CRT initializers
(`0x40b370`, `0x40b380`, `0x40c400`). These are not missing game-source rows:
ISLE is already literally byte-identical while its diagnostic PDB leaves those
five unmatched. Completion therefore means every comparable function/vtable row
is raw 1.0, reccmp prints Accuracy 100.00%, and all three no-/debug images are
literal-byte, SHA-256, and MD5 identical. The terminal equality covers the
runtime entries without inventing annotations or changing a denominator.

This exists because the evidence is spread across `slot-reachability`,
`register-colour`, `scheduling-residue`, `cmpdir-census` and
`sweep-coverage-matrix`, and a single lane needs one place to look.

## The distribution

| rows | disposition | what it means |
|---:|---|---|
| 28 | **ALLOCATOR (no idiom)** | Frame already matches retail; registers re-decided in many places. Nine of ten such rows were read by hand and **none had a differing live range** — the apparent spill differences are the same instruction on both sides, moved. Carrier sweep is the only lever that has ever moved this class. |
| 12 | **AMBIGUOUS** | A screen refused to answer — bodies too divergent to trust an alignment, or slots contested after majority resolution. **Not a verdict of unreachability.** Cheapest unmined population: re-screen with better alignment. |
| 11 | **LENGTH-UNREACHABLE** | Never reaches retail's length in any state measured. Structural, not colour. |
| 9 | **SCHEDULE/ENCODING** | Frame **and** registers already match retail. Scheduling screen says intra-block reordering or a class owned elsewhere; **zero rows in the whole set are cross-block**, and the one that was got tested and refuted. |
| 5 | **ROUTED** | Named, understood, and assigned — see the notes column. |
| 4 | **PERMUTATION (measured families exhausted)** | Pure register bijection: the same live ranges received different physical registers. No source correlate was found in the measured families; this is not proof that no authentic compiler-state route exists. |
| 1 | **OTHER** | Unclassified by the join; inspect individually. |

## What is actually fundable

1. **Authenticated target-closure extraction** — `0x1003cf20` and
   `0x1009f490` are landed. The latter uses a distinct fail-closed class rather
   than weakening B4: identical pinned target source; exact seed/donor section,
   function and COMDAT-primary subset proofs; a complete 13-record semantic
   relocation oracle; retail-exact target bytes; and conservation of the seed's
   complete function set and every non-target section. This is the pattern for
   future visibility-driven authentic donors.
   `0x1001d890` is also landed through the narrower Class-C path: a freshly
   source-generated copy of the same multiply-defined COMDAT installs 36
   retail-exact non-relocation code bytes while retaining the seed object and
   relocation topology. A frozen A/B/A2 link proved +1/-0 before admission.
2. **Carrier sweeps on rows with genuinely untried families** — rank the
   families **from the objects**, never from the matrix's `L` column; a
   missing result file proves nothing about what was compiled.
3. ~~**The AMBIGUOUS rows** — sharpen the alignment.~~ **RETRACTED, measured in
   the main loop 2026-08-16.** Of the ten still-open rows refused by *both* the slot and
   register screens, **10 of 10 have a different length from retail** and zero
   are same-length:

   | row | ours | retail | delta |
   |---|---:|---:|---:|
   | `0x100293c0` UpdateEnabledChild | 282 | 286 | −4 |
   | `0x1002bff0` `_Tree<LegoPathActor*>` | 1104 | 1096 | +8 |
   | `0x1003d170` FindSoundByKey | 282 | 281 | +1 |
   | `0x1004ebd0` LegoTexturePresenter::Read | 745 | 739 | +6 |
   | `0x10058c30` LegoOmni::Destroy | 568 | 571 | −3 |
   | `0x10061010` FUN_10061010 | 717 | 731 | −14 |
   | `0x1006ed90` Infocenter::Create | 380 | 381 | −1 |
   | `0x10081840` CheckPresenterAndActorIntersections | 1163 | 1168 | −5 |
   | `0x100a84a0` LegoROI::Read | 2061 | 2058 | +3 |
   | `0x100ba2c0` MxStillPresenter::Clone | 577 | 576 | +1 |

   The screens refuse with "only 68–80% of instructions aligned" **because the
   bodies genuinely differ in structure**, not because the aligner is weak. A
   sharper aligner cannot manufacture information that isn't in the pair. These
   rows belong with the length-unreachable population and are already routed or
   sealed individually. **Do not fund an alignment-sharpening pass.**

   (The register screen does add real information where the slot screen alone
   refuses — 9 such rows, 5 of them same-length. That part stands.)

The measured broad families are exhausted: source archaeology without a
specific byte-level hypothesis has not paid, `cmpdir` alone is not a general
channel, and the retained corpus contains no further semantically valid exact
body. Novel, bounded compiler-state and authentic visibility mechanisms remain
eligible when they carry a fail-closed proof and a concrete target.

## Per-row table

| disposition | score | address | name | slot | register | schedule | cmpdir | note |
|---|---:|---|---|---|---|---|---|---|
| ALLOCATOR (no idiom) | 0.9739 | `0x100c3750` | MxRegion::AddRect | SLOT-CLEAN | REGIONAL | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.9636 | `0x1007b770` | LegoVideoManager::Tickle | SLOT-CLEAN | SCATTERED | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.9612 | `0x100b24f0` | MxVideoPresenter::AlphaMask::AlphaMask(cla | SLOT-CLEAN | REGIONAL | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.9608 | `0x1004bd10` | MxTransitionManager::DissolveTransition | SLOT-CLEAN | REGIONAL | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.9536 | `0x1004d330` | TowTrack::HandlePathStruct | SLOT-CLEAN | REGIONAL | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.9417 | `0x100720d0` | Act3List::RemoveByObjectIdOrFirst | SLOT-CLEAN | REGIONAL | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.9365 | `0x10084030` | LegoCharacterManager::CreateActorROI | SLOT-CLEAN | SCATTERED | DIFFERENT | NONE | masked object nd 0 is not a row win: gated score .9969, wrong relocation targets/address; reverted |
| ALLOCATOR (no idiom) | 0.9348 | `0x100b26f0` | MxVideoPresenter::AlphaMask::IsHit | SLOT-CLEAN | REGIONAL | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.9315 | `0x1002f770` | LegoPathActor::UpdatePlane | SLOT-CLEAN | REGIONAL | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.9302 | `0x10072ad0` | Act3::TriggerHitSound | SLOT-CLEAN | REGIONAL | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.9273 | `0x1003f540` | WriteDefaultTexture | SLOT-CLEAN | SCATTERED | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.9244 | `0x10085500` | _Tree<char *,pair<char * const,LegoCharact | SLOT-CLEAN | REGIONAL | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.9212 | `0x10029d50` | _Tree<LegoCacheSoundEntry,LegoCacheSoundEn | SLOT-CLEAN | REGIONAL | DIFFERENT | MIXED |  |
| ALLOCATOR (no idiom) | 0.9101 | `0x10051ac0` | LegoAct2::SpawnBricks | SLOT-CLEAN | SCATTERED | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.9048 | `0x100b2a70` | MxVideoPresenter::PutFrame | SLOT-CLEAN | SCATTERED | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.8893 | `0x10073a90` | Act3::Enable | SLOT-CLEAN | REGIONAL | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.8873 | `0x10017af0` | PizzeriaState::PizzeriaState | SLOT-CLEAN | REGIONAL | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.8842 | `0x10069b10` | LegoAnimPresenter::BuildROIMap | SLOT-CLEAN | SCATTERED | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.8791 | `0x100b27b0` | MxVideoPresenter::Destroy(unsigned char) | SLOT-CLEAN | REGIONAL | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.8780 | `0x100a7960` | _Tree<char const *,pair<char const * const | SLOT-CLEAN | SCATTERED | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.8675 | `0x100166a0` | JetskiRace::HandlePathStruct | SLOT-CLEAN | REGIONAL | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.8475 | `0x1006e720` | _Tree<char const *,pair<char const * const | SLOT-CLEAN | SCATTERED | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.8051 | `0x1004f9b0` | _Tree<char const *,pair<char const * const | SLOT-CLEAN | SCATTERED | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.7983 | `0x1006a7a0` | _Tree<char const *,pair<char const * const | SLOT-CLEAN | SCATTERED | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.7828 | `0x1006c200` | _Tree<char const *,pair<char const * const | SLOT-CLEAN | SCATTERED | DIFFERENT | NONE |  |
| ALLOCATOR (no idiom) | 0.7757 | `0x100586e0` | LegoPathBoundary::RemovePresenter | SLOT-CLEAN | SCATTERED | AMBIGUOUS | NONE |  |
| ALLOCATOR (no idiom) | 0.7470 | `0x100bd020` | MxBitmap::BitBltTransparent | SLOT-CLEAN | SCATTERED | AMBIGUOUS | NONE |  |
| ALLOCATOR (no idiom) | 0.7075 | `0x10083890` | _Tree<char *,pair<char * const,LegoCharact | SLOT-CLEAN | SCATTERED | AMBIGUOUS | NONE |  |
| AMBIGUOUS | 0.9907 | `0x100035e0` | Helicopter::HandleControl | AMBIGUOUS | IDENTITY | INTRA-BLOCK | NONE |  |
| AMBIGUOUS | 0.9552 | `0x1003d170` | LegoCacheSoundManager::FindSoundByKey | AMBIGUOUS | AMBIGUOUS | DIFFERENT | NONE |  |
| AMBIGUOUS | 0.9498 | `0x10081840` | LegoCarRaceActor::CheckPresenterAndActorIn | AMBIGUOUS | AMBIGUOUS | DIFFERENT | NONE |  |
| AMBIGUOUS | 0.9496 | `0x100417c0` | Act3Brickster::FUN_100417c0 | AMBIGUOUS | SCATTERED | DIFFERENT | MIXED |  |
| AMBIGUOUS | 0.9476 | `0x10054050` | Act3Ammo::Animate | AMBIGUOUS | SCATTERED | DIFFERENT | NONE |  |
| AMBIGUOUS | 0.9277 | `0x100a84a0` | LegoROI::Read | AMBIGUOUS | AMBIGUOUS | DIFFERENT | MIXED |  |
| AMBIGUOUS | 0.8856 | `0x10062e20` | LegoAnimationManager::FUN_10062e20 | AMBIGUOUS | REGIONAL | DIFFERENT | NONE |  |
| AMBIGUOUS | 0.8698 | `0x100998e0` | LegoTextureContainer::GetCached | AMBIGUOUS | IDENTITY | DIFFERENT | MIXED |  |
| AMBIGUOUS | 0.8696 | `0x100a46b0` | OrientableROI::UpdateTransformationRelativ | AMBIGUOUS | REGIONAL | DIFFERENT | NONE |  |
| AMBIGUOUS | 0.8629 | `0x10048310` | LegoPathController::FindPath | AMBIGUOUS | SCATTERED | DIFFERENT | MIXED |  |
| AMBIGUOUS | 0.8446 | `0x1004ebd0` | LegoTexturePresenter::Read | AMBIGUOUS | AMBIGUOUS | DIFFERENT | MIXED |  |
| AMBIGUOUS | 0.7092 | `0x1002bff0` | _Tree<LegoPathActor *,LegoPathActor *,set< | AMBIGUOUS | AMBIGUOUS | AMBIGUOUS | NONE |  |
| LENGTH-UNREACHABLE | 0.9827 | `0x10058c30` | LegoOmni::Destroy | AMBIGUOUS | AMBIGUOUS | DIFFERENT | LENGTH |  |
| LENGTH-UNREACHABLE | 0.9552 | `0x10046050` | LegoPathController::PlaceActor(class LegoP | AMBIGUOUS | IDENTITY | DIFFERENT | LENGTH |  |
| LENGTH-UNREACHABLE | 0.9545 | `0x10080be0` | LegoCarRaceActor::CalculateSpline | SLOT-CLEAN | REGIONAL | DIFFERENT | LENGTH |  |
| LENGTH-UNREACHABLE | 0.9426 | `0x1002de10` | LegoPathActor::SetTransformAndDestinationF | SLOT-CLEAN | IDENTITY | DIFFERENT | LENGTH |  |
| LENGTH-UNREACHABLE | 0.9251 | `0x100ba2c0` | MxStillPresenter::Clone | AMBIGUOUS | AMBIGUOUS | DIFFERENT | LENGTH |  |
| LENGTH-UNREACHABLE | 0.8966 | `0x1006ed90` | Infocenter::Create | AMBIGUOUS | AMBIGUOUS | DIFFERENT | LENGTH |  |
| LENGTH-UNREACHABLE | 0.8495 | `0x1004c580` | MxTransitionManager::SetupCopyRect | SLOT-CLEAN | SCATTERED | DIFFERENT | LENGTH |  |
| LENGTH-UNREACHABLE | 0.8176 | `0x100a3840` | TglImpl::MeshBuilderImpl::CreateMesh | SLOT-CLEAN | SCATTERED | DIFFERENT | LENGTH |  |
| LENGTH-UNREACHABLE | 0.8149 | `0x1006b140` | LegoAnimPresenter::CopyTransform | REACHABLE | SCATTERED | DIFFERENT | LENGTH |  |
| LENGTH-UNREACHABLE | 0.7933 | `0x1006fda0` | Infocenter::HandleKeyPress | SLOT-CLEAN | REGIONAL | DIFFERENT | LENGTH |  |
| LENGTH-UNREACHABLE | 0.7268 | `0x100aa510` | LegoLOD::Read | UNREACHABLE | SCATTERED | AMBIGUOUS | LENGTH |  |
| OTHER | 0.7442 | `0x10038380` | Pizza::StopActions | NO-SLOTS | REGIONAL | AMBIGUOUS | NONE |  |
| ROUTED | 0.9504 | `0x100a4420` | OrientableROI::OrientableROI | SLOT-CLEAN | IDENTITY | DIFFERENT | LENGTH | inline bit PLUS one EH-store schedule; B1 refuses (not retail-exact) |
| ROUTED | 0.8848 | `0x100a66f0` | ViewManager::ManageVisibilityAndDetailRecu | SLOT-CLEAN | REGIONAL | DIFFERENT | PURE | PURE cmpdir, sealed: ~8,500 cells, floor never leaves nd=1 |
| ROUTED | 0.8611 | `0x100bb1d0` | MxDisplaySurface::VTable0x30 | UNREACHABLE | SCATTERED | AMBIGUOUS | PURE | PURE cmpdir, sealed: nd=4 in every family (6,439 obj + 2,058 cells) |
| ROUTED | 0.7913 | `0x10059dc0` | _Tree<char const *,pair<char const * const | SLOT-CLEAN | SCATTERED | DIFFERENT | PURE | PURE cmpdir, sealed: nd=1 floor, only fwdE/extern reach it |
| ROUTED | 0.5411 | `0x10061010` | LegoAnimationManager::FUN_10061010 | AMBIGUOUS | AMBIGUOUS | AMBIGUOUS | LENGTH | retail inlines the MxListEntry ctor; an 8-state C1 planner-cost panel flips that bit but every accepted state is the same wrong 720 B (retail 731), so frame/allocation state remains |
| SCHEDULE/ENCODING | 0.9953 | `0x1007ca30` | LegoPartPresenter::Read | SLOT-CLEAN | IDENTITY | DIFFERENT | NONE |  |
| SCHEDULE/ENCODING | 0.9953 | `0x100ba7f0` | MxDisplaySurface::Create | SLOT-CLEAN | IDENTITY | INTRA-BLOCK | NONE |  |
| SCHEDULE/ENCODING | 0.9921 | `0x1009a8c0` | LegoWEGEdge::LinkEdgesAndFaces | SLOT-CLEAN | IDENTITY | DIFFERENT | NONE |  |
| SCHEDULE/ENCODING | 0.9891 | `0x100334b0` | Act1State::Act1State | SLOT-CLEAN | IDENTITY | INTRA-BLOCK | NONE |  |
| SCHEDULE/ENCODING | 0.9882 | `0x100c6fa0` | MxDSBuffer::FUN_100c6fa0 | SLOT-CLEAN | IDENTITY | INTRA-BLOCK | NONE |  |
| SCHEDULE/ENCODING | 0.9818 | `0x10055a60` | LegoNavController::Notify | SLOT-CLEAN | IDENTITY | DIFFERENT | NONE |  |
| SCHEDULE/ENCODING | 0.9752 | `0x100170e0` | CarRace::HandlePathStruct | SLOT-CLEAN | IDENTITY | DIFFERENT | NONE |  |
| SCHEDULE/ENCODING | 0.9730 | `0x10040360` | Act3Cop::FUN_10040360 | SLOT-CLEAN | IDENTITY | DIFFERENT | NONE |  |
| SCHEDULE/ENCODING | 0.9725 | `0x10031820` | Isle::Enable | SLOT-CLEAN | IDENTITY | DIFFERENT | NONE |  |
| PERMUTATION (measured families exhausted) | 0.7971 | `0x100a3b40` | TglImpl::MeshBuilderImpl::Clone | SLOT-CLEAN | PERMUTATION | AMBIGUOUS | NONE |  |
| PERMUTATION (measured families exhausted) | 0.7059 | `0x1002a1b0` | _Tree<LegoCacheSoundEntry,LegoCacheSoundEn | SLOT-CLEAN | PERMUTATION | AMBIGUOUS | NONE |  |
| PERMUTATION (measured families exhausted) | 0.6667 | `0x100a12a0` | TglImpl::TextureImpl::SetImage | SLOT-CLEAN | PERMUTATION | AMBIGUOUS | NONE |  |
| PERMUTATION (measured families exhausted) | 0.6522 | `0x10057180` | _Tree<LegoAnimPresenter *,LegoAnimPresente | SLOT-CLEAN | PERMUTATION | AMBIGUOUS | NONE |  |
