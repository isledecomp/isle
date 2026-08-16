# Sweep-coverage matrix — every open LEGO1 row

**81 open rows · 46 TUs · 141,114 measured carrier cells · 114 result files.**

## Where this comes from, and why that matters

Source precedence, in order:

1. **the sweeps' own `results.json`** — authoritative
2. this lane's hand-authored wave 4–12 records
3. the other lanes' `docs/*ledger*.md`

Where (1) disagrees with (2) or (3), **the result file wins** and the
disagreement is recorded below. This ordering is not a stylistic choice:
a matrix built from ledgers alone has now cost this project three rows on
three separate occasions, for two systematic reasons —

* **ledgers do not reflect their own sweep's result files.** A sweep still
  running when a wave closed never got read afterwards.
* **sweep drivers scored only their own stem's target list.** A hit can sit
  in an object that no scorer ever looked at.

Filenames are not used as evidence anywhere. A scratchpad directory proves
a compile happened — not which row it targeted, on which text, or whether
anyone scored the result.

### The re-open rule

`0x10068b20` was recorded "sealed carrier-closed", then oracle-voided, then
floored at nd=1 — and **had an unharvested nd=0 the whole time**. Treat
"sealed" in any ledger as *a claim with a date and a text-state*, never as
a fact. Every seal in this matrix carries its source line so it can be
re-opened cheaply.

## 1. Unharvested floors — nd=0 donors already in the corpus

Re-scanning the result files reproduces, independently, two of the three
nd=0 donors the coordinator's object re-scan found:

| row | nd | state | result file |
|---|---:|---|---|
| `0x10068b20` | **0** | `fCS-211` | `sw-all2-legoanimpresenter_LONG` |
| `0x10069e90` | **0** | `stack_6_60_S-422` | `sw-all2-legoanimpresenter_L660` |
| `0x100495b0` | **0** | — | *not in any `results.json`* — the hit is in FIN's goal-2 objects, whose stem never listed this row |

The third is the sharper lesson: **no result file covers it at all**, so no
amount of result-file mining would have found it. Only re-scoring the
objects themselves does. `legopathcontroller.cpp` is reassigned to another
lane for that landing; it stays here as data only.

### Every row's best measured state

The floor any result file holds for each row, with the exact state to go
back to. This column did not exist before this wave.

| row | nd | state | result file |
|---|---:|---|---|
| `0x10068b20` \_Tree&lt;char const \*,pair&lt;char const | 0 | `fCS-211` | `sw-all2-legoanimpresenter_LONG` |
| `0x10069e90` \_Tree&lt;char const \*,pair&lt;char const | 0 | `stack_6_60_S-422` | `sw-all2-legoanimpresenter_L660` |
| `0x100a66f0` ViewManager::ManageVisibilityAndDe | 1 | `fAP-34` | `sw-all-viewmanagertri3` |
| `0x10069b10` LegoAnimPresenter::BuildROIMap | 2 | `stack_7_15_S-1` | `sw-all2-legoanimpresenter_st715` |
| `0x100574a0` LegoPathBoundary::RemoveActor | 2 | `pad-12-11` | `sw-all2-legopathboundary_v3` |
| `0x100586e0` LegoPathBoundary::RemovePresenter | 3 | `pad-7-9` | `sw-all2-legopathboundary_v3` |
| `0x1007ca30` LegoPartPresenter::Read | 4 | `shape-1-2` | `sw-all-legopartpresenterxps04` |
| `0x1006e720` \_Tree&lt;char const \*,pair&lt;char const | 4 | `shape-6-49` | `sw-all2-legoanimpresenter_pE51sf` |
| `0x1006a7a0` \_Tree&lt;char const \*,pair&lt;char const | 4 | `extern-32-5` | `sw-all2-legoanimpresenter_R40` |
| `0x1006c200` \_Tree&lt;char const \*,pair&lt;char const | 4 | `shape-3-19` | `sw-all2-legoanimpresenter_pE51sf` |
| `0x100bb1d0` MxDisplaySurface::VTable0x30 | 4 | `extern-13-1` | `sw-all2-mxdisplaysurfacerect` |
| `0x100c6fa0` MxDSBuffer::FUN\_100c6fa0 | 4 | `extern-9-0` | `sw-all-mxdsbufferlong` |
| `0x100b24f0` MxVideoPresenter::AlphaMask::Alpha | 5 | `extern-0-4` | `sw-all2-mxvideopresenterxl` |
| `0x100b26f0` MxVideoPresenter::AlphaMask::IsHit | 6 | `extern-100-0` | `sw-all2-mxvideopresenterxl` |
| `0x100c3750` MxRegion::AddRect | 6 | `shape-1-8` | `sw-all2-mxregionrgstack` |
| `0x1004bd10` MxTransitionManager::DissolveTrans | 6 | `extern-0-1` | `sw-all-mxtransitionmanagerrect` |
| `0x10057180` \_Tree&lt;LegoAnimPresenter \*,LegoAnim | 7 | `pad-5-5` | `sw-all2-legopathboundary_v3` |
| `0x100ba7f0` MxDisplaySurface::Create | 9 | `extern-0-1` | `sw-all2-mxdisplaysurfacerect` |
| `0x10031820` Isle::Enable | 11 | `extern-1-8` | `sw-all2-islerect` |
| `0x10038380` Pizza::StopActions | 11 | `shape-1-1` | `sw-all-pizzashape` |
| `0x1003f540` WriteDefaultTexture | 12 | `extern-3-0` | `sw-all-legoutilsrect` |
| `0x100a3b40` TglImpl::MeshBuilderImpl::Clone | 14 | `shape-1-1` | `sw-all-tglrl40shape` |
| `0x100a12a0` TglImpl::TextureImpl::SetImage | 16 | `shape-1-5` | `sw-all-tglrl40shape` |
| `0x100d0d80` ReadData | 18 | `base-0` | `sw-all-mxramstreamproviderrect` |
| `0x10017af0` PizzeriaState::PizzeriaState | 18 | `base-0` | `sw-all-pizzeriarect` |
| `0x1006dec0` \_Tree&lt;char const \*,pair&lt;char const | 18 | `stack_6_60_S-382` | `sw-all2-legoanimpresenter_L660` |
| `0x100035e0` Helicopter::HandleControl | 19 | `base-0` | `sw-all-helicopterrect` |
| `0x1007b770` LegoVideoManager::Tickle | 19 | `extern-0-1` | `sw-all-legovideomanagerrect` |
| `0x100334b0` Act1State::Act1State | 24 | `triM_0_0-0` | `sw-all2-isletri0` |
| `0x100b27b0` MxVideoPresenter::Destroy(unsigned | 25 | `extern-0-4` | `sw-all2-mxvideopresenterxl` |
| `0x1001d890` \_Tree&lt;MxCore \*,MxCore \*,set&lt;MxCore | 35 | `fwdP-31` | `sw-all2-legoworld` |
| `0x1004ebd0` LegoTexturePresenter::Read | 40 | `fwdE-11` | `sw-all-legotexturepresenter_v2` |
| `0x100bd020` MxBitmap::BitBltTransparent | 60 | `extern-0-24` | `sw-all-mxbitmaprect` |
| `0x10062e20` LegoAnimationManager::FUN\_10062e20 | 72 | `base-0` | `sw-all2-legoanimationmanager_faf1` |
| `0x100b2a70` MxVideoPresenter::PutFrame | 101 | `extern-30-0` | `sw-all2-mxvideopresentermstrip` |
| `0x100a7960` \_Tree&lt;char const \*,pair&lt;char const | 259 | `pad-9-12` | `sw-all2-viewlodlist` |

## 2. Ledger vs result-file disagreements

Four rows where a ledger under-reports its own sweep. In every case the
result file is better, and in two cases it is a **finished row**.

| row | ledger says | result file says | state |
|---|---:|---:|---|
| `0x10068b20` \_Tree&lt;char const \*,pair&lt;char c | nd=1 (stl-family-ledger.md:296) | **nd=0** | `fCS-211` |
| `0x10069e90` \_Tree&lt;char const \*,pair&lt;char c | nd=18 (stl-family-ledger.md:1519) | **nd=0** | `stack_6_60_S-422` |
| `0x1006a7a0` \_Tree&lt;char const \*,pair&lt;char c | nd=5 (stl-family-ledger.md:299) | **nd=4** | `extern-32-5` |
| `0x1006dec0` \_Tree&lt;char const \*,pair&lt;char c | nd=55 (stl-family-ledger.md:301) | **nd=18** | `stack_6_60_S-382` |

`0x1006dec0` at nd=18 against a ledger's nd=55, and `0x1006a7a0` at 4
against 5, are the same failure in a milder form: the `_L660` and `_LONG`
strips outran the wave that launched them.

## 3. What has actually closed rows

100 rows are held closed by a donor across 37 compose units:

| recipe kind | rows closed | TUs |
|---|---:|---:|
| `forward_declaration_run` | 45 | 19 |
| `declaration_shape` | 33 | 22 |
| `extern_run_pair` | 18 | 10 |
| `forward_run_with_shape` | 3 | 3 |
| `extern_pair_with_shape` | 1 | 1 |
| `pad_shape` | **0** | **0** |
| `declaration_run_triple` | **0** | **0** |
| `extern_pair_with_pad` | **0** | **0** |

Set that against measured coverage: `pad` has cells on **19 of 81** rows,
`triple` on **2**, `include_perm` on **11**, `fwdP` on **10**, `fwdL` on
**10**. `extern` and `shape` dominate the corpus and dominate the landings.
Whether that is because they are the productive families or merely the
swept ones is **not decidable from this data** — but it is the single
largest asymmetry in the table.

## 4. The matrix

Numbers are carrier states measured in a `results.json`. `·` means no
result file covers that row in that family — *not* proof nothing ran.
`L` marks a family a ledger claims but no result file backs.

| row | m | TU | shp | pad | fwL | fwP | fwE | ext | tri | cmp | inc | cells | nd | class |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `0x10040360` Act3Cop::FUN\_10040360 | 0.973 | `act3actors.cpp` | L | L | L | L | L | L | · | L | · | 0 | — | B |
| `0x100417c0` Act3Brickster::FUN\_100417c0 | 0.9496 | `act3actors.cpp` | L | L | L | L | L | L | · | L | · | 0 | — | B |
| `0x10054050` Act3Ammo::Animate | 0.9476 | `act3ammo.cpp` | L | L | L | L | L | L | · | · | · | 0 | — | B |
| `0x100035e0` Helicopter::HandleControl | 0.9907 | `helicopter.cpp` | · | · | · | · | · | 1680 | · | · | · | 1680 | 19 | C |
| `0x10038380` Pizza::StopActions | 0.7442 | `pizza.cpp` | 1010 | · | · | · | · | 1680 | · | L | · | 2690 | 11 | C |
| `0x10017af0` PizzeriaState::PizzeriaState | 0.8873 | `pizzeria.cpp` | L | L | L | L | L | 1680 | · | · | · | 1680 | 18 | C |
| `0x1004d330` TowTrack::HandlePathStruct | 0.9536 | `towtrack.cpp` | L | L | L | L | L | L | L | L | · | 0 | — | B |
| `0x1003cf20` LegoCacheSoundManager::~LegoCa | 0.895 | `legocachesoundmanager.cpp` | L | L | L | L | L | L | L | · | · | 0 | — | B |
| `0x1003d170` LegoCacheSoundManager::FindSou | 0.9552 | `legocachesoundmanager.cpp` | L | L | L | L | L | L | L | · | · | 0 | — | B |
| `0x10029d50` \_Tree&lt;LegoCacheSoundEntry,Lego | 0.9212 | `legosoundmanager.cpp` | L | L | L | L | L | · | · | · | · | 0 | — | B |
| `0x1002a1b0` \_Tree&lt;LegoCacheSoundEntry,Lego | 0.7059 | `legosoundmanager.cpp` | L | L | L | L | L | · | · | · | · | 0 | — | B |
| `0x10061010` LegoAnimationManager::FUN\_1006 | 0.5411 | `legoanimationmanager.cpp` *(ARCH)* | L | L | L | L | L | L | · | L | L | 0 | — | B |
| `0x10062e20` LegoAnimationManager::FUN\_1006 | 0.8856 | `legoanimationmanager.cpp` *(ARCH)* | L | L | L | L | L | · | · | · | · | 0 | 72 | B |
| `0x10083500` LegoCharacterManager::GetActor | 0.9684 | `legocharactermanager.cpp` | · | · | · | · | L | · | · | · | · | 0 | — | B |
| `0x10083890` \_Tree&lt;char \*,pair&lt;char \* const | 0.7075 | `legocharactermanager.cpp` | L | L | L | L | L | · | · | · | · | 0 | — | B |
| `0x10084030` LegoCharacterManager::CreateAc | 0.9365 | `legocharactermanager.cpp` | L | L | L | L | L | · | · | · | L | 0 | — | B |
| `0x10085500` \_Tree&lt;char \*,pair&lt;char \* const | 0.9244 | `legocharactermanager.cpp` | L | L | L | L | L | · | · | · | · | 0 | — | B |
| `0x1003f540` WriteDefaultTexture | 0.9273 | `legoutils.cpp` | L | L | L | L | L | 2139 | · | · | · | 2139 | 12 | C |
| `0x1004bd10` MxTransitionManager::DissolveT | 0.9608 | `mxtransitionmanager.cpp` | L | L | L | L | L | 2139 | · | · | · | 2139 | 6 | C |
| `0x1004c580` MxTransitionManager::SetupCopy | 0.8495 | `mxtransitionmanager.cpp` | · | · | · | · | · | 2139 | · | · | · | 2139 | — | C |
| `0x100293c0` LegoControlManager::UpdateEnab | 0.8625 | `legocontrolmanager.cpp` | · | · | · | · | · | 400 | · | · | · | 400 | — | C |
| `0x10055a60` LegoNavController::Notify | 0.9818 | `legonavcontroller.cpp` | · | · | · | · | · | · | · | · | · | 0 | — | A |
| `0x1001d890` \_Tree&lt;MxCore \*,MxCore \*,set&lt;Mx | 0.9027 | `legoworld.cpp` | 60 | 144 | 96 | 96 | 108 | 161 | · | · | · | 665 | 35 | D |
| `0x10058c30` LegoOmni::Destroy | 0.9827 | `legomain.cpp` | L | L | L | L | 24 | L | · | · | · | 24 | — | C |
| `0x10059dc0` \_Tree&lt;char const \*,pair&lt;char c | 0.7913 | `legomain.cpp` | L | L | L | L | 24 | L | · | L | L | 24 | — | C |
| `0x1002bff0` \_Tree&lt;LegoPathActor \*,LegoPath | 0.7092 | `legoextraactor.cpp` | L | L | L | L | L | L | L | L | · | 0 | — | B |
| `0x1002de10` LegoPathActor::SetTransformAnd | 0.9426 | `legopathactor.cpp` | L | · | L | · | L | L | · | · | · | 0 | — | B |
| `0x1002f770` LegoPathActor::UpdatePlane | 0.9315 | `legopathactor.cpp` | L | L | L | L | L | L | · | · | · | 0 | — | B |
| `0x10057180` \_Tree&lt;LegoAnimPresenter \*,Lego | 0.6522 | `legopathboundary.cpp` | L | 144 | L | L | L | · | · | · | · | 144 | 7 | C |
| `0x100574a0` LegoPathBoundary::RemoveActor | 0.7527 | `legopathboundary.cpp` | L | 144 | L | L | L | · | · | L | L | 144 | 2 | C |
| `0x100586e0` LegoPathBoundary::RemovePresen | 0.7757 | `legopathboundary.cpp` | L | 144 | L | L | L | · | · | · | · | 144 | 3 | C |
| `0x10046050` LegoPathController::PlaceActor | 0.9552 | `legopathcontroller.cpp` *(reassigned)* | · | · | · | · | · | · | · | · | · | 0 | — | A |
| `0x10048310` LegoPathController::FindPath | 0.8629 | `legopathcontroller.cpp` *(reassigned)* | L | L | L | L | L | L | · | · | · | 0 | — | B |
| `0x100495b0` \_Tree&lt;LegoBEWithMidpoint \*,Leg | 0.6532 | `legopathcontroller.cpp` *(reassigned)* | L | L | L | L | L | L | · | · | · | 0 | — | B |
| `0x100166a0` JetskiRace::HandlePathStruct | 0.8675 | `legorace.cpp` | L | L | L | L | L | L | · | · | · | 0 | — | B |
| `0x100170e0` CarRace::HandlePathStruct | 0.9752 | `legorace.cpp` | L | L | L | L | L | L | · | · | · | 0 | — | B |
| `0x10080be0` LegoCarRaceActor::CalculateSpl | 0.9545 | `legoracespecial.cpp` | L | L | L | L | L | L | · | · | · | 0 | — | B |
| `0x10081840` LegoCarRaceActor::CheckPresent | 0.9498 | `legoracespecial.cpp` | L | L | L | L | L | L | L | · | · | 0 | — | B |
| `0x10068b20` \_Tree&lt;char const \*,pair&lt;char c | 0.768 | `legoanimpresenter.cpp` | 1635 | 288 | 96 | 96 | 120 | 1868 | · | 2499 | 120 | 6722 | 0 | D |
| `0x10069b10` LegoAnimPresenter::BuildROIMap | 0.8842 | `legoanimpresenter.cpp` | 1635 | 288 | 96 | 96 | 120 | 1868 | · | 2499 | 120 | 6722 | 2 | D |
| `0x10069e90` \_Tree&lt;char const \*,pair&lt;char c | 0.7745 | `legoanimpresenter.cpp` | 1635 | 288 | 96 | 96 | 120 | 1868 | · | 2499 | 120 | 6722 | 0 | D |
| `0x1006a7a0` \_Tree&lt;char const \*,pair&lt;char c | 0.7983 | `legoanimpresenter.cpp` | 1635 | 288 | 96 | 96 | 120 | 1868 | · | 2499 | 120 | 6722 | 4 | D |
| `0x1006b140` LegoAnimPresenter::CopyTransfo | 0.8149 | `legoanimpresenter.cpp` | 1635 | 288 | 96 | 96 | 120 | 1868 | · | 2499 | 120 | 6722 | — | D |
| `0x1006c200` \_Tree&lt;char const \*,pair&lt;char c | 0.7828 | `legoanimpresenter.cpp` | 1635 | 288 | 96 | 96 | 120 | 1868 | · | 2499 | 120 | 6722 | 4 | D |
| `0x1006dec0` \_Tree&lt;char const \*,pair&lt;char c | 0.8205 | `legoanimpresenter.cpp` | 1635 | 288 | 96 | 96 | 120 | 1868 | · | 2499 | 120 | 6722 | 18 | D |
| `0x1006e720` \_Tree&lt;char const \*,pair&lt;char c | 0.8475 | `legoanimpresenter.cpp` | 1635 | 288 | 96 | 96 | 120 | 1868 | · | 2499 | 120 | 6722 | 4 | D |
| `0x1007ca30` LegoPartPresenter::Read | 0.9953 | `legopartpresenter.cpp` | 1010 | · | · | · | · | 2139 | · | L | · | 3149 | 4 | C |
| `0x1004ebd0` LegoTexturePresenter::Read | 0.8446 | `legotexturepresenter.cpp` | L | L | L | L | 12 | · | · | · | · | 12 | 40 | C |
| `0x1004f9b0` \_Tree&lt;char const \*,pair&lt;char c | 0.8051 | `legotexturepresenter.cpp` | L | L | L | L | 12 | · | · | L | · | 12 | — | C |
| `0x1007b770` LegoVideoManager::Tickle | 0.9636 | `legovideomanager.cpp` | L | L | L | L | L | 1680 | · | · | · | 1680 | 19 | C |
| `0x100720d0` Act3List::RemoveByObjectIdOrFi | 0.9417 | `act3.cpp` | L | L | L | L | L | L | L | L | L | 0 | — | B |
| `0x10072ad0` Act3::TriggerHitSound | 0.9302 | `act3.cpp` | L | L | L | L | L | L | L | L | L | 0 | — | B |
| `0x10073a90` Act3::Enable | 0.8893 | `act3.cpp` | L | L | L | L | L | L | L | L | L | 0 | — | B |
| `0x1006ed90` Infocenter::Create | 0.8966 | `infocenter.cpp` | · | · | · | · | · | 400 | · | · | · | 400 | — | C |
| `0x1006fda0` Infocenter::HandleKeyPress | 0.7933 | `infocenter.cpp` | · | · | · | · | · | 400 | · | · | · | 400 | — | C |
| `0x10031820` Isle::Enable | 0.9725 | `isle.cpp` | 505 | 900 | · | · | · | 1840 | 122 | L | 72 | 3439 | 11 | D |
| `0x100334b0` Act1State::Act1State | 0.9891 | `isle.cpp` | 505 | 900 | · | · | · | 1840 | 122 | L | 72 | 3439 | 24 | D |
| `0x10051ac0` LegoAct2::SpawnBricks | 0.9101 | `legoact2.cpp` | L | L | L | L | L | L | · | · | · | 0 | — | B |
| `0x1009f490` LegoAnimScene::CalculateCamera | 0.8896 | `legoanim.cpp` *(ARCH)* | L | L | L | L | L | L | · | · | · | 0 | — | B |
| `0x1009a8c0` LegoWEGEdge::LinkEdgesAndFaces | 0.9921 | `legowegedge.cpp` | L | L | L | L | L | L | L | L | L | 0 | — | B |
| `0x100998e0` LegoTextureContainer::GetCache | 0.8698 | `legocontainer.cpp` | · | · | · | · | · | · | · | · | · | 0 | — | A |
| `0x100aa510` LegoLOD::Read | 0.7268 | `legolod.cpp` | L | L | L | L | L | L | · | · | · | 0 | — | B |
| `0x100a84a0` LegoROI::Read | 0.9277 | `legoroi.cpp` | L | L | L | L | L | L | · | · | · | 0 | — | B |
| `0x100c6fa0` MxDSBuffer::FUN\_100c6fa0 | 0.9882 | `mxdsbuffer.cpp` | L | L | L | L | L | 2139 | · | · | L | 2139 | 4 | C |
| `0x100d0d80` ReadData | 0.9722 | `mxramstreamprovider.cpp` | · | · | · | · | · | 1680 | · | · | · | 1680 | 18 | C |
| `0x100bd020` MxBitmap::BitBltTransparent | 0.747 | `mxbitmap.cpp` | L | L | L | L | L | 1680 | · | · | · | 1680 | 60 | C |
| `0x100ba7f0` MxDisplaySurface::Create | 0.9953 | `mxdisplaysurface.cpp` | · | · | · | · | · | 2539 | · | · | · | 2539 | 9 | C |
| `0x100bb1d0` MxDisplaySurface::VTable0x30 | 0.8611 | `mxdisplaysurface.cpp` | L | L | L | L | L | 2539 | · | · | · | 2539 | 4 | C |
| `0x100c3750` MxRegion::AddRect | 0.9739 | `mxregion.cpp` | 1010 | L | L | L | L | 4739 | · | · | L | 5749 | 6 | C |
| `0x100ba2c0` MxStillPresenter::Clone | 0.9251 | `mxstillpresenter.cpp` | 505 | · | · | · | · | 400 | · | · | · | 905 | — | C |
| `0x100b24f0` MxVideoPresenter::AlphaMask::A | 0.9612 | `mxvideopresenter.cpp` | 1010 | L | L | L | L | 5139 | · | · | · | 6149 | 5 | C |
| `0x100b26f0` MxVideoPresenter::AlphaMask::I | 0.9348 | `mxvideopresenter.cpp` | 1010 | L | L | L | L | 5139 | · | · | · | 6149 | 6 | C |
| `0x100b27b0` MxVideoPresenter::Destroy(unsi | 0.8791 | `mxvideopresenter.cpp` | 1010 | L | L | L | L | 5139 | · | · | · | 6149 | 25 | C |
| `0x100b2a70` MxVideoPresenter::PutFrame | 0.9048 | `mxvideopresenter.cpp` | 1010 | L | L | L | L | 5139 | · | · | · | 6149 | 101 | C |
| `0x100a4420` OrientableROI::OrientableROI | 0.9504 | `orientableroi.cpp` *(ARCH)* | L | L | · | · | · | · | · | · | · | 0 | — | B |
| `0x100a46b0` OrientableROI::UpdateTransform | 0.8696 | `orientableroi.cpp` *(ARCH)* | · | · | · | · | · | · | · | · | · | 0 | — | A |
| `0x100a12a0` TglImpl::TextureImpl::SetImage | 0.6667 | `tglrl40.cpp` | 505 | 845 | L | L | L | 2539 | · | · | · | 3889 | 16 | D |
| `0x100a3840` TglImpl::MeshBuilderImpl::Crea | 0.8176 | `tglrl40.cpp` | 505 | 845 | · | · | · | 2539 | · | · | · | 3889 | — | D |
| `0x100a3b40` TglImpl::MeshBuilderImpl::Clon | 0.7971 | `tglrl40.cpp` | 505 | 845 | L | L | L | 2539 | · | L | · | 3889 | 14 | D |
| `0x100a7960` \_Tree&lt;char const \*,pair&lt;char c | 0.878 | `viewlodlist.cpp` | 60 | 144 | 96 | 96 | 108 | 161 | · | · | 2 | 667 | 259 | D |
| `0x100a66f0` ViewManager::ManageVisibilityA | 0.8848 | `viewmanager.cpp` | 1515 | 900 | L | L | L | 4219 | · | · | L | 6634 | 1 | D |

## 5. Ranked gap list

### A — no coverage from any source — 4 rows

Nothing measured and nothing claimed. These are the only rows where 'unswept' is the honest reading.

| row | m | TU | measured | untried | cells |
|---|---:|---|---|---|---:|
| `0x10055a60` LegoNavController::Notify | 0.9818 | `legonavcontroller.cpp` | — | composite, extern, fwdE, fwdL, fwdP, include_perm, pad, shape, triple | 0 |
| `0x10046050` LegoPathController::PlaceActor(c | 0.9552 | `legopathcontroller.cpp` *(reassigned)* | — | composite, extern, fwdE, fwdL, fwdP, include_perm, pad, shape, triple | 0 |
| `0x100998e0` LegoTextureContainer::GetCached | 0.8698 | `legocontainer.cpp` | — | composite, extern, fwdE, fwdL, fwdP, include_perm, pad, shape, triple | 0 |
| `0x100a46b0` OrientableROI::UpdateTransformat | 0.8696 | `orientableroi.cpp` *(ARCH)* | — | composite, extern, fwdE, fwdL, fwdP, include_perm, pad, shape, triple | 0 |

### B — a ledger claims coverage no result file backs — 32 rows

The claim may be true and the file merely lost, or the sweep may never have scored this row. **This is the class the three lost rows came from.** Re-scoring the retained objects against a stem that includes the row is cheap and is the highest-value action in the table.

| row | m | TU | measured | untried | cells |
|---|---:|---|---|---|---:|
| `0x1009a8c0` LegoWEGEdge::LinkEdgesAndFaces | 0.9921 | `legowegedge.cpp` | — | — | 0 |
| `0x100170e0` CarRace::HandlePathStruct | 0.9752 | `legorace.cpp` | — | composite, include_perm, triple | 0 |
| `0x10040360` Act3Cop::FUN\_10040360 | 0.973 | `act3actors.cpp` | — | include_perm, triple | 0 |
| `0x10083500` LegoCharacterManager::GetActorRO | 0.9684 | `legocharactermanager.cpp` | — | composite, extern, fwdL, fwdP, include_perm, pad, shape, triple | 0 |
| `0x1003d170` LegoCacheSoundManager::FindSound | 0.9552 | `legocachesoundmanager.cpp` | — | composite, include_perm | 0 |
| `0x10080be0` LegoCarRaceActor::CalculateSplin | 0.9545 | `legoracespecial.cpp` | — | composite, include_perm, triple | 0 |
| `0x1004d330` TowTrack::HandlePathStruct | 0.9536 | `towtrack.cpp` | — | include_perm | 0 |
| `0x100a4420` OrientableROI::OrientableROI | 0.9504 | `orientableroi.cpp` *(ARCH)* | — | composite, extern, fwdE, fwdL, fwdP, include_perm, triple | 0 |
| `0x10081840` LegoCarRaceActor::CheckPresenter | 0.9498 | `legoracespecial.cpp` | — | composite, include_perm | 0 |
| `0x100417c0` Act3Brickster::FUN\_100417c0 | 0.9496 | `act3actors.cpp` | — | include_perm, triple | 0 |
| `0x10054050` Act3Ammo::Animate | 0.9476 | `act3ammo.cpp` | — | composite, include_perm, triple | 0 |
| `0x1002de10` LegoPathActor::SetTransformAndDe | 0.9426 | `legopathactor.cpp` | — | composite, fwdP, include_perm, pad, triple | 0 |
| `0x100720d0` Act3List::RemoveByObjectIdOrFirs | 0.9417 | `act3.cpp` | — | — | 0 |
| `0x10084030` LegoCharacterManager::CreateActo | 0.9365 | `legocharactermanager.cpp` | — | composite, extern, triple | 0 |
| `0x1002f770` LegoPathActor::UpdatePlane | 0.9315 | `legopathactor.cpp` | — | composite, include_perm, triple | 0 |
| `0x10072ad0` Act3::TriggerHitSound | 0.9302 | `act3.cpp` | — | — | 0 |
| `0x100a84a0` LegoROI::Read | 0.9277 | `legoroi.cpp` | — | composite, include_perm, triple | 0 |
| `0x10085500` \_Tree&lt;char \*,pair&lt;char \* const,L | 0.9244 | `legocharactermanager.cpp` | — | composite, extern, include_perm, triple | 0 |
| `0x10029d50` \_Tree&lt;LegoCacheSoundEntry,LegoCa | 0.9212 | `legosoundmanager.cpp` | — | composite, extern, include_perm, triple | 0 |
| `0x10051ac0` LegoAct2::SpawnBricks | 0.9101 | `legoact2.cpp` | — | composite, include_perm, triple | 0 |
| `0x1003cf20` LegoCacheSoundManager::~LegoCach | 0.895 | `legocachesoundmanager.cpp` | — | composite, include_perm | 0 |
| `0x1009f490` LegoAnimScene::CalculateCameraTr | 0.8896 | `legoanim.cpp` *(ARCH)* | — | composite, include_perm, triple | 0 |
| `0x10073a90` Act3::Enable | 0.8893 | `act3.cpp` | — | — | 0 |
| `0x10062e20` LegoAnimationManager::FUN\_10062e | 0.8856 | `legoanimationmanager.cpp` *(ARCH)* | — | composite, extern, include_perm, triple | 0 |
| `0x100166a0` JetskiRace::HandlePathStruct | 0.8675 | `legorace.cpp` | — | composite, include_perm, triple | 0 |
| `0x10048310` LegoPathController::FindPath | 0.8629 | `legopathcontroller.cpp` *(reassigned)* | — | composite, include_perm, triple | 0 |
| `0x100aa510` LegoLOD::Read | 0.7268 | `legolod.cpp` | — | composite, include_perm, triple | 0 |
| `0x1002bff0` \_Tree&lt;LegoPathActor \*,LegoPathAc | 0.7092 | `legoextraactor.cpp` | — | include_perm | 0 |
| `0x10083890` \_Tree&lt;char \*,pair&lt;char \* const,L | 0.7075 | `legocharactermanager.cpp` | — | composite, extern, include_perm, triple | 0 |
| `0x1002a1b0` \_Tree&lt;LegoCacheSoundEntry,LegoCa | 0.7059 | `legosoundmanager.cpp` | — | composite, extern, include_perm, triple | 0 |
| `0x100495b0` \_Tree&lt;LegoBEWithMidpoint \*,LegoB | 0.6532 | `legopathcontroller.cpp` *(reassigned)* | — | composite, include_perm, triple | 0 |
| `0x10061010` LegoAnimationManager::FUN\_100610 | 0.5411 | `legoanimationmanager.cpp` *(ARCH)* | — | triple | 0 |

### C — one or two families measured — 29 rows

Real coverage, narrow. The `_Ubound` precedent applies: 1,681 extern states frozen at nd=2, then a different generator closed it on its 124th cell.

| row | m | TU | measured | untried | cells |
|---|---:|---|---|---|---:|
| `0x1007ca30` LegoPartPresenter::Read | 0.9953 | `legopartpresenter.cpp` | extern, shape | fwdE, fwdL, fwdP, include_perm, pad, triple | 3149 |
| `0x100ba7f0` MxDisplaySurface::Create | 0.9953 | `mxdisplaysurface.cpp` | extern | composite, fwdE, fwdL, fwdP, include_perm, pad, shape, triple | 2539 |
| `0x100035e0` Helicopter::HandleControl | 0.9907 | `helicopter.cpp` | extern | composite, fwdE, fwdL, fwdP, include_perm, pad, shape, triple | 1680 |
| `0x100c6fa0` MxDSBuffer::FUN\_100c6fa0 | 0.9882 | `mxdsbuffer.cpp` | extern | composite, triple | 2139 |
| `0x10058c30` LegoOmni::Destroy | 0.9827 | `legomain.cpp` | fwdE | composite, include_perm, triple | 24 |
| `0x100c3750` MxRegion::AddRect | 0.9739 | `mxregion.cpp` | extern, shape | composite, triple | 5749 |
| `0x100d0d80` ReadData | 0.9722 | `mxramstreamprovider.cpp` | extern | composite, fwdE, fwdL, fwdP, include_perm, pad, shape, triple | 1680 |
| `0x1007b770` LegoVideoManager::Tickle | 0.9636 | `legovideomanager.cpp` | extern | composite, include_perm, triple | 1680 |
| `0x100b24f0` MxVideoPresenter::AlphaMask::Alp | 0.9612 | `mxvideopresenter.cpp` | extern, shape | composite, include_perm, triple | 6149 |
| `0x1004bd10` MxTransitionManager::DissolveTra | 0.9608 | `mxtransitionmanager.cpp` | extern | composite, include_perm, triple | 2139 |
| `0x100b26f0` MxVideoPresenter::AlphaMask::IsH | 0.9348 | `mxvideopresenter.cpp` | extern, shape | composite, include_perm, triple | 6149 |
| `0x1003f540` WriteDefaultTexture | 0.9273 | `legoutils.cpp` | extern | composite, include_perm, triple | 2139 |
| `0x100ba2c0` MxStillPresenter::Clone | 0.9251 | `mxstillpresenter.cpp` | extern, shape | composite, fwdE, fwdL, fwdP, include_perm, pad, triple | 905 |
| `0x100b2a70` MxVideoPresenter::PutFrame | 0.9048 | `mxvideopresenter.cpp` | extern, shape | composite, include_perm, triple | 6149 |
| `0x1006ed90` Infocenter::Create | 0.8966 | `infocenter.cpp` | extern | composite, fwdE, fwdL, fwdP, include_perm, pad, shape, triple | 400 |
| `0x10017af0` PizzeriaState::PizzeriaState | 0.8873 | `pizzeria.cpp` | extern | composite, include_perm, triple | 1680 |
| `0x100b27b0` MxVideoPresenter::Destroy(unsign | 0.8791 | `mxvideopresenter.cpp` | extern, shape | composite, include_perm, triple | 6149 |
| `0x100293c0` LegoControlManager::UpdateEnable | 0.8625 | `legocontrolmanager.cpp` | extern | composite, fwdE, fwdL, fwdP, include_perm, pad, shape, triple | 400 |
| `0x100bb1d0` MxDisplaySurface::VTable0x30 | 0.8611 | `mxdisplaysurface.cpp` | extern | composite, include_perm, triple | 2539 |
| `0x1004c580` MxTransitionManager::SetupCopyRe | 0.8495 | `mxtransitionmanager.cpp` | extern | composite, fwdE, fwdL, fwdP, include_perm, pad, shape, triple | 2139 |
| `0x1004ebd0` LegoTexturePresenter::Read | 0.8446 | `legotexturepresenter.cpp` | fwdE | composite, extern, include_perm, triple | 12 |
| `0x1004f9b0` \_Tree&lt;char const \*,pair&lt;char con | 0.8051 | `legotexturepresenter.cpp` | fwdE | extern, include_perm, triple | 12 |
| `0x1006fda0` Infocenter::HandleKeyPress | 0.7933 | `infocenter.cpp` | extern | composite, fwdE, fwdL, fwdP, include_perm, pad, shape, triple | 400 |
| `0x10059dc0` \_Tree&lt;char const \*,pair&lt;char con | 0.7913 | `legomain.cpp` | fwdE | triple | 24 |
| `0x100586e0` LegoPathBoundary::RemovePresente | 0.7757 | `legopathboundary.cpp` | pad | composite, extern, include_perm, triple | 144 |
| `0x100574a0` LegoPathBoundary::RemoveActor | 0.7527 | `legopathboundary.cpp` | pad | extern, triple | 144 |
| `0x100bd020` MxBitmap::BitBltTransparent | 0.747 | `mxbitmap.cpp` | extern | composite, include_perm, triple | 1680 |
| `0x10038380` Pizza::StopActions | 0.7442 | `pizza.cpp` | extern, shape | fwdE, fwdL, fwdP, include_perm, pad, triple | 2690 |
| `0x10057180` \_Tree&lt;LegoAnimPresenter \*,LegoAn | 0.6522 | `legopathboundary.cpp` | pad | composite, extern, include_perm, triple | 144 |

### D — deeply measured, families still untried — 16 rows

Thousands of cells, but not across the whole grammar.

| row | m | TU | measured | untried | cells |
|---|---:|---|---|---|---:|
| `0x100334b0` Act1State::Act1State | 0.9891 | `isle.cpp` | extern, include_perm, pad, shape, triple | fwdE, fwdL, fwdP | 3439 |
| `0x10031820` Isle::Enable | 0.9725 | `isle.cpp` | extern, include_perm, pad, shape, triple | fwdE, fwdL, fwdP | 3439 |
| `0x1001d890` \_Tree&lt;MxCore \*,MxCore \*,set&lt;MxCo | 0.9027 | `legoworld.cpp` | extern, fwdE, fwdL, fwdP, pad, shape | composite, include_perm, triple | 665 |
| `0x100a66f0` ViewManager::ManageVisibilityAnd | 0.8848 | `viewmanager.cpp` | extern, pad, shape | composite, triple | 6634 |
| `0x10069b10` LegoAnimPresenter::BuildROIMap | 0.8842 | `legoanimpresenter.cpp` | composite, extern, fwdE, fwdL, fwdP, include_perm, pad, shape | triple | 6722 |
| `0x100a7960` \_Tree&lt;char const \*,pair&lt;char con | 0.878 | `viewlodlist.cpp` | extern, fwdE, fwdL, fwdP, include_perm, pad, shape | composite, triple | 667 |
| `0x1006e720` \_Tree&lt;char const \*,pair&lt;char con | 0.8475 | `legoanimpresenter.cpp` | composite, extern, fwdE, fwdL, fwdP, include_perm, pad, shape | triple | 6722 |
| `0x1006dec0` \_Tree&lt;char const \*,pair&lt;char con | 0.8205 | `legoanimpresenter.cpp` | composite, extern, fwdE, fwdL, fwdP, include_perm, pad, shape | triple | 6722 |
| `0x100a3840` TglImpl::MeshBuilderImpl::Create | 0.8176 | `tglrl40.cpp` | extern, pad, shape | composite, fwdE, fwdL, fwdP, include_perm, triple | 3889 |
| `0x1006b140` LegoAnimPresenter::CopyTransform | 0.8149 | `legoanimpresenter.cpp` | composite, extern, fwdE, fwdL, fwdP, include_perm, pad, shape | triple | 6722 |
| `0x1006a7a0` \_Tree&lt;char const \*,pair&lt;char con | 0.7983 | `legoanimpresenter.cpp` | composite, extern, fwdE, fwdL, fwdP, include_perm, pad, shape | triple | 6722 |
| `0x100a3b40` TglImpl::MeshBuilderImpl::Clone | 0.7971 | `tglrl40.cpp` | extern, pad, shape | include_perm, triple | 3889 |
| `0x1006c200` \_Tree&lt;char const \*,pair&lt;char con | 0.7828 | `legoanimpresenter.cpp` | composite, extern, fwdE, fwdL, fwdP, include_perm, pad, shape | triple | 6722 |
| `0x10069e90` \_Tree&lt;char const \*,pair&lt;char con | 0.7745 | `legoanimpresenter.cpp` | composite, extern, fwdE, fwdL, fwdP, include_perm, pad, shape | triple | 6722 |
| `0x10068b20` \_Tree&lt;char const \*,pair&lt;char con | 0.768 | `legoanimpresenter.cpp` | composite, extern, fwdE, fwdL, fwdP, include_perm, pad, shape | triple | 6722 |
| `0x100a12a0` TglImpl::TextureImpl::SetImage | 0.6667 | `tglrl40.cpp` | extern, pad, shape | composite, include_perm, triple | 3889 |

## 6. What a later wave should read this table for

1. **`0x100495b0` is the template, not the exception.** A hit existed in an
   object no scorer looked at. The generalisation is: re-score the retained
   objects against a stem listing *every* open row, not the stem the sweep
   was launched with. Class B is 32 rows wide.
2. **Read the result files of any sweep that outran its wave.** `_L660` and
   `_LONG` each held a finished row for weeks.
3. **`pad_shape` has 9,801 legal cells, a proven end-to-end path, and zero
   landed rows** — on 19 of 81 rows measured. `declaration_run_triple` has
   two. Neither absence is evidence of inertness.
4. **Four rows have no coverage from any source**: `0x10055a60`,
   `0x10046050`, `0x100998e0`, `0x100a46b0`. Two are in reassigned or ARCH
   TUs; `0x100998e0 GetCached` and `0x10055a60 Notify` are not.

## 7. Known limits of this artifact

* A `·` is *absence of record*, never proof of absence of work.
* Result files predating a landing in their TU were measured on superseded
  text. Five TUs owning open rows have changed since this lane's base:
  `legoanimationmanager.cpp`, `mxtransitionmanager.cpp`,
  `legonavcontroller.cpp`, `legoanim.cpp`, `legocontainer.cpp`.
* `nd` is positional and **meaningless across a length change**. The nd
  column is comparable within a row, never between rows.
* The triage table's `flat cells` figure is an aggregate over five families
  and cannot be decomposed; it is recorded as a ledger claim, not measured
  per-family coverage.
* Cells from different waves ran on different shadows. A state label does
  not transfer across shadows — re-derive before landing.
