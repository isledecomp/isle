# Sweep-coverage matrix — every open LEGO1 row

**Built at 81 open rows · 46 TUs · 141,114 measured carrier cells · 114 result
files.** Section 0 (added 2026-08-16 by lane HARVEST) re-measures the whole
corpus at the object level against the 78 open rows of the current tip and
supersedes §1's floor table; §§1–7 are kept as written for their provenance
argument.

## 0. 2026-08-16 · the corpus re-scored at the OBJECT level, all 78 open rows

### The premise this table was built on was already satisfied — and it is empty

§6 asks a later wave to "re-score the retained objects against a stem listing
*every* open row". **That had already been done**, four hours before this
matrix was written: `fresh3/rescore.py`'s own log opens with
`open rows: 81; covered by oracle: 81; target symbols: 81`. Class B is
therefore not 32 rows of unmeasured exposure; it is 32 rows whose *ledgers*
are silent, over objects that were scored.

Re-running that scan against the tip's 78 rows over **395,874 objects — 6,586
more than the 06:48 pass, including `fresh3/`'s own `bodysweep-*` tree, which
that pass skipped by an explicit `if "fresh3" in dirpath: continue`** —
produces **no nd≤2 state anywhere that the 06:48 pass had not already seen**.
Two further scratchpads exist under this project (`fa2e035c…`, `8df0bb80…`);
neither holds a single `.obj`. **The retained corpus is exhausted at the
object level.** Do not spend another wave re-reading it.

### What replaces it: the corpus is stale, not incomplete

Every retained object was compiled against a source text that has since moved,
and `nd` is not portable across that. Measured, on the row that proves it:

* `0x100574a0 RemoveActor`'s corpus nd=0 (`sweep2-all2-legopathboundary/
  pad-10-12`) **does re-derive at nd=0 on today's cold shadow** — so the
  open-set triage's "STALE — floor nd=2 on later shadows" verdict is wrong —
  but its base source carries a text variant in `~LegoPathBoundary`
  (`!(it == m_actors.end())` for `it != m_actors.end()`), so it is not a
  landable carrier donor on its own.
* Re-running **one generator family on the unmodified tip text** (900
  `pad_shape` cells) lands the row instead: `pad-10-29` reaches nd=0 with no
  source change at all. Landed; LEGO1 4856 → 4857.

**Doctrine: open a wave by re-sweeping the cheapest generator family on
today's text for the rows the corpus floors near zero, not by re-reading the
corpus.** The corpus tells you which rows are close; it no longer tells you
which cell.

### The five corpus nd=0 rows, re-verified today

Each was re-checked against `legobin/LEGO1.DLL` (oracle bytes) **and** through
the S72 semantic-relocation guard (decode retail's own bytes at every
relocation site, name the target from the tip report, compare with the
candidate's relocation symbol and with today's seed object).

| row | state | verdict |
|---|---|---|
| `0x100574a0` RemoveActor | `pad-10-12` → **`pad-10-29`** on tip text | **LANDED** — oracle 258/258 identical, masked nd=0, 10/10 relocation targets agree, 0 seed mismatches |
| `0x10083500` GetActorROI | `insf-20-21` | genuine nd=0 (822/822, 32/32 relocations agree, 0 seed mismatches) but it needs a **source text edit**; see the arithmetic below |
| `0x10084030` CreateActorROI | `shape-5-26`, `pad-5-17`, … | **S72 FALSE POSITIVE, re-confirmed today**: at body offsets **101** and **1220** retail calls `Vector3::Vector3` (`0x1001d150`) where every one of our objects calls `Vector2::Vector2` (`0x1000c0f0`). Offsets 77/1192 agree. A masked nd=0 is meaningless here |
| `0x1003cf20` ~LegoCacheSoundManager | `b10w4/hprobes/lcsm-ool` | Lane B10's TU; the out-of-line text state, −12 pinned donors |
| `0x1002bff0` `_Tree<LegoPathActor*>::erase` | `lpb-stk2/stkE-11-1-3` | **supplier-blocked, now measured**: six objects in the build define this COMDAT — `act3ammo` (1096 = retail's length, nd=47), `legopathactor` (1097), `legoracespecial` (1103), `legoextraactor` and `legopathcontroller` (1104), `legopathboundary` (1105). The link winner is `legoextraactor`; **every corpus nd=0 for this row sits in an object the linker discards.** The only landable route is a `legoextraactor.cpp` donor (Lane B10) |

### Every open row's corpus floor, measured on objects

63 of the 78 open rows appear in at least one retained object at retail's exact
length. `nd` is masked over relocation operands and computed only at exact
length. **This supersedes §1's table, which covered 36 rows from result files.**

| row | m | best nd | state | sweep dir | states |
|---|---:|---:|---|---|---:|
| `0x1002bff0` \_Tree\<LegoPathActor \*,LegoPathActor \*,set\< | 0.7092 | 0 | `stkE-11-1-3` | `nm/probes/lpb-stk2` | 4761 |
| `0x1003cf20` LegoCacheSoundManager::~LegoCacheSoundMana | 0.8950 | 0 | `lcsm-ool` | `b10w4/hprobes` | 1740 |
| `0x100574a0` LegoPathBoundary::RemoveActor | 0.7527 | 0 | `pad-10-12` | `stl/sweep-bench/sweep2-all2-legopathboundary` | 3735 |
| `0x10083500` LegoCharacterManager::GetActorROI | 0.9684 | 0 | `insf-20-21` | `nm/probes/chm-h12-ins2` | 15106 |
| `0x10084030` LegoCharacterManager::CreateActorROI | 0.9365 | 0 | `shape-5-26` | `stl/sweep-bench/sweep2-legocharactermanager` | 20894 |
| `0x10059dc0` \_Tree\<char const \*,pair\<char const \* const | 0.7913 | 1 | `fwdE-311` | `b10w4/sweeps/all2-legomain-k600` | 897 |
| `0x100a66f0` ViewManager::ManageVisibilityAndDetailRecu | 0.8848 | 1 | `extern-3-1` | `inl/nd-vm_a4` | 1094 |
| `0x10069b10` LegoAnimPresenter::BuildROIMap | 0.8842 | 2 | `shape-9-85` | `stl/sw-all2-legoanimpresenter_E019sf` | 13810 |
| `0x1007ca30` LegoPartPresenter::Read | 0.9953 | 2 | `fwdP-38` | `stl/sweep-bench/sweep2-all-legopartpresenter-file-legopartpresenter` | 6521 |
| `0x1009a8c0` LegoWEGEdge::LinkEdgesAndFaces | 0.9921 | 2 | `extern-2-15` | `stl/sweep-bench/sweep2-open-legowegedge` | 9418 |
| `0x100586e0` LegoPathBoundary::RemovePresenter | 0.7757 | 3 | `shape-4-8` | `stl/sweep-bench/sweep2-open-legopathboundary` | 13417 |
| `0x1004f9b0` \_Tree\<char const \*,pair\<char const \* const | 0.8051 | 4 | `fwdL-25` | `bench/sweep2-all-legopartpresenter` | 202 |
| `0x1006a7a0` \_Tree\<char const \*,pair\<char const \* const | 0.7983 | 4 | `extern-32-5` | `stl/sw-all2-legoanimpresenter_R40` | 580 |
| `0x1006c200` \_Tree\<char const \*,pair\<char const \* const | 0.7828 | 4 | `pad-6-2` | `stl/sw-all2-legoanimpresenter_pE19` | 621 |
| `0x1006e720` \_Tree\<char const \*,pair\<char const \* const | 0.8475 | 4 | `shape-5-40` | `stl/sweep-bench/sweep2-buildroi-file-hyp` | 3779 |
| `0x10083890` \_Tree\<char \*,pair\<char \* const,LegoCharact | 0.7075 | 4 | `shape-9-13` | `stl/sweep-bench/sweep2-legocharactermanager` | 2797 |
| `0x100bb1d0` MxDisplaySurface::VTable0x30 | 0.8611 | 4 | `fwdP-46` | `bench/sweep2-all2-mxdisplaysurface` | 7745 |
| `0x100c6fa0` MxDSBuffer::FUN\_100c6fa0 | 0.9882 | 4 | `c4_blockonly` | `inl/g-buf1` | 5959 |
| `0x1001d890` \_Tree\<MxCore \*,MxCore \*,set\<MxCore \*,CoreS | 0.9027 | 5 | `fwdE-187` | `b10w4/redial/…legoworld.cpp` | 868 |
| `0x1002f770` LegoPathActor::UpdatePlane | 0.9315 | 5 | `rederive-all2-legopathactor-fwdL-6` | `stl/fresh2` | 10300 |
| `0x100b24f0` MxVideoPresenter::AlphaMask::AlphaMask(cla | 0.9612 | 5 | `shape-9-14` | `bench/sw-all2-mxvideopresentervp1` | 9764 |
| `0x10040360` Act3Cop::FUN\_10040360 | 0.9730 | 6 | `extern-62-20` | `b10w4/sweeps/all2-act3actors-c1ms` | 9865 |
| `0x1004bd10` MxTransitionManager::DissolveTransition | 0.9608 | 6 | `extern-0-35` | `bench/sw-all-mxtransitionmanagerlong` | 5546 |
| `0x100b26f0` MxVideoPresenter::AlphaMask::IsHit | 0.9348 | 6 | `shape-9-12` | `bench/sw-all2-mxvideopresentervp1` | 9757 |
| `0x100c3750` MxRegion::AddRect | 0.9739 | 6 | `fwdL-82` | `inl/ip-mxreg_w1` | 13807 |
| `0x10057180` \_Tree\<LegoAnimPresenter \*,LegoAnimPresente | 0.6522 | 7 | `fwdL-78` | `stl/sweep-bench/sweep2-open-legopathboundary` | 17912 |
| `0x100720d0` Act3List::RemoveByObjectIdOrFirst | 0.9417 | 7 | `fwdE-72` | `stl/sweep-bench/sweep2-all-act3` | 8225 |
| `0x1002a1b0` \_Tree\<LegoCacheSoundEntry,LegoCacheSoundEn | 0.7059 | 9 | `shape-7-30` | `stl/sweep-bench/sweep2-all-legosoundmanager` | 25614 |
| `0x100ba7f0` MxDisplaySurface::Create | 0.9953 | 9 | `d3_swap16` | `inl/g-mds1` | 7725 |
| `0x10031820` Isle::Enable | 0.9725 | 11 | `shape-10-62` | `fin/sw-all2-islexps18` | 6586 |
| `0x10038380` Pizza::StopActions | 0.7442 | 11 | `pad-3-30` | `fin/sw-all-pizzapad` | 2791 |
| `0x1004d330` TowTrack::HandlePathStruct | 0.9536 | 11 | `tt-base` | `b10w4/seedprobes` | 4154 |
| `0x10072ad0` Act3::TriggerHitSound | 0.9302 | 11 | `fwdE-72` | `stl/sweep-bench/sweep2-all-act3` | 11617 |
| `0x1003f540` WriteDefaultTexture | 0.9273 | 12 | `extern-24-90` | `bench/sw-all-legoutilslong` | 1743 |
| `0x10085500` \_Tree\<char \*,pair\<char \* const,LegoCharact | 0.9244 | 12 | `pad-12-9` | `stl/sweep-bench/sweep2-legocharactermanager` | 21429 |
| `0x100a3b40` TglImpl::MeshBuilderImpl::Clone | 0.7971 | 14 | `fwdE-72` | `bench/sweep2-all-tglrl40` | 9521 |
| `0x100a12a0` TglImpl::TextureImpl::SetImage | 0.6667 | 16 | `shape-4-9` | `bench/sweep2-all-tglrl40` | 9272 |
| `0x100035e0` Helicopter::HandleControl | 0.9907 | 17 | `heli_P_v68_up_va4` | `wave2/probes` | 1781 |
| `0x100166a0` JetskiRace::HandlePathStruct | 0.8675 | 18 | `shape-1-10` | `stl/sweep-bench/sweep2-all-legorace` | 2297 |
| `0x10017af0` PizzeriaState::PizzeriaState | 0.8873 | 18 | `extern-7-22` | `fin/sw-all-pizzeriarect` | 1681 |
| `0x1006dec0` \_Tree\<char const \*,pair\<char const \* const | 0.8205 | 18 | `stack_6_60_S-416` | `stl/sw-all2-legoanimpresenter_L660` | 1913 |
| `0x100d0d80` ReadData | 0.9722 | 18 | `extern-34-30` | `fin/sw-all-mxramstreamproviderrect` | 3778 |
| `0x1007b770` LegoVideoManager::Tickle | 0.9636 | 19 | `extern-7-22` | `bench/sw-all-legovideomanagerrect` | 4740 |
| `0x100334b0` Act1State::Act1State | 0.9891 | 24 | `shape-9-14` | `fin/sw-all2-islexps18` | 6716 |
| `0x100b27b0` MxVideoPresenter::Destroy(unsigned char) | 0.8791 | 25 | `shape-9-14` | `bench/sw-all2-mxvideopresentervp1` | 9764 |
| `0x10062e20` LegoAnimationManager::FUN\_10062e20 | 0.8856 | 30 | `shape-2-2` | `inl/ip-anmgr_ph02` | 8746 |
| `0x1004ebd0` LegoTexturePresenter::Read | 0.8446 | 40 | `fwdE-11` | `stl/sw-all-legotexturepresenter_v2` | 287 |
| `0x100a84a0` LegoROI::Read | 0.9277 | 41 | `extern-0-288` | `b10w4/sweeps/all2-legoroi-ms` | 532 |
| `0x10051ac0` LegoAct2::SpawnBricks | 0.9101 | 58 | `extern-0-35` | `fin/sw-all-legoact2rect` | 1264 |
| `0x100998e0` LegoTextureContainer::GetCached | 0.8698 | 59 | `gc-h2` | `b10w4/seedprobes` | 14 |
| `0x100bd020` MxBitmap::BitBltTransparent | 0.7470 | 60 | `extern-3-23` | `bench/sw-all-mxbitmaprect` | 4866 |
| `0x10048310` LegoPathController::FindPath | 0.8629 | 66 | `xps-7-37-5-28` | `nm/probes/fpd-lpc-FD1` | 667 |
| `0x100417c0` Act3Brickster::FUN\_100417c0 | 0.9496 | 73 | `extern-18-44` | `b10w4/redial/…act3actors.cpp` | 6007 |
| `0x10054050` Act3Ammo::Animate | 0.9476 | 95 | `extern-49-50` | `b10w4/sweeps/all-act3ammo-ms2` | 1930 |
| `0x100a46b0` OrientableROI::UpdateTransformationRelativ | 0.8696 | 99 | `e0_base` | `inl/g-ori1` | 424 |
| `0x10081840` LegoCarRaceActor::CheckPresenterAndActorIn | 0.9498 | 100 | `extern-69-228` | `b10w4/sweeps/all-legoracespecial-ms` | 2000 |
| `0x100b2a70` MxVideoPresenter::PutFrame | 0.9048 | 101 | `shape-9-74` | `bench/sw-all2-mxvideopresentervp1` | 777 |
| `0x10073a90` Act3::Enable | 0.8893 | 105 | `extern-3-12` | `stl/sweep-bench/sweep2-all-act3` | 3035 |
| `0x100170e0` CarRace::HandlePathStruct | 0.9752 | 111 | `fwdE-72` | `stl/sweep-bench/sweep2-all-legorace` | 2222 |
| `0x1003d170` LegoCacheSoundManager::FindSoundByKey | 0.9552 | 153 | `fsk_f4_it_first` | `wave2/probes` | 1 |
| `0x100a7960` \_Tree\<char const \*,pair\<char const \* const | 0.8780 | 259 | `shape-2-7` | `stl/sw-all2-viewlodlist_pE96sf` | 461 |
| `0x10029d50` \_Tree\<LegoCacheSoundEntry,LegoCacheSoundEn | 0.9212 | 268 | `pad-18-12` | `b10w4/sweeps/all2-legocachesoundmanager-w12pad` | 3507 |
| `0x10055a60` LegoNavController::Notify | 0.9818 | 2382 | `nav_variants_objs` | (aa9d0cc1 root) | 1 |

**15 rows never reach retail's length in ANY retained object** — unchanged from
the fresh3 reading: `0x100293c0`, `0x1002de10`, `0x10046050`, `0x1004c580`,
`0x10058c30`, `0x10061010`, `0x1006b140`, `0x1006ed90`, `0x1006fda0`,
`0x10080be0`, `0x1009f490`, `0x100a3840`, `0x100a4420`, `0x100aa510`,
`0x100ba2c0`.

### `0x10083500 GetActorROI` — verified, and priced

The corpus state is two named-local introductions inside `GetActorROI` plus a
`forward_declaration_run` suffix. Both text forms are the file's own idiom
(`LegoActorInfo* info = GetActorInfo(...)` appears at **ten** other sites in
`legocharactermanager.cpp`, including the next function; `MxU32 length =
strlen(x) + 1` is the codebase's standard shape). On today's shadow the row
reaches **nd=0** in three separate generator families
(`fwd count=4 suffix`, `pad-8-17`, `shape-7-52`) — but only with the text.

The text edit re-seeds the whole TU. **Every pinned donor in the unit had to be
re-dialled or re-pinned, and all four were** — which is exactly why this row is
a useful negative:

| function | donor | after the text edit |
|---|---|---|
| `?SwitchSound@LegoCharacterManager@@` | `d_93806ad84a84` | body reproduces; **seed/donor delta re-pinned** |
| `?ReleaseAutoROI@LegoCharacterManager@@` | `d_c15e6e4702a9` | body reproduces; **seed/donor delta re-pinned** |
| `??1?$list@PAVROI@@…` (`0x10084930`) | `d_55a88a58284c` | **body breaks** — re-dialled: nd=0 at `fwd MxUnkRecVC count 25 suffix` (also `pad-1-6`, `shape-1-6`, `fwd prefix 26`) |
| `?erase@?$_Tree@PAD…` (`0x10082ca0`) | `d_25f1c91cdff5` | **body breaks** — re-dialled: nd=0 at `extern_pair_with_shape g_h=15 g_p=20 shape(8,45)` (also `g_h=13 g_p=22`). Invisible to 3,510 cells of pad/shape/fwd/extern; **only the composite family reaches it** |

With all four re-dialled the gated build ran, and the **LOST list is still not
empty**:

```
LEGO1 rows 4856/4934 at 1.0, 1970 address-aligned
  LOST  0x10082b90  _Tree<char *,…LegoCharacter *>::~_Tree
  LOST  0x10083b20  LegoCharacterManager::Exists
  GAIN  0x10083500  LegoCharacterManager::GetActorROI
```

**Arithmetic: +1 −2 = net −1. Reverted.** The two casualties are rows that were
closed by the *plain seed compile*, with no donor and therefore no entry in the
unit's function list — **nothing in the manifest names them, so no amount of
donor bookkeeping predicts them.** The unit's function list is not the blast
radius of a source edit; the whole TU is.

**Doctrine: price a source edit by the gated build's LOST list, never by the
donor-pin audit.** The pin audit here said "two donors break"; it was right and
still incomplete, because donorless closed rows outnumbered the donored ones.
Get the LOST list first — one ~90 s build — then decide whether to re-dial.

The row is worth another wave: `0x10083500` is genuinely reachable, and the
remaining debt is two donorless rows in the same TU.

### Two rows the tip-text re-sweep did NOT move

`pad-10-29` is not a general rule. The other two nd=2 rows that sit in TUs no
lane owns were re-swept on the tip text over the same families, and both held
their corpus floor exactly:

| row | TU | corpus floor | tip-text floor | cells |
|---|---|---:|---|---:|
| `0x1009a8c0` LinkEdgesAndFaces | `legowegedge.cpp` | 2 (`extern-2-15`) | 2 (`pad-5-8`, `shape-5-40`) | 1,130 |
| `0x1007ca30` LegoPartPresenter::Read | `legopartpresenter.cpp` | 2 (`fwdP-38`) | 2 (`pad-13-15`) | 625 |

Re-sweeping today's text is cheap and sometimes decisive, but **a corpus floor
of 2 is not evidence that a cell exists**. These two carry the "one shared
allocator decision" signature, not a stale cell.

### One measured mechanism worth carrying forward

**The carrier prefix is inert; only the count is the lever.** On
`legocharactermanager.cpp`, `forward_declaration_run` sweeps with prefix
`RkNm` and with prefix `MxUnkRecVC` (same width, same placement, 300 and 200
cells) give the **same nd at the same count** for every scored row — the
objects differ, the scores do not. A re-dial never needs a new prefix; sweep
the count and reuse the project's established stems.

## 0.1 · 2026-08-16 wave 2 — tip-text re-sweeps on the near-misses

Both **nd=1** rows were re-swept on the current text in the family their corpus
floor lives in, counts swept and stems held fixed (the prefix-inert finding
below). **Neither floor moved — and both residues are now named, which is what
retires them.**

### The two nd=1 rows have the SAME single-byte mechanism: `cmp` operand direction

| row | TU | tip-text floor | cells | residue byte |
|---|---|---|---:|---|
| `0x10059dc0` `_Tree<…LegoTextureInfo*>::erase` | `legomain.cpp` | nd=1 @ `fwd MxUnkRecVC 311 suffix` | 500 | **+151**: ours `3b 4c 24 10` = `cmp ecx,[esp+0x10]`; retail `39 4c 24 10` = `cmp [esp+0x10],ecx` |
| `0x100a66f0` ManageVisibilityAndDetailRecursively | `viewmanager.cpp` | nd=1 @ `extern g_h=3 g_p=0` | 960 | **+517**: ours `3b c8` = `cmp ecx,eax`; retail `3b c1` = `cmp eax,ecx` |

Same operands, same semantics, one direction bit — opcode `39` vs `3B` in one
case, ModRM reg/rm swap in the other. This is the **`cmpdir` class**, which
`docs/shape-census.md` already records as invisible to SHAPE/STRUCT/EXACT, and
which the standing rules already record as **bit-inert from the source side**:
no spelling of a comparison changes which operand the selector puts in the
register. The direction is a *consequence* of where the two values happen to
live at that point, i.e. of register allocation — the "one shared allocator
decision" signature, not a text target.

**Both rows are retired from the carrier queue.** The remaining defect in each
is one byte, that byte is a comparison direction, and comparison direction is
not addressable from source or from any declaration-only carrier.

### A text dependency retired for free

The corpus reading of `0x100a66f0` had its nd=1 only at `a4 × extern-3-1` —
the `a4` **text** variant, which the inliner ledger notes *perturbs a 1.0 row*.
On plain tip text the same nd=1 is reached at `extern-3-0`. **The a4 text is
not needed for the floor**, so the row carries no text debt; only the `cmp`
byte remains.

### "Stacking is a new state" reproduced on today's text

The standing law — *a row at nd=1 on `fwdE-311` floors at 269 when any shape
cell is added; a force-included shape re-colours the whole compile* — was
re-measured, on this row, on this text: `forward_run_with_shape` pinned at the
floor seat (`MxUnkRecVC 311 suffix`) × all **505** legal shapes gives a best of
**nd=269** (`fsS-311-5-45`). Not "worse in places" — worse in every cell, by
two orders of magnitude. The `fwdpad` variant of the same seat was not run:
`pad_shape` is force-included by the same mechanism, so the law predicts it and
the cells are better spent elsewhere.

### Sealed negatives from this wave

| row | family swept on tip text | cells | floor | verdict |
|---|---|---:|---:|---|
| `0x10059dc0` | `fwd` suffix, counts 1–500 | 500 | **1** | held at the corpus cell; residue is `cmpdir` |
| `0x10059dc0` | `forward_run_with_shape` @ 311 × 505 shapes | 505 | 269 | stacking law |
| `0x10059dc0` | `extern` 21×21 lattice | 440 | — | **never reaches retail's length (1102)** in any cell; the family cannot even be scored for this row |
| `0x100a66f0` | `extern` 31×31 lattice | 960 | **1** | held; residue is `cmpdir`; a4 text retired |
| `0x100a66f0` | `declaration_shape`, all legal (c,f) | 505 | **1** | held — second independent family at the same floor |
| `0x100a66f0` | `fwd` suffix, counts 1–200 | 200 | 7 | family is unproductive for this row |
| `0x100a66f0` | `pad_shape` 15×15 | 225 | 6 | family is unproductive for this row |
| `0x1009a8c0` LinkEdgesAndFaces | `pad` 25×25, `shape` | 1,130 | 2 | held (wave 1) |
| `0x1007ca30` LegoPartPresenter::Read | `pad` 25×25 | 625 | 2 | held (wave 1) |

**Totals on tip text this wave: `0x10059dc0` 1,445 cells, `0x100a66f0` 1,890
cells — 3,335 in all, floor nd=1 in both, and in both the single residue byte
is a `cmp` operand direction.** Two families reach the floor for `0x100a66f0`
(`extern` and `shape`) and two do not (`fwd`, `pad`), so the floor is not an
artifact of one generator — and the two that reach it reach exactly the same
byte. For `0x10059dc0` the split is sharper still: `fwd` suffix reaches the
floor, `extern` cannot reach retail's **length** at all, and stacking a shape
on the floor seat costs two orders of magnitude.

`0x10069b10 BuildROIMap` is **screened, not swept** — `legoanimpresenter.cpp`
belongs to Lane ARCH. Its corpus floor is **nd=2 at `shape-9-85`**
(`stl/sw-all2-legoanimpresenter_E019sf`, 13,810 states); that is the state to
re-derive on today's text if ARCH wants it.

### What would move a `cmpdir` byte, if anything does

Not the source and not a declaration-only carrier — 1,005 and 1,890 cells say
so, on top of the standing bit-inert ruling for comparison spelling. The
direction is chosen at instruction selection from *which side is already in a
register*, so the only lever that could flip it is one that changes the
allocation at that program point. That is the same missing instrument the
seven-row "one shared allocator decision" set is waiting on; these two rows
join that set rather than the carrier queue, and they join it with their
defect localised to a single named byte, which none of the other seven have.

### Incidental: `0x10058c30 LegoOmni::Destroy` stays length-unreachable

`legomain.cpp` also defines this open row. Across all 500 `fwd`-suffix cells it
**never reached retail's length** (seed 568 vs retail 571), consistent with its
membership in the 15-row length-unreachable set. Its length deficit is not
carrier-reachable in this family.

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

> **§0 supersedes items 1 and 3 of this list.** (1) was already done before
> this table was written and the corpus is now exhausted at the object level;
> the productive move is a tip-text re-sweep, not another corpus read.
> (3) is no longer true: `pad_shape` has landed a row —
> `0x100574a0 RemoveActor` at `pad-10-29`, 2026-08-16.

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
