# Residue taxonomy — what the remaining bytes actually are

Measured 2026-08-15 night at LEGO1 4831/4933, over the **size-clean** open rows
(see [row size ledger](row-size-ledger.md); a row with a length defect is a
text problem and is excluded here). Regenerate with `bench/residue2.py`.

## Method

Compare each row's built COMDAT body against the corrected retail body from
`oracles-v2.json`, instruction by instruction, with the COFF relocation table
masking every operand byte that is an address. Relocation masking is what makes
this readable: comparing *images* instead makes every call whose target moved
look like a defect, which is displacement noise, not a codegen defect.

Each differing instruction pair is classified:

| class | meaning |
|---|---|
| `regrole` | identical mnemonic and operand *shape*, different register |
| `memoff` | identical mnemonic and registers, different displacement |
| `cmpdir` | same comparison, operands exchanged (usually with the `jcc` inverted) |
| `jcc` | conditional branch mnemonic differs, operands identical |
| `mnemonic` | different instruction |
| `immdiff` | same instruction, different immediate |
| `desync` | retail has no instruction starting at this offset — the streams have diverged in instruction *boundaries*, so everything from here is unaligned until they resynchronise |
| `other` | anything else |

`desync` is not a class of defect, it is the shadow of one: a single
length-changing difference desynchronises the rest of the decode. Read a row's
`desync` count as "this row has a structural divergence", not as N defects.

## The headline

**Register-role permutation is the single largest real defect class.** And it is
not scattered: in row after row the substitution table is a *clean permutation*
of two or three registers — the same code, computed in a different register.

```
MxRegion::AddRect             ebx→edi ×4, esi→ebx ×3, edi→esi ×5   (a 3-cycle)
ReadModelDbWorlds             edi→ebx ×9, ebx→edi ×9               (a transposition)
_Tree<MxCore*>::erase         ebx→edi ×10, edi→ebx ×7              (a transposition)
DissolveTransition            edi→ebx ×4, ebx→edi ×2               (a transposition)
Act3List::RemoveByObjectId…   edx→eax ×5, eax→edx ×2               (a transposition)
```

These rows are not *wrong*. They are the right instructions with the allocator's
ranking of two or three candidate values exchanged. MSVC 4.2's C2 ranks register
candidates by estimated benefit and breaks ties deterministically, so the
tie-break is reachable from the source — this is the same mechanism recorded
earlier as "the extra symbol changes allocator rank (which param wins the ebx
hoist)" and as "declaration POSITION is the responsive axis".

Two consequences worth acting on:

1. **A regrole-only row is a solved problem waiting for the right lever**, not an
   open reconstruction. Do not read it off from BETA10 as though the statements
   were wrong; they are not.
2. **The lever is whatever perturbs allocator rank**: local declaration order
   inside the function, the number and position of declarations ahead of it, and
   the carrier axis (declaration shapes, forward-declaration runs, extern runs,
   pad grids) which is a blunt version of the same thing. Measured negative on
   two rows so far: `MxDSBuffer::FUN_100c6fa0` holds at nd=4 across 827 carrier
   states and `LegoPartPresenter::Read` holds at nd=4 across 1098 — for those
   the carrier axis is exhausted and the text is the only channel left.

`cmpdir` is real but rare (15 sites). It is the class the wave-2/wave-3 landings
closed with an end-first comparison spelling (`end() != find()`), and it is
*not* reachable by simply reversing a relational operator — measured on
`LegoPartPresenter::Read`, rewriting `i < numROIs` as `numROIs > i` is
completely code-inert (0 of 47 bodies changed), while `i != numROIs` moves the
body. MSVC canonicalises `<`/`>` at the front end; what moves a `cmpdir` is a
change in which subexpression is *evaluated* first.

Totals across the size-clean oracled open rows: **desync** 618, **regrole** 484, **memoff** 184, **other** 149, **mnemonic** 92, **cmpdir** 15, **immdiff** 13, **jcc** 11.

| address | diffs | classes | register permutation (ours→retail) | row |
|---|---|---|---|---|
| `0x100c6fa0` | 2 | mnemonic=2 | — | MxDSBuffer::FUN_100c6fa0 |
| `0x100ba7f0` | 2 | mnemonic=1 desync=1 | — | MxDisplaySurface::Create |
| `0x1002e8d0` | 2 | cmpdir=1 other=1 | — | LegoPathActor::CheckPresenterAndActorIntersect |
| `0x1009a8c0` | 4 | immdiff=4 | — | LegoWEGEdge::LinkEdgesAndFaces |
| `0x1007ca30` | 4 | other=2 cmpdir=1 jcc=1 | — | LegoPartPresenter::Read |
| `0x100b26f0` | 4 | cmpdir=1 jcc=1 mnemonic=1 desync=1 | — | MxVideoPresenter::AlphaMask::IsHit |
| `0x100b24f0` | 5 | regrole=5 | `ax`→`dx`×3 `ecx`→`eax`×2 | MxVideoPresenter::AlphaMask::AlphaMask(class M |
| `0x1002f770` | 5 | regrole=5 | `eax`→`ecx`×3 `ecx`→`eax`×2 | LegoPathActor::UpdatePlane |
| `0x1004bd10` | 6 | regrole=6 | `edi`→`ebx`×4 `ebx`→`edi`×2 | MxTransitionManager::DissolveTransition |
| `0x100334b0` | 6 | other=4 desync=2 | — | Act1State::Act1State |
| `0x100720d0` | 7 | regrole=7 | `edx`→`eax`×5 `eax`→`edx`×2 | Act3List::RemoveByObjectIdOrFirst |
| `0x10057180` | 8 | regrole=6 other=2 | `edi`→`ebx`×5 `ebx`→`edi`×4 | _Tree<LegoAnimPresenter *,LegoAnimPresenter *, |
| `0x100d0d80` | 8 | desync=5 mnemonic=3 | — | ReadData |
| `0x10017af0` | 9 | regrole=6 desync=2 mnemonic=1 | `eax`→`ecx`×6 `ecx`→`eax`×5 | PizzeriaState::PizzeriaState |
| `0x10083500` | 9 | other=4 regrole=4 cmpdir=1 | `ecx`→`eax`×2 `eax`→`ecx`×2 | LegoCharacterManager::GetActorROI |
| `0x1002a1b0` | 10 | regrole=8 other=2 | `edi`→`ebx`×6 `ebx`→`edi`×5 | _Tree<LegoCacheSoundEntry,LegoCacheSoundEntry, |
| `0x100c3750` | 10 | regrole=10 | `edi`→`esi`×5 `ebx`→`edi`×4 `esi`→`ebx`×3 | MxRegion::AddRect |
| `0x10038380` | 11 | regrole=8 mnemonic=2 desync=1 | `edi`→`ebx`×5 `ebx`→`esi`×2 `esi`→`edi`×2 | Pizza::StopActions |
| `0x100796b0` | 12 | regrole=7 desync=3 mnemonic=2 | `edi`→`ebx`×4 `ebx`→`edi`×3 | LegoCarBuildAnimPresenter::FindNodeDataByName |
| `0x100b27b0` | 13 | desync=6 regrole=5 other=2 | `eax`→`ecx`×4 `eax`→`edi`×1 | MxVideoPresenter::Destroy(unsigned char) |
| `0x100a3b40` | 14 | regrole=11 other=3 | `edi`→`esi`×11 `esi`→`edi`×5 | TglImpl::MeshBuilderImpl::Clone |
| `0x1002aba0` | 14 | regrole=7 mnemonic=5 other=1 desync=1 | `ecx`→`edx`×5 `edx`→`ecx`×4 | LegoExtraActor::HitActor |
| `0x1007b770` | 15 | regrole=12 mnemonic=2 desync=1 | `ebx`→`ecx`×7 `ecx`→`ebx`×4 `eax`→`ecx`×2 | LegoVideoManager::Tickle |
| `0x10072ad0` | 15 | desync=9 other=5 mnemonic=1 | — | Act3::TriggerHitSound |
| `0x100a12a0` | 15 | regrole=9 desync=4 mnemonic=2 | `ebp`→`ebx`×8 `ebx`→`ebp`×3 | TglImpl::TextureImpl::SetImage |
| `0x100035e0` | 16 | desync=14 other=1 mnemonic=1 | — | Helicopter::HandleControl |
| `0x1004d330` | 17 | regrole=11 desync=6 | `edx`→`eax`×5 `eax`→`ebx`×4 `bx`→`dx`×3 | TowTrack::HandlePathStruct |
| `0x10027910` | 17 | regrole=15 cmpdir=1 jcc=1 | `ebx`→`edi`×10 `edi`→`ebx`×9 | ReadModelDbWorlds |
| `0x10085500` | 19 | regrole=12 other=5 cmpdir=1 desync=1 | `edx`→`edi`×10 `edi`→`edx`×3 | _Tree<char *,pair<char * const,LegoCharacter * |
| `0x1003f540` | 21 | regrole=16 other=2 desync=2 mnemonic=1 | `ecx`→`eax`×6 `eax`→`ecx`×6 `eax`→`ebx`×2 `ebx`→`eax`×2 | WriteDefaultTexture |
| `0x10057fe0` | 21 | desync=10 other=5 mnemonic=4 regrole=2 | `ecx`→`edx`×1 `eax`→`ecx`×1 | LegoPathBoundary::AddPresenterIfInRange |
| `0x100166a0` | 22 | regrole=18 cmpdir=2 jcc=2 | `ebp`→`ebx`×14 `ebx`→`ebp`×5 | JetskiRace::HandlePathStruct |
| `0x1002a720` | 27 | regrole=10 desync=8 memoff=8 mnemonic=1 | `eax`→`ecx`×5 `ecx`→`eax`×5 | LegoExtraActor::StepState |
| `0x10038b10` | 29 | desync=15 regrole=14 | `ecx`→`edx`×11 `edx`→`ecx`×10 | Pizza::HandleEndAction |
| `0x10040360` | 29 | desync=11 memoff=7 other=5 mnemonic=4 immdiff=1 cmpdir=1 | — | Act3Cop::FUN_10040360 |
| `0x10051ac0` | 30 | regrole=16 desync=10 other=2 mnemonic=2 | `ecx`→`edx`×6 `ecx`→`eax`×5 `eax`→`ecx`×3 `edx`→`eax`×2 | LegoAct2::SpawnBricks |
| `0x100586e0` | 30 | regrole=19 desync=5 mnemonic=4 memoff=1 cmpdir=1 | `ecx`→`eax`×6 `eax`→`edx`×4 `edx`→`ecx`×4 `ebp`→`ebx`×3 | LegoPathBoundary::RemovePresenter |
| `0x100bacc0` | 31 | desync=11 memoff=6 regrole=4 mnemonic=4 cmpdir=3 jcc=3 | `edi`→`ecx`×4 `ecx`→`edi`×2 | MxDisplaySurface::VTable0x28 |
| `0x1001d890` | 36 | regrole=35 cmpdir=1 | `edi`→`ebx`×23 `ebx`→`edi`×22 | _Tree<MxCore *,MxCore *,set<MxCore *,CoreSetCo |
| `0x100bb1d0` | 38 | regrole=27 desync=4 memoff=3 jcc=2 other=1 cmpdir=1 | `eax`→`ebx`×9 `ebx`→`edi`×9 `ebx`→`ecx`×4 `ecx`→`eax`×3 | MxDisplaySurface::VTable0x30 |
| `0x100170e0` | 45 | desync=34 mnemonic=8 immdiff=2 other=1 | — | CarRace::HandlePathStruct |
| `0x10062e20` | 48 | regrole=19 other=17 desync=7 mnemonic=5 | `esi`→`ebx`×18 `esi`→`edi`×6 `ebx`→`esi`×1 | LegoAnimationManager::FUN_10062e20 |
| `0x10084030` | 48 | regrole=30 other=8 desync=6 mnemonic=4 | `eax`→`ecx`×13 `ecx`→`eax`×12 `al`→`cl`×8 `ecx`→`edx`×4 | LegoCharacterManager::CreateActorROI |
| `0x100bd020` | 52 | regrole=26 desync=21 mnemonic=4 other=1 | `eax`→`ebx`×17 `ebx`→`eax`×6 `eax`→`ecx`×4 `edx`→`ebp`×3 | MxBitmap::BitBltTransparent |
| `0x100417c0` | 59 | regrole=27 desync=17 other=6 mnemonic=6 immdiff=2 jcc=1 | `edi`→`ebx`×7 `eax`→`ecx`×7 `ebx`→`edi`×6 `ecx`→`eax`×6 | Act3Brickster::FUN_100417c0 |
| `0x10031820` | 124 | desync=92 other=14 mnemonic=9 regrole=9 | `edi`→`ecx`×3 `ecx`→`edi`×2 `edx`→`eax`×2 `edx`→`ecx`×2 | Isle::Enable |
| `0x100495b0` | 158 | desync=104 regrole=39 mnemonic=11 other=2 immdiff=2 | `ebp`→`ebx`×7 `edi`→`esi`×7 `esi`→`edi`×6 `edx`→`ebp`×5 | _Tree<LegoBEWithMidpoint *,LegoBEWithMidpoint  |
| `0x100a50a0` | 216 | desync=104 memoff=56 other=47 regrole=7 immdiff=1 mnemonic=1 | `esi`→`eax`×4 `eax`→`esi`×3 | OrientableROI::GetLocalTransform |
| `0x100a46b0` | 223 | memoff=103 desync=100 regrole=12 other=6 immdiff=1 mnemonic=1 | `ebx`→`edx`×5 `edi`→`ebx`×5 `edx`→`esi`×4 `esi`→`edi`×1 | OrientableROI::UpdateTransformationRelativeToP |
