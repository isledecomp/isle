# BETA10 archaeology ledger

The debug images in `legobin/` (BETA10.DLL, ALPHA.DLL) are unoptimised builds:
statement order, named locals, un-inlined calls and frame-slot order all
survive. That makes them a **source oracle** for rows the carrier/generator
sweeps have sealed — the channel the sweep campaign ledger calls
"text archaeology".

Instrument: `tools/beta_disasm.py <va> [image] [max-instrs]`.

**Coverage: 41 of the 81 open LEGO1 rows carry a `// FUNCTION: BETA10 0x...`
annotation.** Those are the rows this channel can speak to.

## What the oracle can and cannot say

- It **can** settle: how many locals a function had, their declaration order
  (debug allocates frame slots in declaration order), statement order, whether
  a value was a named local or a repeated expression, and which call arguments
  were used.
- It **cannot** speak to residue that lives inside an *inlined* template body:
  the beta does not inline. `LegoPathBoundary::RemoveActor` (0x100574a0) is the
  worked example — the beta is a bare `call erase`, so the −5 byte residue in
  retail's inlined `set::erase` is out of its reach. Do not spend the read.
- The beta is an **earlier source revision**. Where it disagrees with a retail
  measurement, retail wins. See MxDSBuffer below.

## Rows read so far

### 0x100c6fa0 MxDSBuffer::FUN_100c6fa0 — beta 0x101582f2
Retail residue is a two-instruction transposition (nd=4, length-exact 234).
Full mechanism and sealed negatives: `project-volatile-read-order-lever`.
Beta findings and their verdicts:
- else-branch is `mov eax,[ebp-4]` ⇒ the source says `return current;`, **not**
  an alias local. Kills the alias-variable reading as authentic source.
- Beta has three frame slots (this, current, switch temp) and **no slot for
  `size`**; it reads `[current+4]` twice.
- **But** writing the expression twice at /O2 costs an extra volatile read of
  `current` (`mov ebx,[esp+0xc]` where retail has `mov ebx,eax`) → 237 bytes.
  Retail reuses the value, so retail's source **does** have the `size` local.
  The beta is an older revision here. Row left pristine at 234/nd=4.

### 0x1009f490 LegoAnimScene::CalculateCameraTransform — beta 0x10181a83
Ours 1074, retail 1121 (−47), 304 vs 320 instructions.
- Beta **confirms** the `case 2:` oddity our source flags with
  "Seems to be unused": the beta stores the `Interpolate` result to a slot and
  then passes `m_rotationKeys[i].GetZ()` to `RotateZ` anyway. Our text is
  faithful; do not "fix" it to `RotateZ(z)`.
- ~~Live lead: the first three frame stores go to different slots than retail.~~
  **RETRACTED (lane ARCH, 2026-08-16).** The slot *assignment* is already
  retail's; only the *order* of three independent stores differs. Decoded
  from the object: every one of the seven locals lands on retail's offset —
  `column2 esp+0x0c`, `column0 esp+0x20`, `tempTranslation esp+0x34`,
  `column3 esp+0x48`, `column1 esp+0x50`, `tempMatrix esp+0x98`,
  `original esp+0xe0` — and the three divergent instructions are the same
  three stores `{[0x54]=edx, [0x50]=ecx, [0x20]=ecx}` emitted in a different
  sequence. There is nothing to reorder. See "The /Od slot rule is not
  declaration order" below.

### 0x1009f490 — what the row actually is (lane ARCH, 2026-08-16)
**All 47 missing bytes are ONE C2 inline accept/decline bit at
`legoanim.cpp:277`.** Retail *calls* `LegoAnimNodeData::Interpolate`
(`call 0x100a0b00` at `0x1009f818`); we expand it inline and then DCE the whole
expansion because `z` is unused. Call census: ours 17 calls, retail 18 — the
single missing one is Interpolate. Retail's 18-instruction block at body
offset 870..915 (`i*12`, `&key[i]`, `&key[i+1]`, both `GetZ()`, `call`,
`fstp st(0)`, `add esp,0x14`) is 49 bytes; the row's whole deficit.
- Our source text is **confirmed correct** by a beta call-site census:
  the beta calls Interpolate from exactly 7 sites (3 in `GetTranslation`,
  3 in `GetScale`, 1 in `CalculateCameraTransform`) — precisely our 7.
- `inline` on Interpolate is **required** and must not be removed: retail
  inlines 2 of the 3 `GetScale` sites (only one call survives, at
  `0x100a04a4` inside `CreateLocalTransform`), which only a marked-inline
  function can do.
- This is a **third anchor for [[project-inline-budget-model]]**, and it points
  the opposite way from the 2026-08-02 reading: at this site **we ACCEPT where
  1997 DECLINED**, i.e. our budget here is *larger*.
- Even with the bit flipped the row would not reach 1.0 on its own: it also
  carries three re-ordered prologue stores, an `i`/`old_index` frame-slot
  exchange (`esp+0x2c`/`esp+0x30`) and a tail register renaming. Those may be
  downstream of the inline decision (retail's `case 2` holds an extra live
  value in `edi`), but that is unproven.

## The /Od slot rule is NOT declaration order — measured, decisive

The channel's founding premise ("debug builds allocate stack slots in
declaration order, so the beta's frame decodes the 1997 declaration list") is
**false for anything but a run of plain scalars.** Measured by compiling a
probe with the real `MSVC420/wine/x86/cl` at `/Od`:

    caseA: int a,b,c,d (plain, uninitialised, assigned in order)
      -> -4, -8, -0xc, -0x10.  Strict declaration order.  RULE HOLDS.

    caseB: Big big1; Small small1; int i; Small small2; Big big2; int j;
      -> big1 -0xa0, small1 -0x54, i -0x48, small2 -0x5c, big2 -0x44, j -0x4c
      i.e. top-down:  big2, i, j, small1, small2, big1

    caseC: the SAME six locals in EXACTLY REVERSED declaration order
      -> top-down:  big2, i, small1, j, small2, big1

`Big` is a 0x44-byte class with a ctor, `Small` an 8-byte class with a ctor.
**Reversing the entire declaration order changed the layout by ONE swap out of
six.** The packing is always gapless, but the order is dominated by something
that is not declaration order (it tracks the identifier set, i.e. C1's symbol
table walk). Consequences:
- The beta frame **cannot** recover 1997's declaration order. It still recovers
  the local **SET** (how many locals, of what sizes) and, through the order of
  the emitted initialisers, the **statement** order — those remain sound.
- Three live confirmations in real bodies, all with contiguous gapless packing
  and no monotone relation to source order: `CalculateCameraTransform`
  (beta frame `original -0x48, column2 -0x50, column0 -0x58, translationIndex
  -0x5c, column1 -0x64, tempMatrix -0xac, column3 -0xb4, tempTranslation
  -0xc8` — `column0..3` are *initialised from* `tempMatrix`, so `tempMatrix`
  cannot be sixth in any reading), `LegoLOD::Read`, `CopyTransform`.
- Correction to [[project-beta-frame-oracle]]: "`-4` = first declared is
  reliable" also fails once class types are present (caseB's first-declared
  `big1` gets the *deepest* slot; caseC's first-declared `j` gets a middle one).

## Declaration order at /O2: three straight nulls (do not re-run)

Every probe below was a real gated build (`isle_build.py`, LEGO1 4853/4934
before and after) and produced a **bit-identical** body:
- `0x1009f490` — hoisting `LegoFloat z` and `LegoU32 count` out of the switch
  into the block's declaration run, and splitting `count`'s initialiser from
  its declaration: inert.
- `0x1009f490` — swapping `LegoU32 old_index` / `LegoU32 i`: inert. The
  `esp+0x2c`/`esp+0x30` exchange does **not** follow declaration order.
- `0x100aa510 LegoLOD::Read` — moving `LegoU16 numVertices` ahead of
  `LegoU32 numPolys` (aimed at retail's 2-misaligned `numPolys` slot): inert.
- `0x100a12a0 TextureImpl::SetImage` — swapping `Result result` /
  `void* appData` (the row is a textbook callee-saved exchange, `ebx`↔`ebp`):
  inert. Step 3.5 explains it: the *other* member of the exchanged pair is the
  vtable temporary, not a named local.

## Interpolate's body: two callee source forms tested, both cost rows

`LegoAnimNodeData::Interpolate` is at 1.0 with the current two-line form.
Neither rewrite flips the `CalculateCameraTransform` inline bit (still 17
calls, still 0.8896), and both break rows:
- Beta-shaped evaluation order — the beta at `0x10180e00` computes
  `(p_time - key1.GetTime()) * (v2 - v1)` into its one local, then divides —
  written as `delta = (p_time - p_key1.GetTime()) * (p_value2 - p_value1);
  return p_value1 + delta / (...)`: **−3 rows** (Interpolate .75,
  CreateLocalTransform, GetTranslation).
- Two extra named temporaries (`time1`, `time2`) holding the `GetTime()`
  reads, arithmetic bit-identical, aimed at raising the callee's
  pre-optimisation IL cost: **−5 rows** (adds LegoAnimNodeData::Read and
  GetRotation to the above).
So the /Od evaluation order of an FP expression is **not** evidence about the
source expression; retail's own body is, and it already matches ours.

## BETA10 annotations are not all correct — verify before spending a read

`legoanim.cpp:1026` annotates `LegoAnimNodeData::Interpolate` as
`BETA10 0x1017f7c3`. That address is **`LegoAnim::~LegoAnim`** (vtable store,
`delete[]` loop over 8-byte entries, EH unwind funclet). The real beta
`Interpolate` is **`0x10180e00`**, proved by following the call from the beta's
own `CalculateCameraTransform` (`call 0x10180e00` at `0x10181eb2`) and by its
body being exactly the interpolation arithmetic. `legoanim.cpp:1046`
(`LegoAnim::LegoAnim` = `BETA10 0x1017f8cc`) is also wrong — that body calls
`0x1017f92e`, which the file annotates as `LegoAnim::~LegoAnim`.
**Method: never trust the annotation alone. Confirm structurally, or reach the
callee by following a call from a body you have already confirmed.**
(Spot-checked good: `0x10181a83` CalculateCameraTransform, `0x1017df90`
LegoAnimKey::LegoAnimKey, `0x1018d15d` LegoLOD::Read, `0x100507e0`
CopyTransform.)

## Rows read and classified this pass (lane ARCH, 2026-08-16)

| row | score | verdict |
|---|---|---|
| `0x1009f490` CalculateCameraTransform | .8896 | **C2 inline accept/decline bit** at legoanim.cpp:277 (47/47 bytes) + colour |
| `0x100a84a0` LegoROI::Read | .9277 | allocator/scheduler colour: two arg-load pairs transposed, three `cmpdir`s, `esi`/`ebx`/`edi` renames, and one reload of `textureName` (the whole +3) |
| `0x100aa510` LegoLOD::Read | .7268 | **pure frame-slot colour**, 571 vs 571 instructions, opcode-for-opcode identical. Retail's packer *overlaps* `numNormals` (`ebp-0x2c`) with `numPolys` (`ebp-0x2a`) — disjoint live ranges, 2-byte overlap — which is where the 2-misalignment and the +4 frame come from. Not a source construct. |
| `0x1006b140` CopyTransform | .8149 | colour; `mn` sits at `ebp-0x14` for us and `ebp-0x90` for retail, plus a 4-byte shift of three slots and two reload instructions (the −7). Beta confirms our statement order exactly (ctor order: mn, inverse, local2world, roiTransforms, i). |
| `0x1006fda0` Infocenter::HandleKeyPress | .7933 | colour. The entire −8 is `eax`↔`ecx` in the `e_playCutscene` case: retail puts the constant `1` in `ecx`, so it must rematerialise `mov eax,1` before `ret` (5 bytes), plus a 3-byte jump-table alignment pad. Retail is *longer* for a register-choice reason; no work differs. |
| `0x100bd020` MxBitmap::BitBltTransparent | .7470 | colour. 415 vs 415 bytes, 166 vs 166 instructions; `eax`↔`ecx`, `eax`↔`ebx`, and retail holds a base in `edx` where we re-read `[ebp+…]`. |
| `0x100a12a0` TextureImpl::SetImage | .6667 | colour. 83 vs 83, 39 vs 39; `ebx`↔`ebp` exchange plus one scheduling shift of the `pImage` load. |

**Six of the seven are allocator/scheduler colour with zero text content.** The
one that is not is an inline decision, not a text form.

## THE CALL CENSUS: only THREE of the 81 open rows have a wrong call graph

Zero-build screen, run over **all 81** open LEGO1 rows (the oracle corpus in
`<scratchpad>/bench/oracles-v2.json` covers every one of them): disassemble
ours and retail, count direct and indirect calls. A row whose call counts match
cannot have a function-set or inline defect — its residue is register/stack
colour, scheduling, or code *inside* an inlined body. A row whose counts differ
has a real structural defect and, per
[[feedback-function-set-defects-always-land]], is worth funding.

**78 of 81 rows carry retail's exact call graph.** The three that do not:

| row | dcall ours/retail | len ours/retail | what differs |
|---|---|---|---|
| `0x1009f490` LegoAnimScene::CalculateCameraTransform | 3/4 | 1074/1121 | retail **calls** `LegoAnimNodeData::Interpolate` (`0x100a0b00`) at `legoanim.cpp:277`; we expand it and DCE the result |
| `0x100a4420` OrientableROI::OrientableROI | 4/5 | 520/514 | retail **calls** `Vector3::Vector3` (`0x1001d150`) for the sub-object at `this+0xa8`; we expand it to `mov [ebx],vtbl` / `mov [esi+0xac],eax`. Retail calls `Vector2::Vector2` (`0x1000c0f0`) 4× in both. |
| `0x10061010` LegoAnimationManager::FUN_10061010 | 16/15 | 717/731 | **opposite direction** — retail *inlines* the `MxListEntry` constructor (`mov [edi],eax` / `mov [edi+4],esi` / `mov [edi+8],0`, retail offset 511) where we emit `push 0; push esi; push eax; mov ecx,edi; call` (ours offset 500) |

All three are **one C2 inline accept/decline bit**, and they do not agree on a
direction: two say our budget is *larger* than 1997's, one says *smaller*.
Together with the `act3actors` anchor this gives
[[project-inline-budget-model]] **four** named, byte-exact anchors — and the
`0x10061010` one lands directly on the five-site `MxListEntry` validation set
that model already names.

**Corollary for the endgame**: the function-set channel over the open set is
exactly these three rows. Every other open row's defect lives below the call
graph. Do not go looking for missing or extra calls anywhere else — this screen
is exhaustive and cheap enough to re-run after any change.

*Method warning*: classify a call as indirect by looking for `[` in the operand,
not by "does the target print as `0x…`". Capstone prints an unrelocated
`call rel32` whose target lands at offset 0 as `call 0`, and a naive
`startswith("0x")` test miscounts those as indirect — that bug manufactured six
phantom deltas (ViewManager::ManageVisibilityAndDetailRecursively,
Act3::TriggerHitSound, LegoROI::Read, two `_Tree::_Erase`s) before it was found.

## Operational note: overlay anchors reach into function bodies

`repin_overlay.py` refuses ("operation #N is missing from its clean input")
whenever an edit falls inside an overlay op's **32-token-before / 32-token-after**
context window — which is wide enough to cover a whole small function.
Two seats hit during this pass:
- `legoanim.cpp` op **#1** seats immediately before
  `inline LegoFloat LegoAnimNodeData::Interpolate`; its window covers
  `LegoFloat delta = p_value2 - p_value1; return`. **Any edit to Interpolate's
  body needs the anchor re-cut.**
- `tglrl40.cpp` op **#5** seats inside `ViewportPickImpl`'s body, one token
  after its `{`; its window covers `TextureImpl::SetImage`'s declaration block.
Re-cutting is legitimate bookkeeping — the donor keeps its seat, only the
context sha (and, for `after_newline` seats, the two line shas) is recomputed —
but it is a manifest edit and must be done deliberately, never to paper over a
seat that actually moved. Verify the recomputed signature is unique and that
the same physical newline is still selected.

## Sealed negatives from this pass (do not re-run)

- **Relational operand order is not a source lever.** MSVC 4.2 canonicalises
  it. `p_data == current` ≡ `current == p_data` (byte-identical); and
  `m_width <= p_x` ≡ `p_x >= m_width` on 0x100b26f0 AlphaMask::IsHit
  (byte-identical). A `cmp A,B; jae` vs `cmp B,A; jbe` pair is therefore a
  **register-assignment** difference, i.e. allocator class — not text.
- **`MxU8* volatile current` is load-bearing** in FUN_100c6fa0. Removing the
  `volatile` collapses the body 234 → 162 bytes. It is not a cleanup target.

## Zero-compile row readings, 2026-08-16 (main loop)

Six open rows read instruction-by-instruction with relocations normalised
(`bench/fulldiff.py`). Recorded so no future wave re-reads them. None of these
is a text target; the class is given with the evidence that fixes it.

| row | len | class | evidence |
|---|---|---|---|
| 0x100ba7f0 MxDisplaySurface::Create | 660=660 | **schedule(reordered)** | Exactly one instruction moves. Ours `sub eax,[esi+8]; mov [esp+0x84],0x6040; inc eax`; retail `sub; inc eax; mov [esp+0x84],0x6040`. Both builds hoist the constant `ddsCaps.dwCaps` store up into the width arithmetic; they differ by one slot. Source order is already dwFlags→dwWidth→dwHeight→ddsCaps, so source order is not what places it. |
| 0x1009a8c0 LegoWEGEdge::LinkEdgesAndFaces | 1494=1494 | **colour** | Whole residue is `add ecx,4; add eax,8` vs `add ecx,8; add eax,4`, twice. Two induction variables, opposite register assignment. No operation differs. |
| 0x100b26f0 AlphaMask::IsHit | 101=101 | **colour** | `cmp eax,esi; jae` vs `cmp esi,eax; jbe` — same condition, operands reversed. Rewriting the source as `m_width <= p_x` is byte-identical (measured): MSVC canonicalises, so this is register assignment. |
| 0x1006ed90 Infocenter::Create | 380 vs 381 | **colour** | Retail inserts `mov ecx,eax` and tests `ecx` where we test `eax`; later `mov ecx,[eax+0x74]` vs `mov eax,[ecx+0x74]`. Register roles swapped around the `GetState` result. |
| 0x1003d170 FindSoundByKey | 282 vs 281 | **cmpdir → shape grid** | `cmp ebx,[_Nil]` vs `cmp [_Nil],ebx` inside the inlined `_Tree` sentinel test, plus a spill-vs-register choice for the `find` result. Same family as `_Tree<LegoPathCtrlEdge*>::_Ubound`, which closed on `declaration_shape` state 124 after 1,681 extern states. **Sweep the shape grid, do not read the text.** |
| 0x100c6fa0 MxDSBuffer::FUN_100c6fa0 | 234=234 | **PERMUTED, live** | Two-instruction transposition; full mechanism, six tested forms and the remaining blocker are in the section above. |

Method note: `fulldiff.py` originally showed dozens of false differences on
every row because our object stores `0` where retail stores the linked address.
**Normalise call/jmp targets and any immediate >= 0x100000 on both sides before
diffing**, or the relocation noise buries the real residue.
