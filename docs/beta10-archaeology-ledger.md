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

## THE CALL CENSUS: six of the 81 open rows have a wrong call graph

Zero-build screen over **all 81** open LEGO1 rows. **Compare call TARGETS, not
call counts** — an inline accept/decline hides behind equal counts whenever the
inlined body itself contains a call. Run it on the two *linked* images (ours at
the report's `recomp` address, retail at its `address`) so relocations and
mangling never enter, translate every direct target into one namespace through
the report's own `recomp -> address` map, collapse intra-body targets (MSVC
unwind funclets) to `<self>`, and compare the multisets.

**75 of 81 rows carry retail's exact call graph** — their residue is
register/stack colour, scheduling, or code *inside* an inlined body. The six
that do not, every one a single C2 inline accept/decline bit:

| row | what differs |
|---|---|
| `0x1009f490` CalculateCameraTransform | retail **calls** `LegoAnimNodeData::Interpolate` at `legoanim.cpp:277`; we expand it and DCE the result (−47 B) |
| `0x100a4420` OrientableROI::OrientableROI | retail **calls** `Vector3::Vector3` for the sub-object at `this+0xa8`; we expand it (+6 B) |
| `0x10084030` LegoCharacterManager::CreateActorROI | retail **calls** `Vector3::Vector3` ×2; we expand both — visible only as `Vector2::Vector2` ×2 on our side, because our expansion leaves the nested base-ctor call behind |
| `0x100417c0` Act3Brickster::FUN_100417c0 | same, ×1 of its 3 sites (act3actors.cpp — another lane's TU) |
| `0x1003cf20` ~LegoCacheSoundManager | retail **calls** `~LegoCacheSoundEntry`; we expand it, and the expansion's own `operator delete` keeps the count equal — the counterexample that forced this screen to compare targets (+16 B) |
| `0x10061010` FUN_10061010 | **opposite direction** — retail *inlines* the `MxListEntry<LegoTranInfo*>` ctor; we call it (−14 B) |

*Method warning*: classify a call as indirect by looking for `[` in the operand,
not by "does the target print as `0x…`". Capstone prints an unrelocated
`call rel32` whose target lands at offset 0 as `call 0`, and a naive
`startswith("0x")` test miscounts those as indirect — that bug manufactured six
phantom deltas before it was found.

## THE PER-CALLEE SITE CENSUS — what the bit actually is

Counting rows understates the evidence. Take one callee and enumerate **every**
call site in both linked images, naming each caller by its annotated row
(`<scratchpad>/arch/sitecensus.py`). Two callees, fully enumerated:

**`Vector3::Vector3(float*)` (`0x1001d150`) — retail 28 call sites, ours 24.**
We reproduce retail's decision at **24 of 28** sites (LegoWorld::LegoWorld,
LegoCarBuild ×2, Act1State ×6, FindPath ×3, LegoAct2::Notify, LegoAct2::
CheckBricksterIsLoose ×7, FUN_100648f0 ×2, FUN_100417c0 ×2) and expand at 4.
Retail **declines at all 28** — its rule for this callee is uniform, ours is
not.

**`MxListEntry<T>::MxListEntry` (one body, four template instantiations) — 6
call sites.** Both images call at LegoPhonemePresenter::StartingTickle,
LegoAnimPresenter::AppendROIToScene and MxRegion::AddRect ×3. Retail *expands*
the sixth (FUN_10061010) and therefore emits **three** out-of-line copies of the
body; we decline there and emit **four**. (Correction to
[[project-inline-budget-model]]: this is not "retail declines four and inlines
one" of a single callee — the five declines are spread over four distinct
instantiations, and the site retail expands is the only site of *its*
instantiation.)

**Three facts follow, and together they fix the model's shape:**
1. **The bit is per SITE, not per callee.** `Act3Brickster::FUN_100417c0`
   contains three `Vector3::Vector3` sites; we expand the first and decline the
   second and third, inside one function, in one compile.
2. **It is not a global aggressiveness scalar.** Over the four callees we
   over-accept at 6 sites and under-accept at 1. A single scalar cannot produce
   both signs.
3. **Retail is the *uniform* side and we are the ragged one.** For
   `Vector3::Vector3` retail's answer is "decline" at 28/28; our 4 acceptances
   are the anomaly, not a different threshold consistently applied.

A useful negative for source-shaping: **all three `Vector3::Vector3` sites we
can name are implicitly generated ctor chains** — the sub-objects of
`m_world_bounding_box`/`m_world_bounding_sphere`/`m_world_velocity` in
`OrientableROI`, and of the local `BoundingSphere`/`BoundingBox` in
`CreateActorROI`. There is no source statement at those sites to reshape, which
is why the row reads as "the inline ladder".

## THE CARRIER AXIS DOES NOT REACH THE INLINE BIT — 8,963 cells, zero flips

The campaign ledger names accumulated declaration/IL state on the containing TU
as the live axis for inline-order rows, and `pad_shape`'s 99x99 grid had never
been swept as a carrier. It is now, on three of the four anchors, in two
generator families.

Instrument: `<scratchpad>/arch/sweep.py` — compile-only, ~0.2 s/cell. It renders
the carrier header exactly as `isle_build.py` does (`entropy.generate_pad_shape`
/ `entropy.generate_shape`), force-includes it into the TU's real compile
command from `compile_commands.json` with `/FI`, compiles to a private `/Fo`,
pulls the target COMDAT out of the object and counts the **REL32 relocations
naming the callee**. That relocation count *is* the accept/decline bit, read
without a link and without reccmp. Positive control: pointed at
`Vector2::Vector2` in the same body it reports 4, the known truth.

| row | family | cells | bit flipped | distinct body lengths |
|---|---|---|---|---|
| `0x1009f490` CalculateCameraTransform | `pad_shape` 1..99 x 1..99 | 7,613 | **0** | {1074} — retail is 1121 |
| `0x1009f490` | `declaration_shape` (full domain) | 411 | **0** | {1074} |
| `0x100a4420` OrientableROI::OrientableROI | `pad_shape` full range, step 7 | 165 | **0** | {520} — retail is 514 |
| `0x100a4420` | `declaration_shape` (full domain) | 364 | **0** | {520} |
| `0x10061010` FUN_10061010 | `pad_shape` full range, step 7 | 124 | **0** | {717, 725} |
| `0x10061010` | `declaration_shape` (full domain) | 286 | **0** | {717, 725} |

**8,963 carrier states, zero flips in either direction.** And the shape of the
negative matters more than the count:

- On `CalculateCameraTransform` the carrier **does** reach codegen — the body
  takes two distinct forms across the grid (nd 308 for 6,716 cells, nd 314 for
  897) — but its **length is 1074 in every single cell**. Flipping the bit
  would add ~47 bytes. The axis moves the colouring and cannot touch the
  inliner.
- On `OrientableROI::OrientableROI` the carrier does not reach the function at
  all: **all 529 cells across both families produce the byte-identical body**
  (len 520, nd 290). Nothing to search there.
- On `FUN_10061010` the carrier moves the body by 8 bytes (717 -> 725, and 725
  is *closer* to retail's 731) in 28 of 410 cells, yet the `MxListEntry`
  relocation is present in **all 410**.

**Sealed: the inline accept/decline bit is not carrier-reachable.** Two
generator families, three TUs, both directions of the defect. Combined with the
per-site census above — the bit varies *within a single caller*, at three sites
of one callee in one compile — the mechanism is downstream of anything a
force-included declaration-only header can perturb. Fund an instrument that
observes C2's decision (fresh-eyes-2 §C4), not more carrier cells.

Also sealed on the callee-source axis, from wave 1: two rewrites of
`Interpolate`'s body (see above) leave the bit untouched and cost 3 and 5 rows.
And `OrientableROI`'s and `CreateActorROI`'s sites have **no source statement at
all** — they are implicit member-ctor chains — so the source axis is empty there
by construction.

## THE MODEL — measured with the compiler's own knob (DIAGNOSTIC ONLY)

Nothing in this section is landable: `#pragma inline_depth` is exactly the
"#undef/#define-style manipulation to force codegen" the mandate forbids. It was
injected through `/FI` in a scratch harness (`<scratchpad>/arch/depth.py`), never
into the tree, and no probe here was committed. Its value is that it is a
**direct read of the variable C2 is deciding on**, which is the instrument
[[project-inline-budget-model]] says is missing.

Baseline row = no header; retail column is what we are trying to reach.

    OrientableROI::OrientableROI            retail: 514 B, Vector3 x1, Vector2 x4
      default / depth>=4   520 B   Vector3=0  Vector2=4
      depth(0)             757 B   Vector3=0  Vector2=0
      depth(1)             439 B   Vector3=1  Vector2=0
      depth(2)             514 B   Vector3=5  Vector2=1      <- length trap
      auto_inline(off)     520 B   (inert)

    CalculateCameraTransform                retail: 1121 B, Interpolate x1
      default / depth>=4  1074 B   Interpolate=0
      depth(0)             926 B   Interpolate=1
      depth(1)            1214 B   Interpolate=0
      depth(2)            1212 B   Interpolate=0
      auto_inline(off)    1074 B   (inert)

    FUN_10061010                            retail: 731 B, MxListEntry x0
      default / depth>=4   717 B   MxListEntry=1
      depth(0)             482 B   MxListEntry=0
      depth(2)             664 B   MxListEntry=2
      auto_inline(off)     717 B   (inert)

**What this establishes.**

1. **The bit is the inliner's depth-limited budget, and it is live** — it moves
   under `inline_depth` on all three anchors, in both directions. It is not a
   source form and not a carrier state.
2. **No global depth value is 1997's, on any anchor.** Retail's answers are
   per-site *mixtures* a uniform depth cannot express: `OrientableROI` needs
   four sites expanded one level (leaving `Vector2::Vector2` calls) and a fifth
   declined outright (leaving a `Vector3::Vector3` call), and no single depth
   produces that pair. This is the same conclusion the per-site census reached
   from the other side, now proved with the compiler's own control.
3. **The three anchors are three different depths of disagreement**, which is
   why no one scalar covers them:
   - `OrientableROI` — a **depth-0** decline. Retail declines the callee
     outright at one of five sibling sites; we expand it, and at that site we go
     a level *further* than at the other four (full expansion, no `Vector2`
     call left).
   - `CalculateCameraTransform` — a **depth-1** decline. Restricting to
     `inline_depth(1)` or `(2)` does **not** stop us expanding `Interpolate`;
     only `depth(0)` does. Retail declines a depth-1 leaf expansion we accept.
   - `FUN_10061010` — a **depth-2** accept. The `MxListEntry` ctor site is
     itself inside an inlined body (at `depth(0)` the call vanishes because its
     enclosing callee stops being expanded). Retail expands it there; we decline.
4. **`/Ob1` is in force.** `#pragma auto_inline(off)` is inert on all three, so
   every expansion in dispute is of an explicitly `inline`-marked callee. There
   is no "automatic inlining" component to tune.
5. **A length trap, freshly caught:** `depth(2)` on `OrientableROI` hits retail's
   514 bytes exactly — and is nd=246 with 147 instructions against retail's 142.
   Length is not score, again.

**Consequence for the campaign.** The accept/decline bit is per-site, lives in
C2's depth accounting, and is reachable by neither the source axis (wave 1: two
`Interpolate` rewrites, −3 and −5 rows; and two of the three `Vector3` sites
have no source statement at all, being implicit member-ctor chains) nor the
carrier axis (8,963 cells). The remaining lever would have to change what C2
counts *at one site*, which is what the sandboxed-C2 instrument was for.

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
