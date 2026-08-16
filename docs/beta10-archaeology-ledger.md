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

> **Status:** `legoanim.cpp:1026` was corrected to `BETA10 0x10180e00` on the
> lane branch, independently confirmed. This worktree predates that fix and
> deliberately does not repeat it — the finding below is the record of how it
> was found and of the method it implies. `legoanim.cpp:1046` is still wrong and
> is deliberately left alone: **do not change a BETA10 annotation you have not
> independently confirmed.**

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

**`0x10084030 CreateActorROI` is the tightest specimen in the whole class and
the best target if the bit is ever solved.** It is **2294 vs 2294 bytes and 661
vs 661 instructions**, and its entire codegen residue is *two `call rel32`
target fields* — at body offsets 100 and 1219 ours reaches `Vector2::Vector2`
where retail reaches `Vector3::Vector3`, with byte-identical code on both sides
of each call. The lengths match by luck: our expansion of `Vector3::Vector3`
emits `call Vector2::Vector2` plus the derived vtable store, and that store is
immediately overwritten by the enclosing code (`mov [ebp-0xd4], edi`), so DCE
removes it and the expansion costs exactly as much as the call it replaced.
(The row still scores .9365 rather than ~.997 because reccmp also sees our
data-address divergence, which `fulldiff.py` masks — displacement, not codegen.)

**The one uniform-rule opportunity, and why it is closed.** Unlike the
`MxListEntry` case, retail's answer for `Vector3::Vector3` *is* uniform —
decline at 28/28 — so a source form that stopped MSVC expanding it anywhere
would match retail at every site and could close three rows with no collateral.
The obvious form is "1997 did not define it in the class at all", i.e. an
ordinary out-of-line member. **Retail's own layout refutes that**: both
`Vector3::Vector3` (`0x1001d150`) and `Vector2::Vector2` (`0x1000c0f0`) sit in
the middle of runs of `scalar deleting destructor` / `ClassName` / `IsA`
bodies — the COMDAT region — not inside any TU's ordinary function run. They
were in-class inlines in 1997 exactly as they are here, and retail's compiler
simply declined all 28 while ours declines 24. (Retail also calls
`Vector2::Vector2` at 50 sites to our 47, the same defect seen from the base.)

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

**8,963 carrier states, zero flips in either direction.** (The `legoanim` grid
row above is one pass at 7,613 of 9,801 cells; the 2,188 misses were transient
wine-contention failures scattered across the grid, not a region. A second,
uncontended pass over the same grid reached 6,400 cells before it was stopped,
also with zero flips.) And the shape of the negative matters more than the
count:

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

    CreateActorROI                 retail: 2294 B, Vector3 x2, Vector2 x2
      default / depth>=8  2294 B   Vector3=0  Vector2=4
      depth(0)            1788 B   Vector3=0  Vector2=0
      depth(2)            2284 B   Vector3=6  Vector2=6
      depth(4)            2283 B   Vector3=0  Vector2=4
      auto_inline(off)    2294 B   (inert)

**What this establishes.**

1. **The bit is the inliner's depth-limited budget, and it is live** — it moves
   under `inline_depth` on all three anchors, in both directions. It is not a
   source form and not a carrier state.
2. **No global depth value is 1997's, on any of the four anchors** —
   `CreateActorROI` needs `Vector3 x2 / Vector2 x2` and no depth produces that
   pair either (`depth(2)` gives 6/6, everything >=8 gives 0/4). Retail's answers are
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

## The source axis, closed on two anchors (compile-only, nothing landed)

`<scratchpad>/arch/srcprobe.py` / `srcprobe2.py` copy the rendered `src` tree,
apply a text substitution anywhere in it, rewrite the TU's real compile command
onto the copy and read the target COMDAT back. No repo file is touched, so a
form can be judged before it is worth a gated build.

**`0x1009f490` — five further source forms, all bit-identical** (1074 bytes,
`Interpolate` relocation count 0, i.e. still expanded):
- `Interpolate` **defined in the class body** instead of out-of-line in the .cpp
- `case 2` **discarding the result** (`Interpolate(...);`, no `z`)
- `case 2` **wrapped in its own block**
- (wave 1) the beta-shaped evaluation order, and two extra named `GetTime()`
  temporaries — those two also cost 3 and 5 rows in a real build.
Six source forms, one bit, no movement.

**`0x10061010` — the source construct that governs the bit is identified, and
retail's own rows prove retail did not use it.** `FUN_10061010` reaches the
`MxListEntry` ctor through `Append -> InsertEntry -> new MxListEntry<T>(a,b,c)`,
three inline levels deep. Probing `mxlist.h`:

    baseline                                     len=717  ctor call = 1   (retail: 731, 0)
    ctor written with a member-initializer list  len=717  ctor call = 1
    ctor written with SetValue/SetPrev/SetNext   len=717  ctor call = 1
    InsertEntry: declaration split from the new  len=717  ctor call = 1
    Append: m_last read into a local first       len=717  ctor call = 1
    InsertEntry: default-construct then assign   len=722  ctor call = 0  <-- flips it

The last form **does** remove the call — the only source change found in this
whole campaign that moves an inline accept/decline bit. It is still not
retail's, and the proof is collateral rather than argument: the same header
change was compiled against `LegoPhonemePresenter::StartingTickle`, an
**exact** row, and takes it from retail's 688 bytes to 611 (its ctor call
survives; the surrounding body collapses). `LegoAnimPresenter::AppendROIToScene`
is exact on the same construct and `MxRegion::AddRect` carries three more sites.
> **So retail's `InsertEntry` constructs through `new MxListEntry<T>(a,b,c)` —
> the form the tree already has — and the `FUN_10061010` disagreement is a
> compiler decision, not a source form.** One header text cannot both keep the
> ctor call at five sites and drop it at the sixth; retail does exactly that,
> so the split is C2's, not the source's.

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

### Added by lane ARCH wave 2 (do not re-run)

- **The inline accept/decline bit is not carrier-reachable.** 8,963 cells over
  `pad_shape` (including the full 99x99 grid on `legoanim.cpp`) and the full
  `declaration_shape` domain, three TUs, both directions. Zero flips.
- **No global `#pragma inline_depth` is 1997's**, on any of the four anchors.
  (Diagnostic only — pragma-forced codegen is out of mandate for landing.)
- **`#pragma auto_inline(off)` is inert** on all four anchors: `/Ob1` is in
  force and every disputed expansion is of an explicitly `inline` callee.
- **Six source forms on `0x1009f490`** leave the bit set (callee in the class
  body, result discarded, `case 2` braced, plus wave 1's two callee rewrites).
- **`mxlist.h`: four forms inert, one flips the bit and is refuted.** Writing
  `InsertEntry` as default-construct-then-assign drops the `MxListEntry` ctor
  call, but the same header takes the **exact** row
  `LegoPhonemePresenter::StartingTickle` from 688 to 611 bytes. Retail's
  `InsertEntry` uses the three-argument ctor, as the tree already does.
- **`Vector3::Vector3` was an in-class inline in 1997 too** — it and
  `Vector2::Vector2` sit inside retail's COMDAT run, not in any TU's function
  run. The "define it out-of-line so MSVC can never expand it" repair is
  refuted by retail's own layout.
- **Length is not score, again**: `depth(2)` on `OrientableROI::OrientableROI`
  reproduces retail's 514 bytes exactly at nd=246 and 147 vs 142 instructions.

## WAVE 3 — PRICING THE CHANNEL: what remains once the bit is fixed

Two wave-2 claims of mine were wrong and are corrected first.

1. **"`0x10084030 CreateActorROI`'s entire codegen residue is two `call rel32`
   target fields" is WRONG.** I read 30 lines of a 198-line `fulldiff.py`
   output and generalised from the head of it. Measured properly against retail
   with our relocation fields masked: **`len 2294 = 2294, masked nd = 80`**,
   SHAPE 98.94 / STRUCT 98.94 / EXACT 93.95, first divergence at offset **793**
   — nowhere near the ctor sites at 100 and 1219 — running in clusters to 1797.
   It is an allocator-colour row that also carries a call-target difference.
2. **"Retail declines `Vector3::Vector3` at all 28 sites, so its rule is
   uniform" is WRONG.** 28 is the count of *observable* declines; acceptances
   are invisible because they emit no call. `OrientableROI::OrientableROI` has
   five `Vector3` sub-object sites and retail calls at exactly one, so retail
   **accepts at four of five there**. The rule is not uniform, and the
   "make it non-inlinable everywhere" repair was never available on those
   grounds either.

### Method

`<scratchpad>/arch/forced.py` compiles the TU from a private copy of the
rendered `src` tree with an edit that forces retail's decision at the target
site, then scores the COMDAT with `<scratchpad>/arch/residue.py` — masked nd
(our relocation byte ranges blanked on both sides, length delta charged) plus
Lane FIN's SHAPE/STRUCT/EXACT. Nothing is written to the repo.

**A caveat that decides three of the six cells.** `adiff` normalises a direct
call's target to `T`, and a `call rel32` field is a relocation, so it is masked
in nd too. Wherever our expansion costs **zero instructions** — because the
expansion's derived-vtable store is dead and DCE removes it — the inline bit is
*invisible to every metric*, and "residue after the bit is fixed" is simply the
row's current residue. That is exactly the case for `0x10084030` and
`0x100417c0`.

### The table

| row | now: len / masked nd / SHAPE·STRUCT·EXACT | residue once the bit is fixed | verdict |
|---|---|---|---|
| `0x1003cf20` ~LegoCacheSoundManager | (Lane B10) | **nd 0** — 258/258, 100.00·100.00·100.00 | **channel wins the row** |
| `0x1009f490` CalculateCameraTransform | 1074/1121 · 268 · 97.12·94.23·93.59 | **nd 0** — 1121/1121, 100.00·100.00·100.00, *measured on a forced build* | **channel wins the row** |
| `0x100a4420` OrientableROI::OrientableROI | 520/514 · 222 · 95.04·95.04·95.04 | the bit **plus one instruction** — see below | near; worth a look |
| `0x100417c0` Act3Brickster::FUN_100417c0 | 2875/2875 · **132** · 98.08·97.96·94.96 | **nd 132, unchanged** — bit is instruction-free and masked | allocator pile |
| `0x10084030` CreateActorROI | 2294/2294 · **80** · 98.94·98.94·93.95 | **nd 80, unchanged** | allocator pile |
| `0x10061010` FUN_10061010 | 717/731 · **435** · 93.08·**68.26**·63.48 | nd 432 on the assignment proxy; STRUCT still 67.46 | allocator pile, deep |

### `0x1009f490` is the result of this wave

Dropping `Interpolate`'s definition from the TU (declaration kept, so every site
becomes a real call — retail's decision at this site, without touching global
inline depth) produces **1121 bytes against retail's 1121, masked nd 0, and
SHAPE = STRUCT = EXACT = 100.00.** The inline accept/decline bit is the row's
*only* defect; the three re-ordered prologue stores and the `i`/`old_index`
slot exchange recorded in wave 1 were **downstream of it** and resolve when it
resolves.

> **The forcing edit is a diagnostic, not a candidate.** Deleting the definition
> makes all seven sites in the TU call, and retail inlines five of them, so
> `GetTranslation`/`GetScale`/`CreateLocalTransform` would break. What the
> measurement establishes is the *price*: this row is worth one C2 bit and
> nothing else.

### `0x100a4420` decomposes into the bit plus one instruction

Its aligned SHAPE diff has exactly **two** divergent regions:
- **offsets 168–208** — the bit: retail's `mov [r],R / lea r,[r+0xa8] / push r /
  mov r,r / call T` against our two-instruction expansion, plus the neighbouring
  vtable and `+0xc4` stores reordered around it;
- **offsets ~448–461** — one `mov dword ptr [ebp-4], 0xffffffff` (the EH state
  store) scheduled ~13 bytes earlier in retail.
No surgical force exists for this row — dropping `Vector3`'s in-class body
forces all five sibling sites to call and lands at 508 B / nd 196, and
`inline_depth(2)` produces a different profile again (`Vector3=5`) — so the
"after" cell is a **decomposition of the aligned diff, not a forced
measurement**. Correcting wave 2: the `depth(2)` nd=246 I quoted said nothing
about the bit, because nd is meaningless across a length change and that
variant had the wrong inline profile anyway.

### Verdict

**The channel is worth two rows, not six.** `0x1003cf20` is already closed on
it by Lane B10 and `0x1009f490` is measured at nd 0; `0x100a4420` is one
scheduling instruction behind. The other three are allocator rows that happen to
carry an inline difference, and on two of them the difference costs literally
zero bytes. Do not fund `0x10084030`, `0x100417c0` or `0x10061010` on this
channel — their residue is unchanged by the bit.

## WAVE 4 — THE INCLUDE AXIS: 82 real-source states, zero flips

The carrier sweeps perturbed C2's declaration state with *synthetic* classes.
This wave perturbed it with **real headers** — the TU's own include order and
set — which carry real inline bodies and real symbol-table volume. Judged on
**whole-body identity** of the target COMDAT, not merely on whether the bit
flipped: "inert" below means byte-identical output.

Target: `0x1009f490`, baseline body `b0a0bc0f4e46`, len 1074, 0 relocations
naming `Interpolate@LegoAnimNodeData`.

**1. Include ORDER — 40 legal permutations, all byte-identical.**
`legoanim.cpp` has five includes, so 120 orders. **80 are not legal source**:
`mxgeometry/mxquaternion.h` needs `MxU32`, which arrives via `legoanim.h`, so
every order that puts the quaternion header first fails with
`C2501: 'MxU32' : missing decl-specifiers`. Of the 40 that compile, **all 40
produce the identical body** — same sha, same length, same relocation profile.

**2. Include SET — 37 legal states, all byte-identical.**
- *Removal*: 15 drop-one/drop-two cases, of which exactly **one** is legal —
  `<limits.h>` is unused — and it is byte-identical.
- *Direct naming*: six headers that arrive transitively today (`decomp.h`,
  `misc/legostorage.h`, `misc/legotree.h`, `realtime/vector.h`,
  `realtime/matrix.h`, `mxgeometry/mxgeometry3d.h`) x six insertion positions =
  **36 cells, all byte-identical**. Naming one *after* the header that already
  pulls it in is a preprocessor no-op, so the cells that could matter are the
  early ones — and those are inert too.

**3. Definition placement — 5 positions, and the one that moves is worse.**
Moving `inline LegoFloat LegoAnimNodeData::Interpolate` to sit before
`LegoAnimKey::LegoAnimKey`, `CreateLocalTransform`, `GetTranslation` or
`FindKeys` is **byte-identical**. Moving it *before its own first call site*
(ahead of `CalculateCameraTransform`) is the only cell in this wave that
changes anything — and it still inlines: same length 1074, still 0 callee
relocations, and measurably **worse**, masked nd 268 -> 287, SHAPE 97.12 ->
96.47. So the coordinator's prediction holds with a refinement: definition
position does not gate the *decision*, though it is not codegen-inert.

**Total: 40 + 1 + 36 + 5 = 82 real-source states, zero flips.**

### Verdict: seal the channel at two rows

Across four waves the inline accept/decline bit has been attacked with
**8,963 synthetic carrier cells** (two generator families, three TUs, both
directions), **82 real-source include/placement states**, **six source forms on
the target row**, **five forms on `mxlist.h`**, and the compiler's own
`inline_depth` knob. It moved exactly twice, and both movers are disqualified:
`inline_depth` is out of mandate, and the one source form that flips it
(`InsertEntry` by assignment) takes an exact row from 688 to 611 bytes.

The bit is **C2-internal and unreachable by any permitted lever**. Per the
wave-3 pricing, the channel is worth **two rows** — `0x1003cf20` (banked by
Lane B10) and `0x1009f490` (residue measured at nd 0) — with `0x100a4420` one
scheduling instrument behind. Stop funding it.

### Two harness lessons from this wave

- **A permuting harness must permute contents in place.** My first include
  sweep rewrote the include block and silently dropped the blank lines between
  the groups, so its own baseline was already a perturbed file.
- **Parallel MSVC workers must each get their own `/Fd`.** Dropping `/Fd`
  defaults every worker to `vc40.pdb` in the shared cwd, and 22 of the first
  run's "failures" were `C1033: cannot open program database`, not source
  errors.
- **Source path length is NOT a confound here** — compiling the same tree from
  a 45-character path and a 111-character path gives a byte-identical body, so
  the scratch-copy method used in waves 2-4 is sound. (Worth recording because
  the standing rule warns the compiler arena is path-length sensitive; it is
  not sensitive for this TU.)

## WAVE 4 CLOSE — the two new working rules, applied to this lane's own sweeps

### Rule 1: harvest `results.json`, do not trust a ledger

248 retained result files in the scratchpad. Scanned for every row this lane
owns: **zero records carry an nd-like score <= 2.** No unharvested near-miss
exists for `0x1009f490`, `0x100a4420`, `0x100a46b0`, `0x10061010`,
`0x10062e20`, `0x100a84a0`, `0x100aa510`, `0x1006fda0`, `0x100bd020`,
`0x100a12a0`.

The files did contain something a ledger would never have told me: **94 verdict
records from earlier lanes probing my own `FUN_10061010` inline bit.** Four of
them flip it to INLINED, at caller lengths **668, 662, 556, 552** against
retail's 731. My wave-2 `InsertEntry`-by-assignment form (722) is the closest of
the five, and still nine bytes out with STRUCT 67.46. So the bit on that row has
now been flipped by **five independent source variants across three lanes**, and
not one brings the body near retail — independent corroboration of the wave-3
verdict that `0x10061010`'s problem is not the inline bit.

### Rule 2: score every open-row symbol in the object

My wave-2 sweeps scored only the stem's target and discarded the objects. Two of
the three TUs I swept carry a **second** open row I never looked at:

| TU | swept for | never scored |
|---|---|---|
| `legoanim.cpp` | `0x1009f490` | — (only open row in the object) |
| `orientableroi.cpp` | `0x100a4420` | **`0x100a46b0` UpdateTransformationRelativeToParent** |
| `legoanimationmanager.cpp` | `0x10061010` | **`0x10062e20` FUN_10062e20** |

Re-swept both TUs over the same carrier families, scoring every open row
(`<scratchpad>/arch/sweepall.py`, results written to
`<scratchpad>/arch/sweep-{oroi,anmgr,anmgrdense}/results.json` for future
harvest):

    0x100a4420  seed nd=222  best nd=222  (730 cells, flat)
    0x100a46b0  seed nd= 99  best nd= 99 @ decl(5,27)  (730 cells)
    0x10061010  seed nd=435  best nd=435  (1,918 cells, flat)
    0x10062e20  seed nd= 72  best nd= 30 @ pad(1,4)    (1,918 cells)

Two results worth keeping:

- **`0x100a46b0` is already at its optimum on this axis.** The best cell in 730
  states *is* `declaration_shape(5,27)` — the donor the tree already carries. The
  standing MUST-RESOLVE entry's "best nd=99" is now independently reproduced
  rather than inherited.
- **`0x10062e20` moves, and the way it moves reclassifies the row.** At
  `pad(1,4)` (and `pad(1,15)`) the body is retail's exact length 1098 with
  masked nd 72 -> 30, and the metrics say what happened:

        seed       len 1098  nd 72   SHAPE 94.13  STRUCT 94.13  EXACT 88.56
        pad(1,4)   len 1098  nd 30   SHAPE 94.13  STRUCT 94.13  EXACT 94.13

  **The carrier removes the entire register-colour gap** — EXACT rises to meet
  SHAPE — and leaves a pure operation-sequence difference. A dense 1,188-cell
  pad sweep confirms 30 is the floor. So `0x10062e20` is **not** an allocator
  row: its remaining defect is a real SHAPE gap of ~6%, which belongs to the
  text channel, not the colour pile.

**Nothing landed.** No cell reaches nd 0, the gate is row-based, and byte
distance is not progress. The states are recorded so the next wave can start
from them instead of re-deriving them.

### One confirmation for the false-positive class

`0x10084030 CreateActorROI` reads nd=0 in a scan that masks call-target fields
on both sides (the S72 relocation-target class). The masked nd used here blanks
only **our** relocation byte ranges and compares everything else, which is why it
returns **80** and agrees with the coordinator's independent measurement — and
why my wave-2 nomination of that row was wrong.
