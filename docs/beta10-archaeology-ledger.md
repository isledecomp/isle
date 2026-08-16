# BETA10 archaeology ledger

The debug images in `legobin/` (BETA10.DLL, ALPHA.DLL) are unoptimised builds:
statement order, named locals and un-inlined calls all survive (frame-slot
order does NOT decode declaration order -- see the correction below). That makes them a **source oracle** for rows the carrier/generator
sweeps have sealed — the channel the sweep campaign ledger calls
"text archaeology".

Instrument: `tools/beta_disasm.py <va> [image] [max-instrs]`.

**Coverage: 41 of the 81 open LEGO1 rows carry a `// FUNCTION: BETA10 0x...`
annotation.** Those are the rows this channel can speak to.

## What the oracle can and cannot say

- It **can** settle: how many locals a function had (the local *set*), the
  order of emitted initialisers and hence **statement order**, whether a value
  was a named local or a repeated expression, and which call arguments were used.
- It **cannot** settle local **declaration order**. My original claim here --
  "debug allocates frame slots in declaration order, so the beta frame decodes
  the 1997 declaration list" -- is WRONG and was refuted with the real compiler
  at /Od; see "The /Od slot rule is NOT declaration order" below. Plain scalars
  do descend in declaration order, but class-typed locals do not: reversing all
  six locals of a mixed probe changed the layout by one swap out of six.
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

## Correction to the call census bound (2026-08-16, main loop)

The census over the 81 open rows compares **call counts**, not call targets, so
"78 of 81 carry retail's exact call graph" should read "…matching call counts".
The distinction is not academic — `0x1003cf20 ~LegoCacheSoundManager` is a
counterexample the count test cannot see:

    ours    direct=7 indirect=2  len=274
    retail  direct=7 indirect=2  len=258

Counts agree, graphs do not. Our seven extra instructions at offsets 146-163
are the inlined body of `~LegoCacheSoundEntry`
(`cmp [ecx],0 / jne / mov eax,[eax+0xc] / test / je / push / call / add esp,4`),
i.e. `if (m_sound == NULL && m_name != NULL) delete[] m_name;`. Retail instead
emits one `call ~LegoCacheSoundEntry`. Both bodies therefore contain the same
*number* of calls — ours to `operator delete[]`, retail's to the destructor.

So the bound "don't hunt missing calls anywhere else in the open set" is not
safe as stated: **an inline accept/decline can hide behind equal call counts
whenever the inlined body itself contains a call.** The census still bounds the
cheap cases; to close it, compare call *targets* by symbol, not counts.

Anchors for the inline accept/decline channel, now four and byte-exact:
- `0x1009f490` retail calls `Interpolate`, we expand and DCE it (−47)
- `0x100a4420` retail calls `Vector3::Vector3` for the sub-object at `this+0xa8`,
  we expand it (+6) — previously misfiled as "the inline ladder"
- `0x10061010` **opposite direction**: retail inlines the `MxListEntry` ctor,
  we call it (−14)
- `0x1003cf20` retail calls `~LegoCacheSoundEntry`, we inline it (+16)

## BETA10 annotations are not all correct

`legoanim.cpp` annotated `LegoAnimNodeData::Interpolate` as `BETA10 0x1017f7c3`.
That address opens an SEH frame (`push -1; push handler; mov eax,fs:[0]`) and is
not a float helper. The real beta `Interpolate` is **0x10180e00**, reached from
the beta's own `CalculateCameraTransform` at 0x10181eb2 with five arguments and
`add esp,0x14`. Corrected in-tree; gate re-verified green at 4853.

Method for trusting a beta address: confirm it structurally, or reach the callee
by following a call from a body you already trust. A second suspect annotation
at `legoanim.cpp:1046` is left alone pending that check — do not change a BETA10
annotation you have not independently confirmed.
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

## WAVE 5 — the cost-threshold hypothesis: CONFIRMED as a mechanism, REFUTED as a route

The C4710 oracle (`#pragma warning(1 : 4710)`) was adapted to this worktree and
the scratch-copy method (`<scratchpad>/arch/c4710.py`). **Control first: the
pragma is codegen-inert here** — the target COMDAT is byte-identical with and
without it, so it is a diagnostic, not a forcer.

**Caveat that cost me an hour: C4710's line numbers shift under an injected
body, and un-shifting them is unreliable.** My first vector reading said the
depth-1 sites never declined when in fact they had. Read the decline vector
from the **object** instead — the count of `Interpolate` relocations in a
function *is* the number of declined sites in it. That is authoritative and
just as cheap.

### The mechanism is real, and the predicted ordering is exactly right

Ladder: N live statements injected into `Interpolate` (`p_key1.SetTime(...)`,
a write through a reference, so it cannot be discarded — the dead-code ladders
I tried first are free and move nothing). Vector read from the object as
(CalculateCameraTransform, GetTranslation, CreateLocalTransform):

    n     CCT  GetTr  CrLoc   CCT len   masked nd
    0      0     0      1      1074       268     <- today
    1      0     0      2      1109       274
    2..11  0     0      3      1134..1359 272..420
    12     1     0      3      1121         5     <- the bit flips
    14     1     1      3      1121         5
    22     1     2      3      1121         0     <- byte-identical to retail
    23+    1     2      3      1121       9..54

Two things fall out:

1. **`0x1009f490` is genuinely reachable.** At n=22 it is **1121 bytes against
   retail's 1121, masked nd 0, SHAPE = STRUCT = EXACT = 100.00.** That is the
   second independent confirmation of the wave-3 price, by a different route.
2. **Among depth-1 sites the largest caller declines first**, exactly as the
   hypothesis predicted: `CalculateCameraTransform` (1121 B) at n=12, then
   `GetTranslation` (230 B) at n=14 and again at n=23. There *is* a window —
   n = 12..13 — where CCT is declined and all three GetTranslation sites still
   expand.

### But retail's vector is unreachable on this axis, and the reason is arithmetic

Retail's vector is **(1, 0, 1)**: two `Interpolate` calls image-wide, at
`0x1009f818` and `0x100a04a4`. Our `CreateLocalTransform` count leaves retail's
value of 1 at **n=1** and saturates at 3 by **n=2** — the three depth-2
`GetScale` sites cross their threshold ten cost units *before*
`CalculateCameraTransform` crosses its at n=12.

> **`CrLoc = 1` requires cost < 1. `CCT = 1` requires cost >= 12. The two
> conditions are disjoint, so no callee form — authentic or contrived —
> produces retail's vector.** Step 3 is therefore moot: this is a refutation
> that does not depend on authenticity at all.

Priced on the best cell (n=22), the trade is **+1 / −3**:

    row                                    baseline        at n=22
    0x1009f490 CalculateCameraTransform    nd 268          nd 0      (gain)
    0x100a0600 GetTranslation              nd 0, 1.0       nd 1341   (lost)
    0x100a03c0 CreateLocalTransform        nd 0, 1.0       nd 473    (lost)
    0x100a0b00 Interpolate                 nd 0, 1.0       nd 579    (lost)

### The body axis is inert — and this time with a positive control

The newly authorised body-level generators were swept into
`CalculateCameraTransform` over **10 insertion positions** spanning the whole
function, including immediately before and immediately after the call site:

    empty_scopes   scope_count 1..24 x 10 positions = 192 cells   0 flips
    noop_assign    repeat      1..24 x 10 positions = 240 cells   0 flips
    live_caller    (diagnostic) 1..16 x 10 positions = 160 cells  0 flips

The first two never changed the emitted body at all (length 1074, nd 268
everywhere), so on their own they would only show that *those two generators*
are neutral. The third settles it: `tempMatrix.SetIdentity();` repeated in the
caller is real inlined work and demonstrably moved the caller's codegen
(length 1074 -> 1124, nd 268 -> 968) — **and the site still did not decline, at
any count, at any position, including directly above the call.**

> **The decision at this site is a function of the CALLEE's cost and not of the
> caller's accumulated body state.** 592 body-level cells with a positive
> control on both sides: the callee axis moves the bit at n=12, the caller axis
> never moves it.

### Verdict

The seal stands and is now properly evidenced. The channel is worth the two
rows priced in wave 3 — `0x1003cf20` (banked) and `0x1009f490` (nd 0 by two
independent routes) — and `0x1009f490` cannot be taken on the callee axis
without losing `GetTranslation`, `CreateLocalTransform` and `Interpolate`.
What it needs is a way to move **one site's** decision, which neither the
callee axis (moves all seven) nor the caller-body axis (moves none) provides.

## WAVE 6 — the ACCEPT direction: bit flipped, row not closed

`0x10061010 FUN_10061010` is the one anchor running in the ACCEPT direction
(retail inlines the `MxListEntry` ctor, we call it), so R must rise and
`empty_scopes` is the carrier that raises it.

**Harness control first, because the first sweep was a null.** 240 cells of
`empty_scopes` (1..40 x 7 positions) left the body **byte-identical at 717**
and never flipped the bit. Two controls established that this was the row and
not the instrument:

- *Positive control on the same harness*: substituting a real emitting call
  (`FUN_10064b50(-1);`) moved the body immediately (717 -> 727/731/737/…), so
  the insertion reaches the compiled function.
- *Reproduction of the other lane's datum*: compiling `legopathcontroller.cpp`
  with and without its 13 landed scopes gives **2337 vs 2329** bytes, with
  `_Tree::_Init` surfacing only in the former (1 vs 0 relocations) and the
  `_Tree` ctor going 1 -> 2. The mechanism and my harness are both confirmed.

### The flip, and the number that matters

Pushing to the validator ceiling found it. The transition is a **sharp step**:

    n <= 85 scopes   ctor called   len 717   nd 435   (body byte-identical
                                                       across every count)
    n >= 86 scopes   ctor INLINED  len 720   nd 436

**Threshold: 86 empty scopes.** Two things worth recording about it:

1. **It is position-independent.** All five insertion positions tested —
   function top, before the cursor, immediately before the `Append` call,
   immediately after it, and at the function tail — flip at the same counts.
   That is direct support for "empty scopes are caller-IL units": a global
   quantity for the function, not a local effect at the site.
2. **86, not ~11.** The planner estimate of a 21-unit deficit on the E3 shape
   predicts a flip an order of magnitude sooner. Either the unit conversion or
   the deficit is off for this row; the measured step is the calibration point.

### The honest part: it is a mechanism win and a row loss

    row              variant     len   retail   masked nd   SHAPE   STRUCT   EXACT
    FUN_10061010     baseline    717     731        435     93.08   68.26   63.48
    FUN_10061010     n=86        720     731        436     94.74   69.86   65.55
    FUN_10062e20     either     1098    1098         72     94.13   94.13   88.56

Flipping the bit moves SHAPE by 1.7 points and **makes masked nd very slightly
worse**. `STRUCT ~70` says what wave 3 already priced at nd 432: this row's
frame layout is wrong (the -3 slot frame in the frame census), and the inline
bit is a rounding error on top of it. `FUN_10062e20`, the TU's other open row,
is untouched — no collateral, and none to gain.

**Nothing landed.** The row does not reach 1.0, so 86 generated scopes in the
tree would buy zero rows.

### What this adds

- The `empty_scopes` ACCEPT mechanism is now confirmed on a **second,
  independent row**, in a different TU, by a different lane — and reproduced
  from the landed FindPath op as a control.
- The carrier is **position-independent** and behaves as a **step function**:
  invisible below threshold (byte-identical body across 240+ cells), a 3-byte
  change above it.
- The threshold for this row is **86**, which is the first hard calibration
  point for the planner algebra outside FindPath.
- Stacking the flip with the carrier grid is available and *not* recommended:
  wave 4 already found this row flat at nd 435 over 1,918 carrier cells, and at
  STRUCT ~70 it is not a near-miss by any reading.

## WAVE 7 — GROUP (b): both best specimens read, no source form found

Method: read the allocation, name the idiom, check it against BETA10. New
instrument: `<scratchpad>/arch/slotmap.py` aligns our body against retail's at
SHAPE level (frame displacements erased, so alignment survives a permutation)
and then reads the ebp displacement off **both** sides of every aligned pair.
For an opcode-identical row that yields the allocator's permutation exactly,
with an AMBIGUOUS flag if any slot maps two ways. Frames are read from the
**linked** images (`framemap.py`) with capstone operand sizes, so a 2-byte
local can never be mistaken for a 4-byte one.

### `0x100aa510 LegoLOD::Read` — retail COALESCES two locals; we do not

The permutation is clean. Eleven slots (`-0x48`..`-0x70`) map identically,
most of the rest shift by −4 or −8, and exactly three move sharply:

    ours -0x44  ->  retail -0x2c    numNormals   (used only BEFORE the loop)
    ours -0x3c  ->  retail -0x2a    numPolys     (used only INSIDE the loop)
    ours -0x43/-0x41 -> retail -0x14/-0x12   a 3-byte compiler temp

`-0x2c` (4 bytes) and `-0x2a` (4 bytes) **overlap by two bytes**. That is
live-range coalescing: the two are never live together, so retail's packer
gave them overlapping space, which is where both the 2-misalignment and the
+4 frame come from. The third item is the `LegoColor` temporary returned by
`legoMesh->GetColor()` — retail puts it at `-0x14`, we put it at an *unaligned*
`-0x43`.

**Block-scope hypothesis: refuted.** Every loop-only local (`numPolys`,
`numVertices`, `numTextureIndices`, `meshIndex`, `red/green/blue/alpha`,
`d3dmesh`, `index`, `paletteEntries`) was moved into the loop body in nine
combinations. Moving `numPolys` alone is **bit-identical** to baseline; every
larger combination is worse (masked nd 313 -> 855..890) and **not one changes
the frame size**, which stays 0x170 against retail's 0x174.

**Frame dial: refuted, and it does not even engage.** An unused POD array at
three declaration positions in five sizes (15 cells) leaves `sub esp, 0x170`
untouched in every cell — up to `int[8]`, i.e. 32 bytes. The unused local is
eliminated and never takes a slot here, so the dial cannot reach retail's
0x174 on this row at all. Best cell is nd 313 -> 311 (SHAPE 97.90 -> 98.25),
which is noise against a 313-byte residue.

### `0x1006b140 CopyTransform` — a clean rotation between a local and a temp

Frames are the **same size** (0x150 both) and the slot map is almost the
identity. The entire difference:

    ours -0x14  ->  retail -0x90     `mn`   (6 accesses; this IS the -7 bytes,
                                             disp8 for us, disp32 for retail)
    ours -0x90  ->  retail -0x24     a compiler temp holding `edi + 1`
    ours -0x18/-0x1c/-0x20/-0x24 -> retail -0x14/-0x18/-0x1c/-0x20  (shift by
                                     exactly one slot, a consequence of the above)

So retail places the **named local `mn` deep** and a **compiler temporary
shallow**; we do the reverse, and four slots shift by one as a consequence.

**Declaration order: refuted.** Six orders — `mn` last, `mn` split from its
`new`, `inverse` first, `mn` after `roiTransforms`, `i` first — all keep the
body at 941 bytes (retail 948, so `mn` never leaves the shallow slot) and all
score **worse** than baseline. Our current order is the maximum of the family
(SHAPE 98.31).

### What group (b) actually says

Both specimens reduce to the same statement, and it is not a declaration-order
statement:

> **The divergence is the placement of a compiler TEMPORARY relative to the
> named locals** — the 3-byte `GetColor()` return in `LegoLOD::Read`, the
> `edi + 1` spill in `CopyTransform`. A temporary has no source identity, so no
> declaration-level lever can name it, which is why declaration order, block
> scope and the frame dial are all inert on these rows.

This is the fourth and fifth independent /O2 confirmation that declaration
order does not drive slot assignment, on top of the /Od probe that refuted it
directly (wave 1). The BETA10 oracle was used for what it can settle — the
local SET, which matches our text on both rows — and not for order.

**Nothing landed.** Neither row moved toward retail in any cell.

## WAVE 10 — the SLOT-CLEAN + SCATTERED queue: nine rows settled, no idiom found

The wave-9 queue was worked with the `~MxStreamController` method. The wave's
contribution is a sharper form of the question, because "registers differ" is
not what that method turns on:

> **The `~MxStreamController` signature is a difference in MEMORY TRAFFIC, not
> a rename.** That row fell because its allocation showed a value *spilled*
> where a plain local would have stayed in a register -- a live-range
> difference with a source meaning. A pure rename has identical memory
> traffic. So the screening question is: does one side touch the frame where
> the other does not?

`<scratchpad>/arch/spill.py` asks exactly that, on adiff's SHAPE alignment (so
a differing call target or vtable address is never mistaken for a structural
hunk). Result over the ten first-party rows:

| row | frame-mem delta | reading |
|---|---|---|
| `0x1007b770` Tickle | ours+1 / retail+1 | the SAME `lea r,[F]`, moved 7 bytes; plus an `ebx`<->`ecx` swap of two compiler temporaries (a member load and a sub-object address) |
| `0x1003f540` WriteDefaultTexture | ours+1 / retail+1 | the SAME `mov r,[F]`, hoisted above a `cmp`; the final register assignment is identical on both sides |
| `0x10051ac0` SpawnBricks | ours+2 / retail+2 | balanced; `eax`<->`ecx` on two temporaries |
| `0x100b2a70` PutFrame | ours+2 / retail+2 | balanced; the same `sub r,[F]` moved, twice |
| `0x1004c580` SetupCopyRect | 0 / 0 | no frame-traffic difference at all |
| `0x100bd020` BitBltTransparent | 0 / 0 | no frame-traffic difference at all |
| `0x100586e0` RemovePresenter | ours+2 / retail+2 | balanced |
| `0x100a3840` CreateMesh | ours+2 / retail+1 | **asymmetric**: ours `mov r,[F]` where retail has `mov r,1` -- a reload against a rematerialised constant |
| `0x10069b10` BuildROIMap | ours+1 / retail+0 | **asymmetric** -- pursued below |
| `0x10084030` CreateActorROI | ours+3 / retail+3 | one asymmetric pair at +1615; deferred, Lane HARVEST may route it |

> **Eight of ten have BALANCED frame traffic** -- every apparent spill
> difference is the same instruction present on both sides at a different
> position. That is scheduling and register naming, not the signature. For
> those eight the verdict is **"compiler artifact, no source idiom"**, reached
> by direct measurement rather than by exhausting levers.

### `0x10069b10 BuildROIMap` -- the idiom was already spent, and the overlay is why

This row *does* carry the documented `it++`/`++it` shape (`ours + [mov to
frame, jmp]`, `retail + []`). Reading it turned up something not recorded
anywhere:

- **The clean source says `it++`; a source-overlay op rewrites it to `++it`
  before compiling.** The idiom is therefore already landed, and the row's
  current state -- **617 bytes against retail's 617, masked nd 15**, SHAPE
  97.88 / STRUCT 96.83 / EXACT 95.24 -- *is* the post-`++it` state that the
  historical record attributes to it. The record's "len 622 -> 617" is stale.
- Editing the clean source to `++it` (making it agree with the overlay's
  output) **breaks all ten pinned donor bodies in that TU**
  (`donor body differs from its pinned compiler output`), so the op is
  load-bearing and the clean/effective split there is deliberate.
- The one remaining hunk shows retail running the inlined iterator increment
  at the offset where we run `operator delete[]`, which reads as a statement
  order. **Three statement orders tested, all worse**: advance-before-delete
  with a named key (nd 123), the same with `m_roiMapSize++` hoisted (122), and
  `m_roiMapSize++` before the delete (74), against baseline **15**. The
  current form is the family maximum.

### Verdict

**Nine of the ten rows are settled as "no source idiom exists"**, one
(`CreateActorROI`) deferred for routing. The queue that wave 9 built was worth
building -- it is what let this be a measurement rather than a sweep -- but its
`SLOT-CLEAN + SCATTERED` cell does not contain the class the
`~MxStreamController` method needs. Wave 9's own caveat is now confirmed from
the other side: **SCATTERED is consistent with a differing live range but does
not establish one, and on inspection none of these rows has one.**

The two threads left are both narrow: `CreateMesh`'s reload-versus-
rematerialised-constant, and `CreateActorROI`'s single asymmetric pair.
**Nothing landed.**

## WAVE 11 — the scheduling screen, and a correction to wave 10

`tools/schedmap.py` + `docs/scheduling-residue.{md,json}` are the third screen.
Full result there; the two things worth carrying here:

**Zero rows in the open set are CROSS-BLOCK.** Of the 12 SLOT-CLEAN + IDENTITY
rows, 3 are INTRA-BLOCK (single-digit reorderings inside one block, i.e. the
scheduler) and 9 are DIFFERENT — and the nine are not scheduling at all but
classes already owned elsewhere: `cmpdir` (LegoPartPresenter::Read,
GetActorROI), induction-variable strength reduction
(LegoWEGEdge::LinkEdgesAndFaces), the already-routed inline bit
(OrientableROI::OrientableROI), and addressing-mode / regional register
choices.

**The one row with cross-block moves is compiler block layout, not source
order.** `0x1002de10 SetTransformAndDestinationFromPoints` shows retail
inverting the guard and placing the failure tail at the end of the function
where we emit it inline — which reads exactly like an if/else ordering. Tested:
the positive-if forms lose 50 bytes because MSVC merges the tails (masked nd
617 against baseline 154), and `== FAILURE` is a wash (153). Baseline is the
best form, so **cold-tail placement is MSVC's own decision** and the
CROSS-BLOCK class is retired on the only row that exhibited it.

### Correction to the wave-10 table

Wave 10 recorded `0x100a3840 CreateMesh` as "asymmetric: ours `mov r,[F]`
where retail has `mov r,1` — a reload against a rematerialised constant". That
was read at SHAPE level, where the pairing is unreliable. At EXACT level the
row is a **four-register rotation** of four consecutive frame loads
(ours `edi/edx/ecx/ebx` against retail `edx/ecx/ebx/edi` at +242..+254), plus
retail keeping the constant `1` live in the callee-saved `ebx` where we
rematerialise it into `edi`. Both are register-assignment decisions with no
source name, so `CreateMesh` joins the other eight: **compiler artifact, no
source idiom.** That leaves `CreateActorROI` (routed elsewhere) as the only
cell of the wave-9 register queue not settled.

### Three screens, one conclusion

Slots (wave 8), registers (wave 9) and now scheduling all return the same
verdict on the open set: the residue is allocator and layout decisions with no
source correlate. Goal 1's remaining headroom is the splice machinery and
carrier sweeps, and that is now the conclusion of three independent screens
rather than an inference from failed levers.
