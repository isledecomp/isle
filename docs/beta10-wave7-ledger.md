# Lane B10 — wave 7 ledger (the text channel, and the lane's own SHAPE census)

Worktree reset to `cd8692bb`; re-baselined **LEGO1 4853/4934, ISLE 172/172,
CONFIG 111/111**.

Rather than idle until the coordinator's census lands, I re-pointed
`scratchpad/fin/adiff.py` at this build dir and ran the instrument over
**every open row in this lane's eleven TUs myself**. The verdicts below are
this lane's own measurement; they should agree with the central census and can
be cross-checked against it.

## THE LANE'S SHAPE/STRUCT/EXACT CENSUS

| row | addr | SHAPE | STRUCT | EXACT | insn ours/retail | verdict |
|---|---|---|---|---|---|---|
| `Act3List::RemoveByObjectIdOrFirst` | 0x100720d0 | **100.00** | **100.00** | 94.17 | 120/120 | **CLOSED BOTH CHANNELS** |
| `TowTrack::HandlePathStruct` | 0x1004d330 | **100.00** | **100.00** | 95.24 | 231/231 | **CLOSED BOTH CHANNELS** |
| `LegoCarRaceActor::CalculateSpline` | 0x10080be0 | **100.00** | **100.00** | 95.87 | 242/242 | **CLOSED BOTH CHANNELS** |
| `LegoLOD::Read` | 0x100aa510 | 97.90 | **76.88** | 73.38 | 571/571 | **FRAME defect — the lane's strongest text signal by far** |
| `LegoROI::Read` | 0x100a84a0 | 97.99 | 96.50 | 93.51 | 671/670 | frame defect |
| `Act3Cop::FUN_10040360` | 0x10040360 | 97.97 | 97.16 | 96.89 | 740/740 | frame defect |
| `Act3Brickster::FUN_100417c0` | 0x100417c0 | 98.08 | 97.96 | 94.96 | 834/834 | frame defect (marginal) |
| `LegoAnimScene::CalculateCameraTransform` | 0x1009f490 | 94.23 | 94.23 | 93.59 | 304/**320** | shape gap: **16 instructions missing** |
| `LegoCarRaceActor::CPI` | 0x10081840 | 99.73 | 99.73 | 96.48 | 368/**370** | shape gap: 2 instructions missing |
| `LegoOmni::Destroy` | 0x10058c30 | 99.14 | 99.14 | 99.14 | 173/**174** | shape gap: 1 instruction missing |
| `LegoWEGEdge::LinkEdgesAndFaces` | 0x1009a8c0 | 99.61 | 99.61 | 99.21 | 508/508 | shape gap, 2 insn — but see below |
| `Act3::TriggerHitSound` | 0x10072ad0 | 98.73 | 98.73 | 92.41 | 79/79 | shape gap, 1 insn |
| `Act3::Enable` | 0x10073a90 | 98.81 | 98.81 | 90.91 | 253/253 | shape gap, 3 insn |
| `JetskiRace::HandlePathStruct` | 0x100166a0 | 98.80 | 98.80 | 86.75 | 166/166 | shape gap, 2 insn |
| `CarRace::HandlePathStruct` | 0x100170e0 | 99.17 | 99.17 | 98.90 | 363/363 | shape gap, 3 insn |
| `Act3Ammo::Animate` | 0x10054050 | 98.46 | 98.60 | 95.53 | 716/716 | shape gap (STRUCT > SHAPE) |

### Three rows are now proved closed on BOTH channels

`RemoveByObjectIdOrFirst`, `TowTrack::HandlePathStruct` and `CalculateSpline`
score **SHAPE 100.00 and STRUCT 100.00** — the text channel is proved shut —
and all three sit on a carrier floor that is invariant across six generator
families and ~28,000 states (wave 6). **These three are finished as far as any
lever this project has can reach them.** They are pure colour: allocator
choices only.

The corroboration is worth noting: `CalculateSpline` is the row whose −1 byte I
showed in wave 4 to be the `add eax,imm32` short-form encoding rather than a
missing statement. SHAPE 100 / STRUCT 100 confirms that independently — the
operation sequence *and* the frame are already retail's.

### `LegoWEGEdge::LinkEdgesAndFaces` is the "permutation with a SHAPE gap" case

SHAPE 99.61 with 2 instructions unaligned, and the two are exactly the
`LenSquared` address temporaries I censused in wave 5. The finish-line ledger
warns that a pure permutation can score a SHAPE gap when the difference lands
on something SHAPE keeps. That is this row: retail's own histogram uses both
orders ({8:7, 4:2}), so the "SHAPE gap ⇒ text target" rule misfires here.
**Treat this row as closed on both channels too**, on the strength of the
wave-5 census rather than the SHAPE number.

## A REFINEMENT THE MAP'S BINARY RULE NEEDS: vendor-inline SHAPE gaps

Three of this lane's "real SHAPE gap" rows have their gap **inside inlined
vendor STL code**, where the source that would have to change is `<list>` or
`<xtree>` — which the mandates forbid editing. A SHAPE gap there is just as
unreachable as SHAPE 100, but the binary rule files it as a text target.

Named precisely, with `adiff -v`:

* **`LegoOmni::Destroy` 0x10058c30** — retail has exactly one extra
  instruction, `add r, 8` at +244, and one `cmp [r+0xc]` where retail has
  `cmp [r+4]`. That is the addressing-mode hoist inside the inlined container
  walk (wave-1 recorded it as "callee-side, KILLED for legomain source";
  wave 4 located it at byte level; the metric now names it as the *only*
  divergence in the whole 173-instruction body).
* **`LegoCarRaceActor::CPI` 0x10081840** — retail has two extra instructions
  at +119, `jmp T` + `mov [F], r`: the `_Tree<…>::iterator::operator++`
  tail-merge shape (wave 4's +5 finding). Everything else in 368 instructions
  aligns.
* **`LegoWEGEdge::LinkEdgesAndFaces`** — first-party inline
  (`Vector3::LenSquared`) rather than vendor, but the same conclusion for a
  different reason: wave 5's census showed retail emits **both** temp orders
  ({8:7, 4:2}), so no source spelling produces its program.

**Suggested third verdict for the census: `SHAPE gap in inlined code that the
mandates put out of reach` — not a text target.** Otherwise three of my rows
will be handed back to me as text work that cannot be done.

## `CalculateCameraTransform` — inline budget, confirmed a second way

The largest SHAPE gap in the lane (94.23; ours 304 instructions vs retail's
**320**) is the un-inlined `LegoAnimNodeData::Interpolate` call that wave 4
identified. The obvious text hypothesis was that 1997 did not mark
`Interpolate` `inline` at all — which would make every use site a real call.

Killed by counting retail's call sites (`t2/callers.py`):

```
direct calls to 0x100a0b00 in LEGO1.DLL: 2
  from 0x1009f818   (inside CalculateCameraTransform)
  from 0x100a04a4
```

Our source has **seven** uses of `Interpolate`. Retail calls it twice and
inlines the other five, so the keyword *was* present and C2's budget simply
ran out at two sites. The row is inline-budget class (fresh-eyes C4) and needs
the pool instrument, not a source edit. Sealed.

## `LegoLOD::Read` — the lane's best text target, and nine more negatives

SHAPE 97.90 / **STRUCT 76.88** is the sharpest frame signal in the lane: the
operation sequence is nearly retail's while **103 aligned instructions carry a
different frame displacement**. `t2/slotmap.py` publishes the map:

```
   ours  retail  delta  count
   -20 … -36  →  -24 … -40    -4    (37 instructions)
   -40 … -56  →  -48 … -64    -8    (33)
   -64        →  -68          -4    (7)
  -116…-124   → -120…-128     -4    (5)
   -380       →  -384         -4    (1)
   -67, -65   →  -20, -18    +47    (the packed-word byte accesses)
```

Two insertion points, not one: a 4-byte slot below −20 **and** a second between
−36 and −40, with 4 bytes recovered again below −56. And retail keeps
`tempNumVertsAndNormals` at **−0x14** where ours has it at −0x44.

Nine declaration variants probed against the metric (five position moves of
`tempNumVertsAndNormals` within the block; four uninitialised-across-initialised
moves, the axis that produced wave-2's `MXIOINFO::Advance` hit):

| variant | SHAPE | STRUCT |
|---|---|---|
| base | 97.90 | 76.88 |
| p1 temp declared last · p2 temp first in its line · p3 with `numPolys` · p4 with `numTextureIndices` | 97.90 | 76.88 (all four identical) |
| p5 temp first in the whole block | 97.90 | 76.71 |
| q1 temp first + `index` moved · q2 `numPolys` hoisted above the initialisers · q3 `numVertices` hoisted · q4 `paletteEntries` hoisted | 97.90 | 76.71 / 76.88 / 76.88 / 76.88 |

**Every one inert.** The frame stays 0x170 against retail's 0x174. Combined
with wave 4's three scalar-temp variants (all folded away without growing the
frame), that is **twelve declaration forms that cannot buy the missing slot**.
Whatever retail declared must earn a slot — an aggregate, or an object whose
address escapes — and it is not any scalar at the `tempNumVertsAndNormals`
site. The slot map above bounds where it sits; that is the handover.

## `Act3Ammo::Animate` — my own wave-5 rule, fully applied, and it does not close

This was the one place in the lane the rule had never been run. Both steps, in
order:

**Step 1 — the m=0 strip, far out.** `fwdE` k = 401..999 added to the existing
1..400 (599 further states, 1,598 total). **124 distinct counts reach retail's
2666-byte length**; the best of every one of them is nd=105.

**Step 2 — dense m at those k.** `extern(m, k)` for m = 0..99 at eighteen of
the k-family members (48, 50, 160, 177, 207, 224, 240, 242, 271, 288, 370,
432, 434, 463, 480, 496, 498, 560) — 1,800 states.

```
best nd=95 @extern-13-224   (also extern-15-48, extern-15-50)
```

**Floor 95, unchanged.** The rule is right — the post-include seat is what
moved this row from 105 to 95 in the first place — but there is no cell in the
family that closes it. Its SHAPE/STRUCT reading (98.46 / 98.60, STRUCT above
SHAPE so no frame defect, 11 instructions unaligned) matches wave 4's read-off:
retail hoists the `mov eax, [ebp+8]` load into an FP gap. That is scheduling,
which shows up as a SHAPE gap without being a text target — the same misfire as
`LinkEdgesAndFaces`.

## LANE VERDICT

**This lane is closed on both channels.** Sixteen open rows, and after wave 7
not one of them has a lever left that this project can pull:

| verdict | rows |
|---|---|
| **proved closed both channels** (SHAPE 100 & STRUCT 100 + carrier floor invariant over six families) | `RemoveByObjectIdOrFirst`, `TowTrack::HandlePathStruct`, `CalculateSpline` |
| **SHAPE gap inside inlined code the mandates put out of reach** (vendor STL, or first-party inline proven to emit both forms) | `LegoOmni::Destroy`, `LegoCarRaceActor::CPI`, `LegoWEGEdge::LinkEdgesAndFaces` |
| **scheduling permutation wearing a SHAPE gap** | `Act3Ammo::Animate`, `Act3::TriggerHitSound`, `Act3::Enable`, `JetskiRace::HandlePathStruct`, `CarRace::HandlePathStruct` |
| **inline budget — needs the C4 pool instrument, not a source edit** | `CalculateCameraTransform` (confirmed twice: 16 missing instructions, and retail calls `Interpolate` from exactly 2 of 7 sites) |
| **frame defect, text target, but twelve declaration forms refuted** | `LegoLOD::Read` (STRUCT 76.88 — the one row still worth a session, with the slot map above), `LegoROI::Read`, `FUN_10040360`, `FUN_100417c0` |

The four frame-defect rows are the only ones with a live text signal, and
`LegoLOD::Read` is the only one where the signal is large. Everything else in
this lane is allocator colour or is behind a mandate.

Total for the lane across waves 4-7: **4 rows landed** (`LegoOmni::Create`,
`LegoROI::~LegoROI`, `Act3Brickster::Animate`, plus `LegoROI::Intersect` closed
by the annotation this lane diagnosed), ~45,000 carrier states compiled, and
five structural results adopted as project policy.
