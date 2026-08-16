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
