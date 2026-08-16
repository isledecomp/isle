# BETA10/ALPHA transcription foundry — wave 4 ledger (Lane B10)

Session: 2026-08-15 night, agent worktree `agent-ae4a0ccb643677ee3`, branch
reset to `entropy-stabilization` **53a19e9c** (the worktree had been created
off upstream master `31bd20de` — reset was the first action).
Build dir: `/Users/foxtacles/Projects/isle-build-bt04` (15-char stem, so the
shadow root is 45 chars, byte-identical in length to `isle-build-lean/src` —
the pinned donor lengths transfer; verified, all compose units pass).

Baseline (cold gated run, this worktree, this build dir):
**LEGO1 4831/4933, ISLE 172/172, CONFIG 111/111**,
`ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE` in 93.4 s.

Owned TUs: act3actors · act3ammo · towtrack · act3 · legorace ·
legoracespecial · legomain · legoroi · legolod · legoanim · legowegedge.

## Harness (built and validated this session)

Scratchpad `…/3233884b…/scratchpad/b10w4/`:

| tool | what it does | validated by |
|---|---|---|
| `t/nd.py` | masked distance of a TU object body vs the retail oracle, reports SIZE-CLEAN / DELTA | reads nd=0 for the three rows that are already exact (`Intersect`, `UpdateWorldSpeed`, `HandleJump`) |
| `t/ndiff.py`, `t/dump.py` | side-by-side disassembly of ours vs retail at the diff clusters | — |
| `t/bdis.py` | BETA10/ALPHA/LEGO1 PE disassembly at a VA | — |
| `t/sw.py` | carrier sweep (shape/pad/fwdL/fwdP/fwdE/extern/padgrid) repointed at `isle-build-bt04`, **logs best-nd per target**, counts length defect as distance | reproduces wave-3's record `all-legowegedge fwdL-2 nd=2` exactly |
| `t/sw2.py` | **include-order permutation axis** (fresh-eyes-2 C2), optionally crossed with a fixed carrier | see act3 section |
| `t/seed.py` | **SEED-lane** probe through a length-matched mirror root `/private/tmp/claude-501/b10w4-shadow-mirror-N` (45 chars), only `/Fo`,`/Fd` redirected, `/I<real TU dir>` added | legorace: 0 of 58 bodies differ from the build object; legoroi: exactly 1 differs (`FindChildROI`, which is the TU's composed function) |

**HARNESS TRAP (new, cost me a cycle):** naming a scratch tool `dis.py` shadows
the CPython stdlib `dis` module that `inspect`/`dataclasses` import — every
`import byte_identity` in that directory dies. Renamed to `bdis.py`.

**HARNESS NOTE:** the mirror needs `/I<real TU directory>` prepended, otherwise
quoted sibling includes (`#include "legoroi.h"`) do not resolve from the
mirror. Wave-3 measured extra `/I` as inert; the legoroi/legorace controls
above re-confirm it.

## ORACLE CORRECTION (coordinator, mid-session) — what it invalidated here

`sweep-bench/wave2-oracles.json` recorded every retail body as
`retail_image[addr : addr + OUR_len]`, so a row could read nd=0/near-0 while
our body was simply shorter than retail's. All lane tooling was repointed at
`bench/oracles-v2.json` and **every number below is a v2 measurement**.

What it changed for this lane (v1 nd → v2 nd/delta):

| row | v1 | v2 |
|---|---|---|
| `Act3::Enable` | 930/235 | 930 vs **929**, nd=234 (DELTA −1) |
| `LegoROI::Read` | 2061/1362 | 2061 vs **2058**, nd=1359 (−3) |
| `LegoLOD::Read` | 1694/313 | 1694 vs **1693**, nd=312 (−1) |
| `CalculateSpline` | 779/646 | 779 vs **778**, nd=645 (−1) |
| `~LegoROI` | 206/118 | 206 vs **210**, nd=118 (+4) |
| `CalculateCameraTransform` | 1074/221 | 1074 vs **1121**, nd=221 (+47) |
| `LegoOmni::Create` | 2616/1386 | 2616 vs **2648**, nd=1386 (+32) |
| `LegoOmni::Destroy` | 568/253 | 568 vs **571**, nd=253 (+3) |
| `LegoCarRaceActor::CPI` | 1163/930 | 1163 vs **1168**, nd=930 (+5) |
| `Act3Brickster::Animate` | 1628/1149 | 1628 vs **1632**, nd=1149 (+4) |
| `Act3Ammo::Animate` | 2665/935 | 2665 vs **2666**, nd=935 (+1) |
| `_Tree<…LegoTextureInfo>::erase` (legomain) | 1103/652 | 1103 vs **1102**, nd=651 (−1) |

Nothing measured *before* the correction was invalidated in kind — the four
sweeps already run were re-scored against v2 from their cached objects (the
sweep runner reuses `o.obj`, so re-scoring costs no compiles), and the sweep
runner now **adds `abs(len - retail_len)` to nd** so a size-wrong state can
never masquerade as a near-miss.

## Lane baselines (v2, from this build's objects)

SIZE-CLEAN (a carrier/state channel can in principle close these):

| row | addr | len | nd |
|---|---|---|---|
| `LegoROI::Intersect` | 0x100a9410 | 1553 | **0** (link/order row, see below) |
| `LegoWEGEdge::LinkEdgesAndFaces` | 0x1009a8c0 | 1494 | 4 |
| `Act3List::RemoveByObjectIdOrFirst` | 0x100720d0 | 323 | 7 |
| `TowTrack::HandlePathStruct` | 0x1004d330 | 856 | 11 |
| `Act3::TriggerHitSound` | 0x10072ad0 | 348 | 11 |
| `JetskiRace::HandlePathStruct` | 0x100166a0 | 645 | 22 |
| `Act3Cop::FUN_10040360` | 0x10040360 | 2496 | 68 |
| `CarRace::HandlePathStruct` | 0x100170e0 | 1391 | 111 |
| `Act3Brickster::FUN_100417c0` | 0x100417c0 | 2875 | 132 |

LENGTH-DEFECT (text must change size): see the v2 table above.

## LANDED (each proven by a full gated `isle_build.py` run from this worktree)

### 1. `LegoOmni::Create` 0x10058e70 (.9510 -> 1.0) — commit 89c0b621, LEGO1 4831 -> 4832

Donor `fwdE-7` (`forward_declaration_run`, placement `suffix`, prefix
`MxUnkRecVC`, count 7, width 3), id `d_aa8cbbfdb45d`, appended to the existing
`lego1:LEGO1/lego/legoomni/src/main/legomain.cpp` unit.

* Surfaced by the coordinator's corpus rescore; **re-derived on TODAY's text in
  the pipeline-exact donor lane** (`t/sw.py all2-legomain --axes fwdE`):
  body 2648 = retail's true length, masked nd=0.
* Today's seed is 2616 — a **−32 length defect that a carrier state fixes**.
  This refutes "a length defect is text-channel-only": the carrier changes an
  inlining decision and therefore the size.
* S72 relocation-target guard: 147 relocations, target sequence IDENTICAL to
  the seed's.
* splice_class `same_slot_resize` (2616 -> 2648, linked span 2656);
  `compose_same_slot_resize` dry-run OK, first-party directive validation OK.
* Gate: `GAIN 0x10058e70 LegoOmni::Create`, zero LOST.

### 2. `LegoROI::~LegoROI` 0x100a83c0 (.9538 -> 1.0) — commit 3ed88514, LEGO1 4832 -> 4833

Donor `fwdE-159` (same recipe kind, count 159), id `d_3d572fd742b2`, appended
to the existing `roi:LEGO1/lego/sources/roi/legoroi.cpp` unit (which already
carried the fwdL-3 donor for `FindChildROI`).

* **METHOD FINDING (this is the session's biggest one).** The whole historical
  bench caps forward-run sweeps at **k = 96** (`sweep2.py --kmax 96`). Over the
  full 653-state grid the best state for this row was nd=1 (fwdE-31 and
  fwdE-95, both at 210 = retail's true length, one CMPDIR byte at the
  loop-preheader compare). Extending the axis to k = 97..300 found
  **fwdE-159 at nd=0**. The forward-run count axis is *not* saturated at 96;
  `generate_forward_run` accepts 1..999.
* S72 guard: 11 relocations, target sequence IDENTICAL.
* splice_class `same_slot_resize` (206 -> 210, linked span 208 -> 224 — a
  16-byte image growth that cost **zero** rows).
* Gate: `GAIN 0x100a83c0 LegoROI::~LegoROI`, zero LOST.

## DIAGNOSED, NOT LANDABLE HERE: `LegoROI::Intersect` 0x100a9410 (.9981)

Recipe for the coordinator — **the fix is a one-line annotation in
`LEGO1/realtime/vector.h`, which is outside this lane's TU list.**

The body is retail-true: our plain seed object is already masked-exact
(1553/1553, nd=0), and 26 carrier states also reach nd=0. Image-level diff
against retail shows 20 differing instructions, all of them `.rdata`
displacement that reccmp normalises. `reccmp --verbose 0x100a9410` names the
single instruction it cannot normalise:

```
0x100a963a : -call <OFFSET6>                        (retail)
           : +call Vector4::operator= (FUNCTION)    (ours)
```

Resolved by hand: retail's callee is `0x100a9a30`; ours is `0x100a9a70`. The
two are the **same 26-byte function**, byte-identical modulo the +0x40 rebase
(only the `push 0x100a9ab0` / `push 0x100a9af0` EH-frame operand differs),
sitting in the same slot immediately before `TimeROI::TimeROI`
(retail 0x100a9a50 / ours 0x100a9a90).

So this is **not** a link/order defect and **not** a text defect: it is a
missing decomp annotation. `LEGO1/realtime/vector.h` carries

```
	// SYNTHETIC: LEGO1 0x10010be0
	// SYNTHETIC: BETA10 0x100121e0
	// Vector3::operator=
<blank>
	// SYNTHETIC: BETA10 0x1004af40
	// Vector4::operator=
```

`Vector4::operator=` has a BETA10 synthetic annotation but **no LEGO1 one**, so
reccmp cannot name retail's callee and scores the instruction as different.

**Line-neutral recipe:** replace the blank line between the two blocks with
`	// SYNTHETIC: LEGO1 0x100a9a30`. Comments are token-free and the line count
is unchanged, so no TU that includes `vector.h` can be recoloured.

**Caveat the coordinator must decide:** adding a SYNTHETIC annotation adds a
row to LEGO1's comparison set, so the denominator moves 4933 -> 4934 (and the
new row should itself score 1.0, since the function is byte-identical). That
collides with the binding "exactly 4933/4933" framing and is a
project-level call, not a lane call. Not landed.
