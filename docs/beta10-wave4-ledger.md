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
