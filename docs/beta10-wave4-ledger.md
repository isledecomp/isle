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

## READ-OFFS AND TEXT PROBES (all seed-lane, with victim lists)

### `JetskiRace::HandlePathStruct` 0x100166a0 — BETA10 0x100c8085 read, edit REFUTED

BETA10's June body is an earlier function (nested `switch (GetTrigger())` /
`switch (GetData())` dispatches at /Od, no `sender` local, an extra
0x1f4/0x1f5/0x1f6 script-id local beside `score`), so it is not a structural
oracle for the retail form. It *is* a clean oracle for the comparison
spellings in the score block. June frame: result −4, score −8, scriptId −0xc,
this −0x10, trigger −0x14, data −0x18, entityId −0x1c. June spelled

```
if (m_playerLaps > m_opponent1Laps && m_opponent2Laps < m_playerLaps)      // 3
else if (m_playerLaps > m_opponent1Laps || m_opponent2Laps < m_playerLaps) // 2
else                                                                       // 1
```

i.e. the FIRST comparison player-first with `>` (our source has
`m_opponent1Laps < m_playerLaps`), the second exactly as ours.

Residue before: 645/645 nd=22 — a whole-function `ebx`↔`ebp` role swap
(`p_param` vs `paramData`) plus a CMPDIR pair at offsets 242/243 and 261/262
(ours `cmp ecx,eax; jle` / `jg`, retail `cmp eax,ecx; jge` / `jl`).

**Edit probed** (legorace.cpp:404 and :407 flipped to June's spelling,
line-neutral): seed-lane result **BIT-INERT — 0 of 58 bodies changed**, nd
still 22. The integer register-register comparison mirror is fully
canonicalised, extending wave-2 method finding 4. The CMPDIR bytes here are
NOT source-reachable by spelling. Best carrier state: `shape-1-10`, nd=18.

### `~LegoROI` 0x100a83c0 — BETA10 0x10189a42 read (this is how the +4 was understood)

BETA10 /Od frame: iterator −0x10, `*iterator` temp −0x14, begin() return temp
−0x18, end() return temp −0x1c, `child` −0x24, delete temp −0x20, comp −0x2c,
this −0x38. Loop is `iterator = comp->begin()` in the for-init and
`!(iterator == comp->end())` as the condition, member `operator==`,
`ROI* child = *iterator; delete child;` — **exactly our source**. So the +4
was never a statement-structure defect.

Retail's extra 4 bytes are at body+58: retail spills the begin() pointer to
the frame and compares memory (`mov [ebp-0x14],eax` + `cmp ecx,[ebp-0x14]`),
ours compares registers (`cmp eax,ecx`). Everything after is displacement.

Six seed-lane text variants, victims measured against a fresh seed replica
(123 bodies):

| variant | dtor len/nd | victims |
|---|---|---|
| base | 206/118 | — |
| v1 `iterator != comp->end()` (free `operator!=`) | 206/118 | **11 changed**, incl. `Intersect` 0 → 48 and `Read` — hard NO |
| v2 `!(comp->end() == iterator)` mirror | 206/118 | 0 — **BIT-INERT** |
| v3 `iterator iterator = comp->begin();` + empty for-init | 217/136 | 4 (dtor, Read, FindChildROI) — wrong direction |
| v4 declaration inside the for-init | 217/136 | 4 — same as v3 |
| v5 `delete *iterator;` (drop `child`) | 206/118 | 3 (dtor untouched; Read/FindChildROI/ApplyChild recoloured) |
| v6 `ROI* child;` hoisted above the loop | 206/118 | 0 — bit-inert |

Verdict: the loop-form axis is closed for this row; the carrier axis closed it
instead (fwdE-159). The mirror v2 was re-tested *under* the fwdE carrier as
well (96-state fwdE sweep on the mirror text): still nd=1 at fwdE-31, so the
mirror is inert in that state too.

### `Act3List::RemoveByObjectIdOrFirst` 0x100720d0 — five declaration variants, all worse

Residue: 323/323 nd=7, a pure `eax`↔`edx` role swap in the 30-byte window that
sets up `it = begin(); unusedIterator = it; firstItem = front(); it++`
(slots [esp+0x14] = it, [esp+0x10] = unusedIterator, [esp+0x18] = firstItem).

Seed-lane probes on act3.cpp (96 bodies), all measured:

| variant | row nd | other effects |
|---|---|---|
| base | 7 | — |
| a1 `it` / `unusedIterator` declaration order swapped | **19** | 1 victim (itself) |
| a2 `firstItem` before `unusedIterator = it` | 152 (len 317) | 1 |
| a3 `++it` instead of `it++` | 245 (len 329) | 3 |
| a4 `firstItem` before `it = begin()` | 158 (len 309) | 1 |
| a5 `while (!(it == end()))` instead of `it != end()` | 7 (inert here) | recolours `Act3::Enable` 930/234 → **928/144** and two list COMDATs |

The base is a sharp local optimum (this matches the two decomp comments in the
function, which already record that removing either unused variable hurts).
Note a5: a loop-spelling change inside `RemoveByObjectIdOrFirst` moves
`Act3::Enable` by 90 nd — that is record-stream (carrier-like) coupling, not
causal text, and it is a live lead for `Enable` (see next-steps).

### Include-order axis (fresh-eyes-2 C2) on act3.cpp — NEGATIVE, fully inert

act3.cpp has 22 quoted includes after its own header. All 21 adjacent swaps
were compiled: **every one produced a byte-identical object** for all three
open rows (`RemoveByObjectIdOrFirst`, `TriggerHitSound`, `Enable`). Unlike
legopathactor/legoextraactor (where C2 measured 4–9 moving bodies), the axis
has zero reach in this TU. `legowegedge.cpp` has only one quoted include, so
the axis does not exist there at all. Recorded as a sealed negative for these
two TUs; the axis remains untested on legomain/legorace/legoroi/act3actors.

### `LegoWEGEdge::LinkEdgesAndFaces` 0x1009a8c0 — mechanism identified, no text lever

1494/1494 nd=4 = two sites × 2 bytes, both the SAME defect: the inlined
`Vector3::LenSquared` at legowegedge.cpp:110 and :118 assigns its two address
temporaries the wrong way round (`add ecx,4 / add eax,8` where retail has
`add ecx,8 / add eax,4`). The THIRD `LenSquared` inline in the same function
(line 184, `sqrt(local94.LenSquared())`) already matches retail exactly, which
proves the shared `vector3d.inl.h` text is not the problem — it is a
register-role tie local to the two sites. Full 653-state carrier grid: best
nd=2 (`shape-5-40`, `fwdL-2`), i.e. one of the two sites flips but never both.

### `Act3Cop::FUN_10040360` / `Act3Brickster::Animate` / `CalculateSpline` — residue classes

* `FUN_10040360` 2496/2496 nd=68: pure instruction *scheduling* permutations in
  the prologue block (same instructions, different order) plus CMPDIR
  (`cmp eax,[ebp-0x34]` vs `cmp [ebp-0x34],eax`). Best carrier so far nd=14
  (`fwdE-19`, coordinator's rescore) / nd=35 in my k55..65 window.
* `Act3Brickster::Animate` 1628 → **1632 = retail's true length at `fwdE-59`**,
  nd=7: a single `ebx`↔`ebp` role swap in one loop (`xor ebx,ebx` /
  `inc ebx` / `push ebx` / `[eax+ebx*4-4]`). One carrier flip from landing.
* `CalculateSpline` 779 vs 778: the **entire −1 byte** is at body+64 — retail
  emits `05 c0 00 00 00` (`add eax,imm32`, the 5-byte EAX-only encoding), ours
  `81 c2 c0 00 00 00` (`add edx,imm32`, 6 bytes) — because retail keeps the
  vbase-adjusted `this` in EAX and we put it in EDX at the
  `SwitchBoundary(m_boundary, m_destEdge, m_destScale)` set-up. The whole
  nd=645 is that role permutation cascading. One register-role flip would
  collapse the row; no text lever is visible (the operand order is dictated by
  the virtual call's argument evaluation).

### `LegoAnimScene::CalculateCameraTransform` 0x1009f490 — the +47 is one inline decision

Read off against retail: at body+865 retail emits a real CALL to
`LegoAnimNodeData::Interpolate` with five pushed arguments
(`p_time, &key[i], key[i].GetZ(), &key[i+1], key[i+1].GetZ()`) and then
`fstp st(0)` — it computes the value and throws it away, exactly matching our
`case 2:`'s unused `LegoFloat z`. **Our compile inlines `Interpolate` and then
dead-code-eliminates it entirely**, which is where all 47 bytes go. Everything
before that point is structurally identical (only frame-slot assignment
[esp+0x20]↔[esp+0x54], [esp+0x2c]↔[esp+0x30] and the shifted branch targets).

So this row is a member of the **inline-budget class** (fresh-eyes-2 C4), not a
statement-structure row: the source is already right and the byte budget is
consumed by one call that retail's C2 declined to expand. Best carrier state is
still nd=263 at len 1074 (the wrong length), so no carrier has yet moved the
decision. Candidate legitimate levers, none tried: moving the `inline`
definition of `Interpolate`/`GetKey` within legoanim.cpp (definition position
is period-authentic entropy, like include order) so the pool's
cost-ascending/encounter order changes.
