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

### `Act3Brickster::Animate` 0x10041050 — a TEXT lever that reaches retail's length

Base 1628 vs retail 1632 (+4), nd=1149. Seed-lane probes on act3actors.cpp
(179 bodies, victims measured against a fresh seed replica; in every case the
ONLY body that changed was the target itself):

| variant | len/nd |
|---|---|
| base | 1628 / 1149 (+4 short) |
| b1 `MxS32 i;` hoisted above both `root`/`time` blocks | 1628 / 1149 (body changed, distance identical) |
| b2 `time` before `root` at BOTH sites | 1636 / 736 (4 too long) |
| b3 loop bound mirrored `root->GetNumChildren() > i` | bit-inert |
| b4 `i` hoisted at the case-4 site only | 1628 / 1149 |
| b5 **`time` before `root` at the case-3 site only** | **1632 / 395 — retail's exact length from text alone** |
| b6 `time` before `root` at the case-4 site only | 1632 / 836 |

So the declaration order of the two `case`-local variables

```
LegoTreeNode* root = m_shootAnim->GetAnimTreePtr()->GetRoot();
float time = p_time - (m_unk0x50 - m_shootAnim->GetDuration());
```

is a live, size-changing lever, and swapping it at exactly one of the two
identical sites lands the retail length. **But the carrier channel is better
here:** on the BASE text, `fwdE-59` already gives 1632/1632 with **nd=7**, and
the residue is a single `ebx`↔`ebp` role swap in the `ApplyAnimationTransformation`
loop (`xor ebx,ebx` / `inc ebx` / `push ebx` / `[eax+ebx*4-4]` vs retail's
`ebp`). Ranked next step for this row: carrier search around fwdE-59 on the
base text (not the b5 text) — it is 7 tie bytes from landing.

### `TowTrack::HandlePathStruct` 0x1004d330 — text axis closed

856/856 nd=11 is a **three-register rotation**: retail holds `m_state` in EAX,
`m_state->m_state` in EBX and the `GetData()` word in DX; ours holds them in
EDX, EAX and BX respectively (map retail→ours: eax→edx, ebx→eax, edx→ebx).
Everything before body+116 is byte-identical, so nothing upstream differs.

BETA10 0x100f74c0 is a much earlier function (no `GetData()==0x168` fuel block,
no `UserActor() != this` guard, no `c_missionFinalWaypoint`/0x169 alternative)
so it cannot arbitrate; it does confirm the retained statement order
(`m_state->m_state = e_none; time = Timer()->GetTime() - m_startTime; Leave();`
then the three time thresholds).

Seed-lane probes (69 bodies): t1 (state test moved to the tail of the
condition) 860/646 — worse and 4 long; t2 (`GetData()==8 || ==9` order
swapped) 856/13 — worse; t3 (`e_hookedUp == m_state->m_state` mirror) —
BIT-INERT, 0 victims. Base is a sharp local optimum.
Carrier grid (653 states + fwdE/fwdL 97..400): best nd=11, unmoved.

### `LegoWEGEdge::LinkEdgesAndFaces` — text axis closed too

Seed-lane probes (70 bodies): `float length;` hoisted above the loop,
`length > m_boundingRadius` mirror at both sites, and splitting the
`float length` declaration from its assignment are **all BIT-INERT**
(0 victims, nd stays 4). Hoisting `Mx3DPointFloat local44` above the loop
gives 1509/1119 — much worse. Carrier grid incl. fwdE/fwdL 1..400:
best nd=2 (`shape-5-40`, `fwdL-2`, `fwdL-156`).

### `LegoOmni::Destroy` 0x10058c30 — +3 located exactly

The whole +3 is at body+244: retail emits `add edi, 8` once and then uses
`[edi+4]`-style addressing through the inlined container walk; ours re-derives
`[edi+0xc]` each time. This is the addressing-mode hoist the wave-1 ledger
recorded as "callee-side, KILLED for legomain source" — confirmed at byte
level here. Best carrier so far: nd=251 at `fwdE-12` (len 573, 2 too long).

### `CarRace::HandlePathStruct` 0x100170e0 — structural read-off, edit REFUTED

1391/1391 nd=111. The divergence starts at body+580 in the score block
(legorace.cpp:686-710). Retail:

```
+580  mov eax, [edx*4 + g_rhodaLoosesAnimation]
+587  jmp <join>                       ; the m_secondFinishAnimation store is
                                       ; NOT in this branch
```

ours:

```
+580  mov edx, [edx*4 + g_rhodaLoosesAnimation]
+587  mov [esi+0x14c], edx             ; store in-branch
+593  jmp <join>
```

The decomp already carries a `secondAnim` temp used only in the middle branch
(`m_secondFinishAnimation = secondAnim;` at the end of that branch), so the
obvious hypothesis was that 1997 used `secondAnim` in **all three** branches
with one store after the whole if-chain.

**Probed (line-neutral: the two direct stores rewritten to `secondAnim`, the
in-branch store blanked, the hoisted store placed on the blank line after the
chain): 1385/1391 — 6 bytes SHORT, nd 111 -> 510.** Refuted: retail is not the
fully hoisted form. Retail's shape is consistent with MSVC cross-jumping two of
the three branch tails, which only happens when both tails use the same
register — i.e. this is once again a register-role interaction (branch 1 lands
its value in EDX for us and EAX for retail), not a statement-structure defect.
Recorded so the next wave does not re-derive it.

## METHOD FINDINGS (measured this session, all new)

1. **The forward-run count axis was never saturated.** Every historical sweep
   used `sweep2.py --kmax 96`; `entropy.generate_forward_run` accepts counts
   1..999 and the manifest validator accepts them too. `~LegoROI`'s nd=0 sits
   at **fwdE-159**, invisible to the entire prior corpus. Re-run the tail
   (97..400 and beyond) on every open near-miss row before declaring a row
   state-closed. Cost: ~600 compiles/TU, 3-8 minutes at 4 workers.
   *Also still unexplored on the same generator:* `width` 1 and 2 (the sweep
   hardcodes 3 — a probe at width 2 on legoroi reproduced the nd=1 plateau, so
   width is a real but weak axis), and the `prefix` string, whose LENGTH
   changes every name record's size and which no sweep has ever varied.
2. **Length defects are not text-channel-only** (correcting the mid-session
   framing): `LegoOmni::Create` needed +32 bytes and a *carrier* supplied them
   by changing an inlining decision. `Act3Brickster::Animate` needs +4 and
   `fwdE-59` supplies them. Never triage a size-wrong row out of the carrier
   queue.
3. **`pad_shape` states are unlandable today.** `tools/entropy.py` ships
   `generate_pad_shape` and the sweep bench uses it (`pad-C-F`), but
   `byte_identity.py`'s donor validator only accepts
   `forward_declaration_run` / `declaration_shape` / `extern_run_pair`. Two of
   this lane's best states are pad states (`LegoROI::Read` 2058/65 at
   `pad-11-8`), so a typed `pad_declaration_shape` donor kind — a small,
   generator-backed extension, no new literal text — would immediately open
   them. Recommended framework growth.
4. **Include-order permutation has no reach in act3.cpp** (21 adjacent swaps,
   every object byte-identical) and does not exist in legowegedge.cpp (one
   quoted include). The axis is TU-specific; do not assume the
   legopathactor/legoextraactor result generalises.
5. **Integer register-register comparison mirrors are canonicalised.** Three
   independent refutations this session (JetskiRace `m_playerLaps >
   m_opponent1Laps`, TowTrack `e_hookedUp == m_state->m_state`, legowegedge
   `length > m_boundingRadius`), each with a live 0-victim control. Combined
   with wave 2's finding, the comparison-spelling axis should be considered
   closed for scalar operands; it only moves at an inlined-call boundary.
6. **This lane's residue is overwhelmingly register-role ties.** Of the nine
   size-clean rows, seven are pure physical-register permutations
   (TowTrack 3-cycle eax/ebx/edx, RemoveByObjectIdOrFirst eax↔edx,
   JetskiRace ebx↔ebp, Animate ebx↔ebp, LinkEdgesAndFaces ecx↔eax twice,
   CalculateSpline eax↔edx cascading, FUN_10040360 scheduling+CMPDIR). Text
   probes on four of them (16 variants total) produced no improvement and
   mostly bit-inert results; carrier state produced both landings. Fund the
   carrier axis first for this lane, text second.

## RANKED NEXT STEP PER UNFINISHED ROW

| row | state today | ranked next step |
|---|---|---|
| `Act3Brickster::Animate` 0x10041050 | **1632/1632 nd=7** at `fwdE-59` (base text) | Closest row in the lane. Sweep fwdE/fwdL 97..999 and `shapefull`/`externdeep` on act3actors; the residue is ONE ebx↔ebp tie. |
| `Act3List::RemoveByObjectIdOrFirst` 0x100720d0 | 323/323 nd=7 | fwdE/fwdL 97..999 + shapefull + externdeep on act3.cpp (fwdE-72 and shape-1-2 both plateau at 7). Text axis measured closed. |
| `LegoWEGEdge::LinkEdgesAndFaces` 0x1009a8c0 | 1494/1494 nd=2 | Only the two `LenSquared` address temporaries remain. fwd 1..400 both placements and the 653-grid plateau at 2; try `shapefull` (550 cells, never run for this TU), `externdeep`, and fwd `width` 1/2. |
| `Act3::TriggerHitSound` 0x10072ad0 | 348/348 nd=11 | Same TU as the above; ride the same extended sweep. Wave-1 already closed the text channel (5× table-load register). |
| `TowTrack::HandlePathStruct` 0x1004d330 | 856/856 nd=11 | Text closed (3 probes). Extended carrier only; the 3-cycle is a hard tie. |
| `Act3Cop::FUN_10040360` 0x10040360 | 2496/2496 nd=14 at `fwdE-19` | Extended carrier; residue is prologue scheduling + one CMPDIR. |
| `JetskiRace::HandlePathStruct` 0x100166a0 | 645/645 nd=18 at `shape-1-10` | Extended carrier. The 4 CMPDIR bytes are proven source-inert, so text can only ever fix the ebx↔ebp half — carrier must do the rest. |
| `Act3::Enable` 0x10073a90 | 930 vs 929; best **929/105** at `shape-1-3`/`extern-3-12` | Two live levers: (a) the `a5` loop-spelling change *inside* `RemoveByObjectIdOrFirst` moves it to 928/144 — i.e. it is record-stream sensitive, so run a text×carrier product; (b) extended carrier. |
| `Act3Brickster::FUN_100417c0` 0x100417c0 | 2875/2875 nd=83 at `fwdE-28` | Extended carrier on act3actors (rides the Animate sweep). |
| `CarRace::HandlePathStruct` 0x100170e0 | 1391/1391 nd=111 | Hoisted-store hypothesis refuted (see above). Extended carrier; then re-read the branch-tail merge with a fresh eye. |
| `LegoROI::Read` 0x100a84a0 | 2061 vs 2058; best **2058/41** at `fwdE-288`, **2058/65** at `pad-11-8` | Extended fwdE past 300 (it was still improving monotonically at 288), and/or add the `pad_declaration_shape` donor kind and land a pad state. |
| `LegoLOD::Read` 0x100aa510 | 1694 vs 1693; best 1694/283 at `fwdE-63` | Extended carrier first; the wave-1 parked lead (one extra retail named local at the numVerts/numNormals extraction) is still the text hypothesis. |
| `LegoAnimScene::CalculateCameraTransform` 0x1009f490 | 1074 vs 1121 (+47); best 1074/263 | Inline-budget row (proven: retail keeps the `Interpolate` call, we inline+DCE it). Try moving the `inline` definitions of `Interpolate`/`GetKey` within legoanim.cpp; otherwise it waits on the C4 pool-dump instrument. |
| `LegoOmni::Destroy` 0x10058c30 | 568 vs 571 (+3); best 573/251 | The +3 is one `add edi,8` addressing hoist in the inlined container walk. Extended carrier on legomain (the TU has just been re-dialed by the Create landing — all its old sweep records are stale). |
| `LegoCarRaceActor::CalculateSpline` 0x10080be0 | 779 vs 778; best 778/646 | Whole-function eax↔edx cascade rooted at one `add reg,imm32` encoding choice. Extended carrier on legoracespecial (also re-dialed if anything lands there). |
| `LegoCarRaceActor::CheckPresenterAndActorIntersections` 0x10081840 | 1163 vs 1168 (+5) | Not read off this session. Read BETA10 0x100cf680 first — a +5 size defect usually means a missing statement or an inline decision. |
| `Act3Ammo::Animate` 0x10054050 | 2665 vs 2666 (+1); nd=935 | Not read off this session (BETA10 0x1001e362). |
| `Act3::CreateROIAndBuildMap`, `Act3::TriggerHitSound` ALPHA bracket | not run | Still queued from wave 3. |
| `LegoROI::Intersect` 0x100a9410 | body exact | See the annotation recipe above — coordinator decision. |

### `LegoCarRaceActor::CheckPresenterAndActorIntersections` 0x10081840 — the +5 is vendor-inline

1163 vs 1168. The whole delta is at body+121 inside the inlined
`_Tree<...>::iterator::operator++`: retail emits
`mov [ebp-0x10], eax` + `jmp <join>` (5 bytes) on the "right subtree is not
_Nil" path, ours falls through and reloads the slot at the join. Retail also
holds the walk pointer in EAX where we hold it in ECX. Same class as
`LegoOmni::Destroy`'s `add edi,8`: a tail-merge/register interaction inside
vendor xtree inline code, with no first-party text lever. Carrier-only row.

### Sealed negative: the forward-run `width` parameter is codegen-inert

`generate_forward_run(prefix, count, width)` renders `class MxUnkRecVC000;`
at width 3 and `class MxUnkRecVC00;` at width 2. A full fwdE 1..99 sweep at
width 2 on act3actors produced **exactly the same best states and distances**
as width 3 (`Animate` 7 @ fwdE-59, `FUN_10040360` 8 @ fwdE-20,
`FUN_100417c0` 96 @ fwdE-28), even though the objects themselves differ
(200561 vs 200565 bytes — the symbol names change). Width is not a useful
axis; spend the compiles on `count` instead. (`prefix` length remains
untested.)

## SWEEP LEDGER (every carrier state compiled this session; best nd per row)

All donor-lane (`s.cpp` relative, cwd = probe dir, `/I<source dir>`), scored
against `oracles-v2.json` with the length defect added to nd. Objects retained
under `…/scratchpad/b10w4/sweeps/<stem>[-tag]/<state>/o.obj`; per-state maps in
each directory's `rows.jsonl`.

| stem | axes run | states | best per row |
|---|---|---|---|
| all-legowegedge | shape,fwdL,fwdP,fwdE(1-96),extern,padgrid | 653 | LinkEdgesAndFaces **2** @ shape-5-40 (also fwdL-2) |
| all-legowegedge | fwdE,fwdL 97..400 | 608 | LinkEdgesAndFaces **2** @ fwdL-156 |
| all-act3 | shape,fwdL,fwdP,fwdE(1-96),extern,padgrid | 653 | RemoveByObjectIdOrFirst **7** @ shape-1-2 · TriggerHitSound **11** @ shape-1-1 · Enable **105** @ shape-1-3 (len 929 = retail) |
| all-act3 | fwdE,fwdL 97..400 | 608 | 7 @ fwdE-99 · 11 @ fwdE-97 · 105 @ fwdL-99 |
| all-towtrack | full grid + fwd 97..400 | 1261 | HandlePathStruct **11**, unmoved (@shape-1-5, @fwdE-103) |
| all-legorace | full grid | 653 | JetskiRace **18** @ shape-1-10 · CarRace **111** @ shape-1-1 |
| all2-legoroi | full grid | 653 | Intersect **0** (26 states) · ~LegoROI **1** @ fwdE-31/95 · Read **65** @ pad-11-8 |
| all2-legoroi | fwdE 97..300 | 204 | **~LegoROI 0 @ fwdE-159 (LANDED)** · Read **41** @ fwdE-288 (still improving with k) |
| all2-legoroi | fwdL 97..300 | 204 | Read 62 @ fwdL-271 |
| all2-legoroi | fwdE/fwdL 1..99 width 2 | 198 | ~LegoROI 1 @ fwdE-31 (width inert) |
| all2-legolod | full grid | 653 | LegoLOD::Read **283** @ fwdE-63 |
| all-legoanim | full grid | 653 | CalculateCameraTransform **263** @ fwdE-15 (len 1074, still 47 short) |
| all2-act3actors | full grid | 653 | Animate **7** @ fwdE-59 (len 1632 = retail) · FUN_10040360 **8** @ fwdE-20 · FUN_100417c0 **96** @ fwdE-28 |
| all2-act3actors | fwdE,fwdL 97..400 | 608 | Animate 7 @ fwdE-123 · FUN_10040360 8 @ fwdE-212 · FUN_100417c0 96 @ fwdE-112 |
| all2-act3actors | fwdE 1..99 width 2 | 99 | identical to width 3 (sealed negative) |
| all2-legomain | fwdE 1..12 | 12 | **Create 0 @ fwdE-7 (LANDED)** · Destroy 251 @ fwdE-12 · erase 675 |
| all2-legoroi (mirror text) | fwdE 1..96 | 96 | ~LegoROI 1 @ fwdE-31 — the `end() == it` mirror is inert under the carrier too |

Plateau reading: `RemoveByObjectIdOrFirst` (7), `TriggerHitSound` (11),
`TowTrack::HandlePathStruct` (11), `LinkEdgesAndFaces` (2),
`Act3Cop::FUN_10040360` (8) and `Act3Brickster::Animate` (7) each hold the SAME
distance across 1200+ states on four different generators — these are hard
one-or-two-tie rows, not "not searched enough" rows. The untried landable
cells left for them are `declaration_shape`'s full 550-cell grid and large
`extern_run_pair` counts (both queued as `sweep5`).

### Late sweep results (legoracespecial, legoroi, act3actors)

* `LegoCarRaceActor::CheckPresenterAndActorIntersections` 0x10081840:
  base 1163 (5 short) / nd=930; **`shape-3-15` reaches 1168 = retail's true
  length with nd=103.** Another length defect the carrier channel fixes.
  Promote this row: it went from "not read off, +5 unexplained" to a
  103-byte near-miss in one sweep. Next: fwdE/fwdL 97..400 and `shapefull`
  on legoracespecial (only the 60-cell shape subset has been run).
* `LegoCarRaceActor::CalculateSpline`: 646 across the whole 653-state grid —
  the eax/edx cascade does not respond to any carrier tried.
* `Act3Cop::FUN_10040360`: **8** at `fwdE-20` (better than the corpus
  rescore's 14) and unchanged at k up to 400.

**Harness note (silent sweep deaths):** with three concurrent 3-4 worker
sweeps plus another lane's build on the same machine (load average 21), two
sweep processes (`all-towtrack` k400 and `all-act3ammo`) died mid-run with no
traceback and no `done` line — almost certainly OS-killed under memory
pressure. Detect this by the missing `best.json`; the state objects are cached
so simply re-running resumes where it stopped (the towtrack re-run completed
608/608 and confirmed nd=11). Keep total workers at or below 4 when another
lane is active.

## PRIOR VERDICTS THE ORACLE CORRECTION INVALIDATES (lane-relevant)

1. **`docs/fresh-eyes-2-plan.md` C1.4 doctrine — partially REFUTED.** It ruled
   rows out of every carrier queue "permanently" on the strength of a large
   corpus min-nd, naming `LegoOmni::Create 1386` among them. Create's true
   corpus min-nd was **0**; the 1386 was an artefact of comparing a 2648-byte
   retail body against a 2616-byte window. The triage rule ("large min-nd ⇒
   text-channel only") is only sound when the oracle length is right — and it
   was wrong for 92 of 184 bodies. Re-run the triage before trusting any
   "permanently out of the carrier queue" verdict. (`FindPath`,
   `~MxStreamController`, `FUN_10061010`, `ParseExtra` are not this lane's, but
   they were ruled out by the same broken measurement.)
2. **`docs/beta10-wave3-ledger.md` "Lane B queue" baseline table — superseded.**
   Eleven of its fourteen `today len/nd` figures were measured against the
   truncated oracle. The corrected table is at the top of this ledger.
3. **`docs/beta10-wave2-ledger.md` NOT-REACHED list** quotes the same numbers
   (`2665/935`, `2616/1386`, `1074/221`, `779/646`, `1391/111`) — only the
   size-clean ones (1391/111) survive unchanged.
4. **`docs/beta10-foundry-ledger.md` "LegoOmni::Destroy … recorded KILLED for
   legomain source"** stands as a *text* verdict (confirmed at byte level here)
   but must not be read as a state verdict: the row is +3 short and no carrier
   has yet been searched past fwdE-12 on today's text.

### Final sweep additions

* `all2-legomain` full grid (653 states): `Create` **0** at fwdL-7 as well as
  fwdE-7 and four extern states (extern-4-3/5-2/6-1/7-0) — the landed state is
  not a knife-edge. `_Tree<const char*, LegoTextureInfo*>::erase` 0x10059dc0
  dropped from nd=651 to **66 @ fwdL-34** (len 1101 vs retail 1102);
  `LegoOmni::Destroy` stays at 251.
* `all-legorace` fwdE/fwdL 97..400 (608 states): JetskiRace 18, CarRace 111 —
  both unmoved from the 1..96 grid.
* `all-legowegedge` `shapefull` (505 further declaration-shape cells):
  LinkEdgesAndFaces still **2**. Together with fwd 1..400 on both placements
  and the pad/extern grids, that is ~1770 distinct carrier states holding the
  same 2-byte residue.

## ALPHA.DLL bracket (wave-3 queued item) — CLOSED NEGATIVE for the Act3 rows

Wave 3 queued an ALPHA bracket read for `Act3::TriggerHitSound` and
`Act3::CreateROIAndBuildMap`. **ALPHA does not contain Act 3 at all.** Measured
by substring presence in the three images:

| token | ALPHA | BETA10 | LEGO1 |
|---|---|---|---|
| `Act3` / `act3` | absent | present | present |
| `Brickster` | absent | present | present |
| `eatpz`, `thpt` (Act3Brickster sound names) | absent | present | present |
| `Act3Ammo` | absent | present | absent (retail strips class names) |

ALPHA is the Oct-29-1996 build and predates the act structure; the whole tree
carries only three `// FUNCTION: ALPHA` annotations, none in Act3 sources. The
ALPHA bracket is therefore unavailable for every row in `act3.cpp`,
`act3actors.cpp` and `act3ammo.cpp` — take it off the queue. It remains a
legitimate bracket for the older subsystems (viewlodlist, legoroi, realtime).

## NEW DIAGNOSTIC: the EAX short-form census explains half the −1 rows

x86 has a 5-byte `add eax, imm32` (opcode `05`) where every other register
needs the 6-byte `81 /0` form. So a row that is **exactly one byte short of
retail** is very often just a register-role tie in which retail happened to
put the value in EAX. `t/eaxform.py` counts both forms in ours vs retail in
one second, with no compiles:

| row | ours (short/long) | retail (short/long) | verdict |
|---|---|---|---|
| `CalculateSpline` (−1) | 0 / 1 | **1 / 0** | **explained** — body+64 `81 c2 c0…` vs `05 c0…` |
| `Act3::Enable` (−1) | 2 / 2 | **3 / 1** | **explained** — body+659 `add ecx,0x1a0` vs `add eax,0x1a0` |
| `LegoLOD::Read` (−1) | 8 / 2 | 8 / 2 | not this; the −1 is elsewhere |
| `_Tree<…LegoTextureInfo>::erase` (−1) | 0 / 0 | 0 / 0 | not this |
| `LegoROI::Read` (−3) | 0 / 1 | 0 / 1 | not this |
| `TowTrack::HandlePathStruct` (control, size-clean) | 0 / 3 | 0 / 3 | control behaves |

Consequence for triage: **`CalculateSpline` and `Act3::Enable` are not missing
any statement** — both are pure register-role rows whose length defect is an
encoding side effect. Do not spend read-off time reconstructing text for them;
they need the carrier channel (or nothing). Run this census first on every
±1 row in the project.

### `LegoLOD::Read` 0x100aa510 — the wave-1 frame lead confirmed at byte level

Prologue, ours vs retail:

```
+24  OURS   81 ec 70 01 00 00   sub esp, 0x170
+24  RETAIL 81 ec 74 01 00 00   sub esp, 0x174        <- 4 bytes more frame
```

and the zero-init run differs in both slot numbers and order:
ours `[-0x34] [-0x30] [-0x38] [-0x48] … [-0x2c] [-0x28]`,
retail `[-0x3c] [-0x38] [-0x40] [-0x48] …`. So retail really does carry **one
extra 4-byte named local** that our text does not declare, and the whole slot
map is shifted by it — which is why nd is 312 despite the body being only one
byte short.

The `// TODO: Can't get this one right` site (legolod.cpp:190-192) remains the
likeliest home for it: retail almost certainly named an intermediate for the
packed `tempNumVertsAndNormals` word extraction, e.g. a `LegoU16*` cursor or a
`LegoU16 packed` temp, instead of our two casts of `&tempNumVertsAndNormals`.
That is a *bounded* search (the extra local's slot is between −0x3c and −0x48)
and is the single best text-channel target left in this lane. The EAX census
above rules the −1 out as the encoding artefact, so the −1 and the extra local
are two separate defects.

Three seed-lane probes for the missing local (19 bodies in the TU, all
line-neutral, the new declaration placed on the blank line at shadow 170):

| variant | len/nd | frame | victims |
|---|---|---|---|
| base | 1694/312 | 0x170 | — |
| l1 `LegoU16* packed = &tempNumVertsAndNormals` cursor, `packed[0]`/`packed[1]` | 1694/312 | 0x170 | **0 — bit-inert** (the pointer is fully optimised away, no slot) |
| l2 `LegoU16 packedVerts` value temp for the low half | 1694/**310** | 0x170 | 3 (target + two others) — best so far but still no extra slot |
| l3 `LegoU32 packedVertsAndNormals` shadow copy | 1699/1353 | — | 3 — much worse |

So the extra retail local is **not** a scalar temp at this site: MSVC folds all
three away without growing the frame. Whatever retail declared, it must be
address-taken or aggregate (array/struct) to earn a slot. Confirmed
`LegoLOD::Read` needs its own session, as wave 1 said.

### `Act3Ammo::Animate` 0x10054050 (+1) — read off, register-role again

EAX census: ours 1 short / 1 long, retail 1 short / 1 long — the +1 is not an
encoding artefact. First real divergence is at body+967 and it is the familiar
shape: ours `lea ecx,[ebp+esi-0xc0]` / `lea eax,[ebp+esi-0xbc]`, retail
`lea eax,[ebp+esi-0xc0]` / `lea ecx,[ebp+esi-0xbc]` — an eax↔ecx swap of the
two matrix-row address temporaries in the rotation loop, cascading through the
following ~900 bytes. Everything before body+51 is byte-identical, and the
first three diff bytes (49, 58, 68) are just branch displacements absorbing the
+1. BETA10 0x1001e362 was not read (the structure before the divergence already
matches, so a read-off has nothing to arbitrate).

### `LegoCarRaceActor::CheckPresenterAndActorIntersections` and `Act3Brickster::Animate`

EAX census on both: identical short/long counts in ours and retail, so their
+5 and +4 are structural (the `_Tree` `operator++` tail-merge for the former,
see above) rather than encoding.

## METHOD FINDING: the forward-run response is quasi-periodic in the count

`t/period.py` groups a sweep's states by (body length, nd) and prints the k-set
for each. The forward-run axis turns out to have a **TU-specific period**:

* `legoroi` `~LegoROI` (fwdE): the interesting family is
  **k ≡ 31 (mod 64)** — k = 31, 95, 159, 223, 287 all reach retail's 210-byte
  length. Four of them are nd=1; **k=159 is the deviation that is nd=0** (the
  landing). A second family (len 209, nd 142) sits at k = 109, 173, 237 —
  again stride 64.
* `act3actors` `Act3Brickster::Animate` (fwdE): the 1632-byte family is
  **k ≡ 59,60 (mod 64)** — 59/60, 123/124, 187/188, 251/252, 315, 379/380 —
  and a `--klist` probe of the same class out to **k=956** (18 further states)
  gives nd=7 at every one. The period is *exact* for this row, so the
  forward-run axis is now **exhausted** for it at a cost of 18 compiles instead
  of 600.
* `act3` `RemoveByObjectIdOrFirst`: no structure — nd=7 is simply the floor at
  163 of 304 counts. `TriggerHitSound`: nd=11 at *every* k from 97 to 400.
* `legowegedge` `LinkEdgesAndFaces`: local strides of 17/34/68 (nd=2 at
  fwdL-156 and fwdL-224), but the class does **not** persist — a `--klist`
  probe of 156+68n for n=4..12 (27 states, k up to 973) gives nd≥15. So the
  period is local here, not global.

**Operational rule:** run one dense window (say 1..128) to find the residue
classes, then (a) if the class is exactly periodic, a dozen `--klist` probes
across many periods either find the deviation or *prove exhaustion cheaply*;
(b) if it is not periodic, only a dense sweep is trustworthy. Either way, do
not assume k≤96 is the whole axis — `~LegoROI` proves it is not.
