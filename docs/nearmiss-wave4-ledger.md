# Near-miss finish line — wave 4 ledger (Lane NM)

Session: 2026-08-15 night, three-lane parallel wave. Lane NM worktree
`agent-abdfe085f8e94c6b0`, branch `worktree-agent-abdfe085f8e94c6b0` reset to
`entropy-stabilization` **53a19e9c**. Build dir `/Users/foxtacles/Projects/isle-build-nm01`
(length-matched to `isle-build-lean`, harness trap #1).

Baseline reproduced in this lane by a full cold gated run:
**LEGO1 4831/4933, ISLE 172/172, CONFIG 111/111.**

Owned TUs: `legoextraactor.cpp`, `legopathactor.cpp`, `legopathboundary.cpp`,
`legopathcontroller.cpp`, `legocharactermanager.cpp` (+ their headers).

Lane scratchpad: `/private/tmp/claude-501/-Users-foxtacles-Projects-isle/3233884b-d405-46dd-ab8c-ee0c06400055/scratchpad/nm/`

| tool | what it does |
|---|---|
| `probe.py` | generic donor-lane driver: (text-variant x include-permutation x carrier); logs **best-nd for every target, always** |
| `axes.py` + `sweep.sh` / `sweep2.sh` | expand `fwd/shape/shapefull/padgrid/extern` into carrier lists |
| `rescore.py` | re-score already-compiled objects against a new oracle set (no compiles) |
| `scan.py` | score the whole retained prior-wave corpus for a TU |
| `ctx.py` | byte context around each masked diff |
| `disx.py` | capstone disassembly of the retail span and a candidate body, with call targets named from the reccmp report |
| `relcheck.py` / `relscan.py` | **the S72 semantic-relocation guard, mechanised** (below) |
| `mkoracle.py` | build a retail-span oracle for a row that has none |
| `gate.sh`, `landinto.sh`, `repin.py` | gated build / manifest landing / accepted-row re-pin, all repointed at this worktree |

Harness note for the coordinator: a fresh git worktree has **no `legobin/`**
(gitignored, lives only in the main checkout), so `isle_build.py` dies in
`verify_pins`. Fix: symlink `legobin -> /Users/foxtacles/Projects/isle/legobin`.

---

## 0. ORACLE CORRECTION APPLIED (coordinator directive, mid-session)

The coordinator's finding — `wave2-oracles.json`'s `retail_hex` was recorded as
`retail_image[addr : addr + OUR_seed_len]`, so 92/184 bodies are the wrong
length/bytes — was adopted. Everything below is scored against
`<coordinator scratchpad>/bench/oracles-v2.json` (true retail bodies, padding
stripped) with the **exact-length rule**: a candidate whose length differs from
retail's is not a near miss at all, it is a length defect.

What that invalidated in this lane, concretely:

* My first pass used the wave2 spans + the `nearmiss.py` pad-flex rule. For the
  rows where our body is the SHORTER one that rule was accidentally right, so
  the corpus table in §1 survives; but every number was re-measured under v2
  before being used. Both `scan.py` (corpus) and `probe.py` (fresh) now carry
  the v2 rule.
* **One coordinator claim does NOT survive contact with a carrier sweep**: the
  size ledger's "text-channel-only" verdicts are verdicts about the **seed**,
  not about the reachable set. Carriers *do* move body length in these TUs.
  Measured today, on the current text, with no source edit:

  | row | seed len | retail | reachable by carrier | best nd at retail length |
  |---|---|---|---|---|
  | 0x1002bff0 `_Tree<LegoPathActor*>::erase` | 1104 | 1096 | **93 of 653 states hit 1096** | **1** @434 |
  | 0x10082ca0 charmgr `erase` | 1104 | 1096 | 26 of 653 states hit 1096 | **1** @145 |
  | 0x100574a0 `LegoPathBoundary::RemoveActor` | 253 | 258 | 151 of 653 states hit 258 | **1** @240 |
  | 0x10083890 charmgr `_Insert` | 652 | 653 | 110 of 653 states hit 653 | **4** @[457,459,462,463] |

  So four of the coordinator's eight "text-channel" rows are in fact **one to
  four bytes from a landable donor on the carrier axis**. The correct rule is:
  *a length defect in the seed is not a proof of a text defect; it is a proof
  that the seed's carrier state is wrong.* Only rows where **no** carrier state
  reaches the retail length are text-channel (in my lane: `PlaceActor` x2 and
  `SetTransformAndDestinationFromPoints`, see §5).

---

## 1. Landed: 0x1002e8d0 `LegoPathActor::CheckPresenterAndActorIntersections`

`.9892 -> 1.0`, commit `f9c134a8`, gate `LEGO1 4831 -> 4832/4933`,
ISLE 172/172, CONFIG 111/111, **zero LOST rows**.

* Fresh full carrier sweep of `legopathactor.cpp` on today's shadow — 653
  states (fwdL/fwdP/fwdE 1..96, shape lattice, padgrid 12x12, extern 9x18),
  donor lane — found **16 retail-masked-exact states**, all producing the same
  561-byte body `a7ef431b6a2e8176…`:
  `fwdL-{62,63,95,96}`, `shape-{2-16,6-18,8-24,10-20}`,
  `pad-{2-8,3-12,5-4,6-3,7-7,8-3,9-12,10-2}`.
* Landed `declaration_shape(2,16)` as a second donor on the existing
  legopathactor unit; splice class `equal_body_eh_structural_local`.
* Relocation guard (below) run before landing: **17/17 relocation targets agree
  with retail's callee identities**; the only differences vs the seed are the
  compiler-local `$L69961` / `$T70206` label ids — the standard landable shape.
* The wave-3 record ("fwdL-6, nd=1, RE-DIALED to nd=2 today") was correct *for
  that shadow*; on today's shadow fwdL-6 is nd=2 and the winners are elsewhere.
  **Never re-use a state label across shadows; re-sweep.**

---

## 2. NEW INSTRUMENT: the S72 semantic-relocation guard, mechanised

`relcheck.py <obj> <mangled-prefix> <row-va> [<seed-obj>]` decodes the **retail
bytes** at every relocation site (rel32 -> `va + off + 4 + disp`), names the
target from the reccmp report, and prints it beside the candidate's relocation
symbol. `relscan.py <root> <mangled-prefix> <offs>` does the same for a whole
probe tree and tallies the distinct call-target signatures.

This is the oracle guard the sweeps never had, and it is cheap. **Run it on
every nd==0 donor before landing.** It is what proves a landing (§1) and what
kills a false positive (§3).

---

## 3. 0x10084030 `CreateActorROI` — the S72 trap re-diagnosed (it is NOT a wrong-type bug)

`relcheck.py` on the nd=0 donors reproduces the trap exactly: at body offsets
**101** and **1220** retail calls `Vector3::Vector3` (`0x1001d150`) where every
one of our objects calls `Vector2::Vector2` (`0x1000c0f0`). Offsets 77 and 1192
agree (`Vector2::Vector2` both sides). All other 79 relocations agree.

Disassembling the retail prologue (`disx.py`) shows what is really going on —
three *identical* `Mx3DPointFloat` sub-object constructions with three
*different* inline depths:

```
+43  mov  edi, 0x100d4488            ; Mx3DPointFloat vftable, hoisted
+64  mov  [ebp-0x114], eax           ; obj1 (boundingSphere.center) m_data — FULLY INLINE
+70  mov  [ebp-0x118], edi
+76  call Vector2::Vector2           ; obj2 (boundingBox.min)  — one level less
+94  mov  [ebp-0xe8], edi
+100 call Vector3::Vector3           ; obj3 (boundingBox.max)  — two levels less
+111 mov  [ebp-0xd4], edi
```

obj1/obj2/obj3 sit at `ebp-0x118`, `ebp-0x148+…` `ebp-0xe8`, `ebp-0xd4`
(0x14 apart = `sizeof(Mx3DPointFloat)`, i.e. `BoundingBox::min`/`::max`). This
is a **monotonic C2 inline-budget ladder**, not a semantic type error: our
compile keeps one more expansion of budget at obj3 and therefore emits the
`Vector2::Vector2` call that `Vector3::Vector3(float*)`'s trivial forwarding
body would itself have emitted. The two bodies are byte-identical because
`Vector3::Vector3(float*)` is a pure forward to `Vector2::Vector2(float*)`.

Consequences (all measured):

* The old framing ("making `g_actorLODs` const changed 23 semantic
  relocations", "reverting const is inadmissible") is a **correlation, not the
  mechanism**. The mechanism is the inline budget in
  `LegoCharacterManager::CreateActorROI`.
* **The carrier axis cannot reach it.** `relscan.py` over
  348 prior-corpus states + 653 fresh full-sweep states + 120 include-perm
  product states = **1121 states, 100% `(Vector2, Vector2)`**. Zero hits.
  This axis is CLOSED for this row; do not re-sweep it.
* Because our frame displacements are byte-identical to retail (nd=0 with the
  `[ebp-0x…]` bytes unmasked), our **local declaration order is already
  correct**; a declaration-order edit cannot be the fix without breaking nd=0.
* The remaining lever is whatever changes the C2 inline pool **without changing
  any emitted byte** — which points at the *header* definitions
  (`Mx3DPointFloat` / `Vector3` / `Vector2` ctor bodies in `mxgeometry3d.h` /
  `vector.h`, or `BoundingBox`'s member order in `realtime.h`), i.e. **outside
  this lane's TU list**. Recorded, not attempted. This is exactly the row the
  fresh-eyes C4 pool-dump instrument was specified for.

---

## 4. The near-miss table on TODAY's shadow (v2 oracles, exact-length rule)

Every number below is from a fresh 653-state donor-lane sweep of the owning TU
on this worktree's shadow (`nm/rescore-<root>.jsonl` has the per-state map).

### legocharactermanager.cpp (`nm/probes/chm-full`, 653 states)

| addr | row | retail len | best nd | offsets | state |
|---|---|---|---|---|---|
| 0x10082ca0 | `_Tree<char*,LegoCharacter*>::erase` | 1096 | **1** | [145] | `fwdL-69`, `fwdP-69`, `pad-2-9` |
| 0x10083890 | `_Tree<char*,…>::_Insert` | 653 | **4** | [457,459,462,463] | `fwdL-35`, `fwdP-35`, `pad-1-9`, `pad-3-9` |
| 0x10083500 | `GetActorROI` | 822 | 4 | [501,504,506,508] | 20 states (`fwdE-23`, `extern-0-6`, …) |
| 0x10084030 | `CreateActorROI` | 2294 | 0 (FALSE POSITIVE, §3) | — | many |
| 0x10085500 | `_Tree<char*,…>::insert` | 653 | 12 | [400,402,405,414,…] | `fwdL-66` |

The **offsets [501,504,506,508] are invariant over all 653 states** for
GetActorROI, and **[457,459,462,463] invariant over all 653** for `_Insert`:
those residues are text-channel, the carrier has already done all it can.

### legopathboundary.cpp (`nm/probes/lpb-full`, 653 states)

| addr | row | retail len | best nd | offsets | state |
|---|---|---|---|---|---|
| 0x100574a0 | `RemoveActor` | 258 | **1** | [240] | 21 states (`extern-0-11`, `extern-0-14`, `fwdE-11`, `fwdP-14`, …) |
| 0x100586e0 | `RemovePresenter` | 314 | **3** | [194,197,199] | `fwdP-15` |
| 0x10057180 | `_Tree<LegoAnimPresenter*>::_Erase` | 57 | 7 | [4,10,20,23,31,34,44] | `fwdL-46` |
| 0x10057fe0 | `AddPresenterIfInRange` | 214 | 44 | [19..25,37,38,39,41,42] | `extern-6-0` |

`RemoveActor` residue @240: ours `3b 5c 24 10` (`cmp ebx,[esp+0x10]`) vs retail
`39 5c 24 10` (`cmp [esp+0x10],ebx`) — a CMPDIR at the inlined
`set::erase(key)` loop bottom. **Offset 240 is not invariant**: `pad-10-3`,
`pad-4-11` and `shape-10-30` fix it and break [45,129,203] instead. Both halves
are reachable separately, so the product axis is live for this row.

### legoextraactor.cpp (`nm/probes/lea-full`, 653 states)

| addr | row | retail len | best nd | offsets | state |
|---|---|---|---|---|---|
| 0x1002bff0 | `_Tree<LegoPathActor*>::erase` | 1096 | **1** | [434] | `extern-{0-9,1-8,…,8-1}` (the M+K=9 diagonal), `fwdE-9`, `fwdP-9` |
| 0x1002a720 | `StepState` | 876 | 6 | [635,639,649,655,670,676] | `extern-1-12` |
| 0x1002aba0 | `HitActor` | 1617 | 7 | [889,892,894,897,964,967,977] | `extern-5-11` |

Offset 434 is invariant over all 93 length-1096 states (residue is the
`3b fa` = `cmp edi,edx` vs retail `3b d7` = `cmp edx,edi` **register-role tie**
recorded by wave 3).

**This changes the donor-debt verdict.** The bisect ledger and wave 3 both said
`0x1002bff0` reaches nd=0 only on "varab" text. That remains true for nd=0, but
on *current* text (with the `find` pin intact, `HitActor`/`StepState` intact)
the row is **one register-role byte away at the correct 1096 length**. Attacking
that one byte is strictly cheaper and strictly safer than the varab trade, and
it needs no `find` re-cover and no `HitActor`/`StepState` story.

### legopathactor.cpp (`nm/probes/lpa-full`, 653 states)

| addr | row | retail len | best nd | offsets | state |
|---|---|---|---|---|---|
| 0x1002e8d0 | `CheckPresenterAndActorIntersections` | 561 | **0 — LANDED** | — | 16 states |
| 0x1002f770 | `UpdatePlane` | 188 | 5 | [59,61,72,74,76] | `extern-0-1` |
| 0x1002de10 | `SetTransformAndDestinationFromPoints` | 743 | — | — | **no state reaches 743; ours is 746 everywhere** -> text channel |

---

## 5. Negatives recorded (swept extent stated; do not re-run these)

1. **`0x10082ca0` charmgr `erase`, include-order product** — 40 include
   permutations x {`fwdL-69`, `fwdP-69`, `pad-2-9`} = **120 states**, plus the
   653-state full carrier sweep = 773 states. Body offset 145 is `3b` in
   **every single one**; nd never left 1. (`nm/probes/chm-prod`,
   `nm/chm-prod.log`.) The include-order axis does not reach this bit.
2. **`0x10084030` `CreateActorROI` call-target pattern** — 1121 states, 100%
   `(Vector2,Vector2)` at offsets 101/1220. Carrier axis and include-order axis
   both CLOSED (§3).
3. **`0x10083500` `GetActorROI`** — offsets [501,504,506,508] invariant over
   653 carrier states. Carrier axis exhausted at nd=4; needs the bisect
   ledger's `h12` text edit (see §6).
4. **`0x10083890` charmgr `_Insert`** — offsets [457,459,462,463] invariant
   over 653 carrier states.
5. **`0x1002de10` `SetTransformAndDestinationFromPoints`** — no carrier state
   in 653 produces retail's 743-byte length (ours is 746 in all of them).
   Genuinely text-channel, +3 bytes.
6. **`0x10048310` `FindPath`** — corpus min-nd 1741; today's oracle says ours
   2337 vs retail 2338. Text channel, permanently out of carrier queues
   (confirms the prior seal).

---

## 6. NEW AXIS: interior declaration records (the manifest already supports it)

The carrier grammar used by every sweep to date places records in three seats:
file start (`fwdL`), after the include block (`fwdP` / `extern` header) and EOF
(`fwdE` / `extern` seat). But `tools/byte_identity_manifest.json`'s
`source_overlay` already carries `insert` ops anchored **anywhere inside a TU**
(`{"anchor": {"ctx": …, "line_before": …, "line_after": …}}` with `empty_class`
/ `fwd` / `fwd_run` / `class` items) — legopathboundary.cpp has four such ops,
legocharactermanager.cpp has six. **Interior record position is therefore a
landable, typed channel that no sweep had ever explored.**

`probe.py` now implements it as two carrier kinds:

* `insf:<anchor>:<count>` — `entropy.generate_forward_run("RkNm", count, 3)`
  inserted immediately before anchor;
* `insc:<anchor>:<count>` — a run of `class RkNm%03d {};` empty classes;

where anchors are the `// FUNCTION:` / `// SYNTHETIC:` / `// GLOBAL:`
annotation-block starts (9 in legopathboundary.cpp, 46 in
legocharactermanager.cpp).

It is a real axis — e.g. on legopathboundary it moves `??1LegoPathBoundary`
between nd=0, 1 and 2 across anchors and counts — but see the negatives below:
it did not reach any of the three surviving one-byte ties.

---

## 7. `0x10083500 GetActorROI` — COMPLETE RECIPE, blocked on one victim

**The row is landable.** On the `h12` text (the bisect ledger's two named
temporaries, re-verified here on today's shadow) `GetActorROI` is
**retail-masked-exact at 822 bytes, body sha
`a574d9690310e6f37896d160f1e68625f56e297ffbb21012f033ef2d8339e5d5`**, in ~30
donor-lane states: `fwdE-{4,5,6,21,39,56,57,60,74,95}`,
`extern-{0-4,0-5,0-6,1-3,1-4,1-5,1-6,2-3,2-4,2-5}` and more. This is the exact
body the donor-debt bisect ledger recorded, reproduced independently.

Text (both hunks required; each alone gives 825 bytes = wrong length):

```diff
--- a/LEGO1/lego/legoomni/src/common/legocharactermanager.cpp
+++ b/LEGO1/lego/legoomni/src/common/legocharactermanager.cpp
@@ LegoROI* LegoCharacterManager::GetActorROI(const char* p_name, MxBool p_createEntity)
-			char* name = new char[strlen(p_name) + 1];
+			MxU32 length = strlen(p_name) + 1;
+			char* name = new char[length];
@@
-			GetActorInfo(p_name)->m_actor = actor;
+			LegoActorInfo* info = GetActorInfo(p_name);
+			info->m_actor = actor;
```

**Seed-lane victim accounting** (exact-replica compile at a length-matched
mirror root, `nm/seedlane/chm-h12/`): 123 of 132 .text COMDATs bit-identical.
The nine that move are

| body | seed len -> h12 len | status | cover on h12 |
|---|---|---|---|
| `GetActorROI` | 822 -> 822 | target | **nd=0** (30 states) |
| `~_Tree<char*,LegoCharacter*>` 0x10082b90 | 196 -> 196 | **1.0 victim** | **nd=0** (`extern-0-10`, `fwdE-2`, …) |
| `~list<ROI*>` 0x10084930 | 100 -> 100 | composed pin | **nd=0** (`extern-8-17`) |
| `ReleaseAutoROI` 0x10083f10 | 248 -> 248 | composed pin | **nd=0** (`extern-0-1`, `none`) |
| `SwitchSound` 0x10085090 | 47 -> 47 | composed pin | **nd=0** (`fwdL-10`) |
| `Exists` 0x10083b20 | 148 -> 148 | **1.0 victim** | **NO COVER — nd=6, see below** |
| `erase` 0x10082ca0 | 1104 -> 1101 | open (.68) | regresses 1 -> 19 |
| `_Insert` 0x10083890 | 652 -> 655 | open (.71) | 4 |
| `insert` 0x10085500 | 653 -> 653 | open (.92) | 12 |
| `CreateActorROI` 0x10084030 | 2294 -> 2294 | open (.94) | nd=0 but §3 trap |

So the landing is **one victim away**: everything else, target and pins
included, has a retail-exact donor state on h12 text.

### The `Exists` blocker, characterised precisely

`Exists`'s h12 residue is a fixed **two-instruction scheduling swap** at body
offsets 118–123 (6 bytes):

```
ours  : … 8b 00  [8b 0e]  [89 44 24 10]  8b 41 04 …   ; mov ecx,[esi] ; mov [esp+0x10],eax
retail: … 8b 00  [89 44 24 10]  [8b 0e]  8b 41 04 …   ; mov [esp+0x10],eax ; mov ecx,[esi]
```

Swept on h12 text, all at length 148, **nd=6 with those identical offsets in
every single state**:

* 653 carrier states (fwdL/fwdP/fwdE 1..96, shape lattice, padgrid 12x12,
  extern 9x18) — `nm/probes/chm-h12`;
* 368 interior-record states (`insf`, anchors 0..45, counts 1..8) —
  `nm/probes/chm-h12-ins`;
* a focused interior run around `Exists`' own anchor (`insc`+`insf`,
  anchors 17..21, counts 1..24) — `nm/probes/chm-h12-ins2`;
* 5 `Exists` text cells x 5 carriers: `!(it == end())`, `end() != it`,
  hoisted `end` local, split declaration, single-expression `return` — all
  nd=6 (and the single-expression form additionally costs GetActorROI its
  nd=0). Comparison-spelling mirrors are canonicalized here, confirming the
  wave-2 finding.

**Recipe for the coordinator (do not land until `Exists` is covered):**
* text: the two hunks above, then `python3 tools/repin_overlay.py LEGO1/lego/legoomni/src/common/legocharactermanager.cpp`
* donor for `GetActorROI`: `forward_declaration_run` placement `suffix`,
  prefix `MxUnkRecVC`, count 4, width 3 (state `fwdE-4`) — expected body length
  822, sha `a574d969…8339e5d5`
* donors to re-cover: `~_Tree` (`extern-0-10`), `~list<ROI*>` (`extern-8-17`),
  `ReleaseAutoROI` (`extern-0-1`), `SwitchSound` (`fwdL-10`)
* still missing: any state that makes `Exists` retail-exact on h12 text.

---

## 8. `0x100574a0 LegoPathBoundary::RemoveActor` — nd=0 exists, on ONE line of text

`RemoveActor`'s body is a single statement (`m_actors.erase(p_actor);`), so it
has no text of its own; the beta10 foundry ledger classed it STATE-CLASS. On
today's text the carrier axis gets it to **258 bytes / nd=1 at offset 240**
(`3b 5c 24 10` = `cmp ebx,[esp+0x10]` vs retail `39 5c 24 10`) in 21 states,
and that byte survives:

* 653 carrier states (`nm/probes/lpb-full`),
* 600 include-permutation product states (all 120 permutations of the five
  quoted includes x `extern-0-11`, `extern-0-14`, `fwdE-11`, `pad-10-3`,
  `shape-10-30`) — `nm/probes/lpb-prod`,
* 216 interior-record states (`insf`+`insc`, anchors 0..8, counts 1..12) —
  `nm/probes/lpb-ins`.

**1469 states, offset 240 never flips.**

It flips on **one line of source**. Diffing the retained corpus state that the
coordinator's rescore flagged (`sweep2-all2-legopathboundary/pad-10-12`, nd=0)
against today's rendered text gives exactly one differing line — the
`~LegoPathBoundary` loop condition:

```diff
-	for (LegoPathActorSet::iterator it = m_actors.begin(); it != m_actors.end(); it++) {
+	for (LegoPathActorSet::iterator it = m_actors.begin(); !(it == m_actors.end()); it++) {
```

Re-derived on today's shadow (`nm/probes/cell-lpb-d32`): with that single line
reverted, **`RemoveActor` is retail-masked-exact at 258/258 in state
`pad-10-12`**, and `??1LegoPathBoundary` lands at 380 bytes / nd=1 (offset 195)
rather than being lost outright.

**Why this is not landed here.** Two reasons, both recorded rather than
guessed:

1. **It contradicts BETA10.** `docs/beta10-foundry-ledger.md` reads BETA10
   `0x100b140d` as calling the 2-arg cdecl free `operator!=`, i.e. June spelled
   this loop `it != m_actors.end()`; that spelling is what makes
   `~LegoPathBoundary` (0x10057260) exact today.
2. **Five currently-1.0 rows become victims.** Seed-lane accounting
   (`nm/seedlane/lpb-d32/`): 63 of 74 COMDATs identical; the movers are
   `??1LegoPathBoundary` 380->385, `erase<LegoAnimPresenter*>` 1102->1112,
   `insert<LegoAnimPresenter*>` 613, `_Insert<LegoAnimPresenter*>` 634->637,
   `equal_range<LegoAnimPresenter*>` 110, plus `RemoveActor` 253->258 (the
   target), `AddPresenterIfInRange` 214 and `RemovePresenter` 314 (both open),
   and the two `_Tree<LegoPathActor*>` bodies this TU loses at link anyway.

So the landing is: revert that line + a `pad_shape(10,12)` donor for
`RemoveActor` + re-cover donors for those five rows, each of which needs its
own nd=0 state on the reverted text (**not measured — one 653-state sweep
away**). Net +1 if all five cover, net negative otherwise. Flagged for the
coordinator as a decision, not taken unilaterally, because of the BETA10
tension.

**The generalisable finding**: a vendor-template one-byte tie in function *A*
can be flipped by a comparison spelling in an unrelated function *B* of the
same TU. Text cells for a state-class row should therefore be searched over the
**whole TU**, not just the row's own statements.

---

## 9. Which swept states are actually LANDABLE as donors (read this before celebrating an nd=0)

`byte_identity.py:8015` restricts `compose_equal_body_comdat` donors to three
recipe kinds, and `forward_declaration_run.placement` to
`prefix | force_include | suffix`. Mapping that onto the sweep axes:

| sweep axis | generator | landable donor? |
|---|---|---|
| `shape-c-f` | `entropy.generate_shape` | **yes** — `declaration_shape` |
| `fwdL-k` | `generate_forward_run` prepended | **yes** — placement `prefix` |
| `fwdE-k` | appended | **yes** — placement `suffix` |
| `fwdF-k` | rendered as the `/FI` header | **yes** — placement `force_include` (added to `probe.py` this session; never swept before) |
| `extern-m-k` | `generate_extern_run` x2 | **yes** — `extern_run_pair` (wave-3 addition) |
| `fwdP-k` | forward run after the include block | **NO** — no such placement in the grammar |
| `pad-c-f` | `generate_pad_shape` | **NO** — not a donor recipe kind at all |
| `insf/insc-a-k` | interior record run | **NO** — landable only as a `source_overlay` insert op, i.e. as *effective text*, not as a donor |

Three consequences that change how earlier records should be read:

1. Any historical "nd=0 at `pad-…`" or "nd=0 at `fwdP-…`" is **not a landing**
   as it stands — it needs an equivalent state in a supported kind. That
   includes the coordinator's `0x100574a0 @ pad-10-12` hit (§8).
2. The sweep axis set is *narrower* than the donor grammar in one place and
   *wider* in two others. `force_include` placement of a forward run was
   never swept by anybody; `probe.py --carriers fwdF:k` now does it.
3. The donor grammar's free `prefix` and `width` parameters are an entirely
   unswept dimension: `class A000;` and `class MxUnkRecVA000;` are different
   compile states. Every sweep to date fixed `width=3` and three specific
   stems.

---

## 10. legopathcontroller.cpp (`nm/probes/lpc-full`, 653 states, v2 oracles)

Two of its rows had **no oracle anywhere in the prior corpus** — they had never
been swept. `oracles-v2.json` supplies them, and this is their first measurement:

| addr | row | retail len | seed len | best nd | offsets | state |
|---|---|---|---|---|---|---|
| 0x10045c20 | `PlaceActor(LegoPathActor*, const char*, int, float, int, float)` | 338 | 331 | **2** | [195, 232] | `extern-1-16` (also `extern-{2-15,3-14,4-13,5-12,6-11,7-10}`) |
| 0x10046050 | `PlaceActor(LegoPathActor*, LegoAnimPresenter*, Vector3&, Vector3&)` | 703 | 693 | — | — | **no state reaches 703; only 693 and 700 occur** -> text channel |
| 0x10048310 | `FindPath` | 2338 | 2337 | 491 | [135,136,142,150,…] | `extern-0-12` |
| 0x10046770 | `RemoveActor` | 328 | 329 | 0 | — | `fwdE-94`/`fwdP-94` (already landed, reproduces) |

`0x10045c20` at nd=2 is the strongest untouched row in this lane and the
beta10-foundry ledger had classed it STATE-CLASS with no text lever — correct,
and now quantified: **two bytes**. `FindPath`'s corpus min-nd of 1741 is
superseded: at the correct 2338 length the best carrier state is 491, still
text-channel but not the hopeless number the seal recorded.

---

## 11. Interior-record axis results on the other TUs (negatives)

* `legocharactermanager.cpp`, current text, `insf` anchors 0..45 x counts 1..6
  (276 states, `nm/probes/chm-ins`): `erase` 0x10082ca0 best **nd=43** — far
  worse than the fwdL/pad carriers' nd=1. `_Insert` best 8, `insert` 15,
  `GetActorROI` 4, `Exists` 0 (it is already exact on this text).
  The interior axis is not a refinement of the flat carriers; it is a
  *different* region of the state space.
* `legopathboundary.cpp`, current text, `insf`+`insc` anchors 0..8 x counts
  1..12 (216 states, `nm/probes/lpb-ins`): `RemoveActor` still nd=1 @240;
  `??1LegoPathBoundary` moves between nd 0/1/2 (proving the axis is live in
  this TU); `RemovePresenter` best 4, `_Erase` best 10.

---

## 12. `0x10083500 GetActorROI` — the interior-record op closes `Exists`; one victim left

Following §6/§7: the `Exists` blocker **is** solvable, by the interior-record
channel, and the op is authored and dry-run-validated below.

**Measured.** On the h12 text, `insc` (empty-class runs) at anchors 17, 18 or
19 with **count exactly 18** makes `Exists` retail-masked-exact
(`nm/probes/chm-h12-ins2`; counts 1..24 x anchors 17..21 x {insf,insc} = 240
states, only the three count-18 cells hit).

Rendering that state as effective text (`nm/texts/chm-h12j.cpp` = h12 + 18
`class RkNm0xx {};` immediately before `// FUNCTION: LEGO1 0x10083b20`) and
sweeping the standard 653 carrier states over it (`nm/probes/chm-h12j`) gives:

| body | addr | seed nd | best donor nd | donor state |
|---|---|---|---|---|
| `GetActorROI` | 0x10083500 | 2 | **0** | `fwdE-20` |
| `Exists` | 0x10083b20 | **0 (seed)** | 0 | — no donor needed |
| `~LegoCharacterManager` | 0x10083180 | 1 | **0** | `fwdL-1` |
| `~_Tree<char*,LegoCharacter*>` | 0x10082b90 | 5 | **0** | `fwdL-4` |
| `SwitchSound` | 0x10085090 | 2 | **0** | `fwdL-4` |
| `ReleaseAutoROI` | 0x10083f10 | 1 | **0** | `fwdE-12` |
| `~list<ROI*>` | 0x10084930 | 2 | **0** | `fwdL-2` |
| `ReleaseActor(const char*)` | 0x10083c30 | 2 | **0** | `fwdE-1` |
| `ReleaseActor(LegoROI*)` | 0x10083db0 | 1 | **0** | `fwdL-66` |
| **`GetRefCount`** | **0x10083bc0** | **1** | **1 @84 — NO COVER in 653 states** | — |

`GetRefCount`'s residue is a register-role tie: ours `3b f2` (`cmp esi,edx`),
retail `3b d6` (`cmp edx,esi`), at body offset 84, invariant across all 653
states.

### The overlay op, authored and dry-run-proven

`nm/mkop.py` computes the 32/32 token-context sha and the surrounding physical
line shas for a seat; `nm/tryop.py` applies the h12 clean edit plus the op to a
sandbox copy of the tree, runs the real
`byte_identity.validate_source_overlay` + `render_source_overlay_outputs`, and
compares. Result: **`RENDER MATCHES the measured probe text EXACTLY`**
(29699 bytes both sides). The op to append to
`source_overlay.outputs[LEGO1/lego/legoomni/src/common/legocharactermanager.cpp].ops`
(after the h12 clean edit, then `tools/repin_overlay.py <that path>`):

```json
{"op": "insert",
 "anchor": {"ctx": "69774eccf3b2ba346e09cfb40dfe66482291ebfff4f2a1dc07a29780ff3373da",
            "line_before": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "line_after": "f8d34f6d5a677937388a47db04466f7a40dddc9132a70347c3820c0329c861df"},
 "gen": {"k": "seq", "lines": 19,
         "items": [{"k": "empty_class", "id": "RkNm000", "line": 1},
                   ... "RkNm001".."RkNm017" at lines 2..18 ...]}}
```

(The full JSON is `nm/op-exists.json`. The identifiers are load-bearing —
`RkNm%03d` is what was measured; any other stem is a different compile state.)

**Status: NOT LANDED, one row short of zero-loss.** Landing it today would
close 0x10083500 (+1) and lose 0x10083bc0 (-1). All three follow-up directions
were run tonight and all three are negative — `GetRefCount` is nd=1 at offset
84 in **1,859 states**:

| search | states | GetRefCount best |
|---|---|---|
| 653 standard carriers on h12j (anchor-19 op) | 653 | 1 @84 |
| 653 standard carriers on h12i (anchor-17 op) | 653 | 1 @84 |
| a **second** interior op before `GetRefCount` (anchor 20, `insf`+`insc`, counts 1..24) on h12j | 48 | 1 @84 |
| the **full 505-cell `shape` grid** (c=1..10, f=c..10c) on h12j | 505 | 1 @84 |

The full shape grid is worth recording separately because it also **reproduces
the donor-debt bisect ledger's state exactly**: on plain h12 text
`GetActorROI` is retail-exact at `shape-7-52`, the off-lattice cell that
ledger named. So the grid is doing its job; `GetRefCount`'s `3b f2` -> `3b d6`
tie simply does not live in the declaration-record state space.

Three more directions were then run, all negative, bringing the total to
**2,197 states with `GetRefCount` nd=1 @84 in every one**:

| search | states | result |
|---|---|---|
| new donor prefix `MxUnkRecVD` x placements `force_include`/`prefix`/`suffix` x counts 1..96, width 3 (`nm/probes/chm-h12j-fw`) | 288 | 1 @84 |
| five text cells **inside `GetRefCount` itself** x 10 carriers (`nm/probes/grc-chm-h12jG{1..5}`) | 50 | 1 @84 |

The five cells were: swap the `character`/`it` declarations; hoist `roi` out of
the loop; `!(it == end())` loop condition; mirror the hit test to
`p_roi == roi`; and delete the named `roi` temporary entirely. **All five give
byte-identical 108-byte bodies with the same single wrong byte** — the
`character`/`roi`/`it` register assignment in this function is completely
insensitive to its own source text. That is a strong, transferable result: for
a tie of this class, do not spend text cells on the row itself.

(Both new axes are nonetheless live and worth keeping: `force_include`
placement produced `Exists` nd=0 at `fw-fi-MxUnkRecVD-14-3` and `GetActorROI`
nd=0 at `fw-suffix-MxUnkRecVD-20-3`, i.e. it reaches states the three historical
fwd placements do not.)

Remaining direction: the C2 pool/allocator instrument (fresh-eyes C4), or
accept the trade only once `GetRefCount` is closed independently.

---

## 13. Residue anatomy of the remaining lane rows (read-offs, for the text lane)

Every residue below was disassembled with `nm/disx.py` against the retail span
and the best candidate object, so the *class* of each defect is now recorded
rather than guessed.

* **0x10057180 `_Tree<LegoAnimPresenter*>::_Erase` (.6522, 57 bytes, nd=7)** —
  a clean **two-register role swap over the whole body**: retail keeps `this`
  in `esi` and the node walker in `ebx`; ours does the opposite
  (`mov ebx,ecx` / `mov esi,edi` vs retail `mov esi,ecx` / `mov ebx,edi`), and
  every subsequent use follows. Not a scheduling or CMPDIR defect — a single
  allocation decision at function entry. 653 carrier + 216 interior states all
  keep our assignment.
* **0x10082ca0 charmgr `erase` (nd=1 @145)** — CMPDIR: ours
  `3b 4c 24 10` (`cmp ecx,[esp+0x10]`), retail `39 4c 24 10`
  (`cmp [esp+0x10],ecx`), in the node-unlink path of the inlined rebalance.
* **0x1002bff0 extraactor `erase` (nd=1 @434)** — register-role tie:
  ours `3b fa` (`cmp edi,edx`), retail `3b d7` (`cmp edx,edi`).
* **0x100574a0 `RemoveActor` (nd=1 @240)** — CMPDIR: ours `3b 5c 24 10`,
  retail `39 5c 24 10`, at the `set::erase(key)` loop bottom.
* **0x10083bc0 `GetRefCount` on h12j (nd=1 @84)** — register-role tie:
  ours `3b f2` (`cmp esi,edx`), retail `3b d6` (`cmp edx,esi`).
* **0x10083b20 `Exists` on h12 (nd=6 @118-123)** — two-instruction schedule
  swap: retail spills `eax` to `[esp+0x10]` before reloading `ecx` from
  `[esi]`; ours reloads first.
* **0x10083500 `GetActorROI` on current text (nd=4 @501,504,506,508)** and
  **0x10083890 `_Insert` (nd=4 @457,459,462,463)** — both invariant over all
  653 carrier states; text channel (h12 closes GetActorROI, §12).

**Landability caveat for `RemovePresenter` 0x100586e0**: its nd=3 states are
`fwdP-15`, `fwdP-51` and `pad-7-9` — all three are **non-landable donor kinds**
(§9). The best state in a landable kind is nd=4 (`fwdL-52`). Anyone quoting
"RemovePresenter is 3 bytes away" should quote 4.

---

## 14. Full `shape` grid results (505 cells, c=1..10 x f=c..10c)

Run on two texts; both confirm the bisect ledger's "off-lattice f values
matter" rule and both are negative for the target byte.

* `legocharactermanager.cpp`, h12 text (`nm/probes/chm-h12-sf`):
  `GetActorROI` **nd=0 at `shape-7-52`** — the exact off-lattice cell the
  donor-debt ledger named, independently reproduced. `Exists` nd=6 in all 505.
* `legocharactermanager.cpp`, h12j text (`nm/probes/chm-h12j-sf`):
  `GetActorROI` nd=0 at `shape-4-31`, `Exists` nd=0 at `shape-1-3`,
  `GetRefCount` nd=1 @84 in all 505.
* `legoextraactor.cpp`, current text (`nm/probes/lea-sf`):
  `_Tree<LegoPathActor*>::erase` best **42** — far worse than the extern
  diagonal's nd=1. `StepState` 19, `HitActor` 29,
  `LegoExtraActor::CheckPresenterAndActorIntersections` nd=0 at
  `shape-{6-57,10-37,10-48}` (the landed row, reproducing).
  **The shape family is simply not this row's axis**; `extern`/`fwdE` at
  M+K=9 is, and the nd=1 states there (`extern-{0-9..8-1}`, `fwdE-9`) are all
  landable donor kinds.

---

## 15. Session summary

**Rows gained: 1** (proved end to end by a gated `isle_build.py` run from this
worktree).

| row | before | after | proof |
|---|---|---|---|
| 0x1002e8d0 `LegoPathActor::CheckPresenterAndActorIntersections` | .9892 | **1.0** | `ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE: LEGO1 4832/4933, ISLE 172/172, CONFIG 111/111`, zero LOST |

**Rows attempted, with their best measured distance on today's shadow** (all
numbers against `oracles-v2.json`, exact-length rule):

| addr | row | best nd | landable-kind? | channel verdict |
|---|---|---|---|---|
| 0x10083500 `GetActorROI` | **0** on h12+op text | yes (`fwdE-20`, `shape-7-52`) | **landing blocked by one victim** (`GetRefCount`), everything else covered, §12 |
| 0x1002bff0 `_Tree<LegoPathActor*>::erase` | **1** @434 | yes (`extern-0-9`, `fwdE-9`) | reg-role tie; carrier + include-perm + shape grid exhausted |
| 0x10082ca0 charmgr `erase` | **1** @145 | yes (`fwdL-69`) | CMPDIR; carrier + 120 include-perms exhausted |
| 0x100574a0 `RemoveActor` | **1** @240 (0 on the d32 text) | `pad-10-12` is **not** landable | text lever found (§8), costs 5 victims |
| 0x10045c20 `PlaceActor(const char*)` | **2** @[195,232] | yes (`extern-1-16`) | first measurement ever; strongest untouched row |
| 0x100586e0 `RemovePresenter` | 3 (`fwdP`/`pad`), **4** in a landable kind | — | CMPDIR family |
| 0x10083890 charmgr `_Insert` | 4 @[457,459,462,463] | yes | invariant over 653 carriers -> text |
| 0x1002a720 `StepState` | 6 | yes (`extern-1-12`) | — |
| 0x1002aba0 `HitActor` | 7 | yes (`extern-5-11`) | — |
| 0x10057180 `_Erase` | 7 | yes (`fwdL-46`) | whole-body esi/ebx role swap (§13) |
| 0x1002f770 `UpdatePlane` | 5 | yes (`extern-0-1`) | not attacked |
| 0x10085500 charmgr `insert` | 12 | yes (`fwdL-66`) | — |
| 0x10057fe0 `AddPresenterIfInRange` | 44 | yes | — |
| 0x10084030 `CreateActorROI` | 0 masked, **FALSE POSITIVE** | — | inline-budget ladder, lever is outside this lane's TUs (§3) |
| 0x10048310 `FindPath` | 491 | — | text channel |
| 0x10046050 `PlaceActor(LegoAnimPresenter*)` | no length match | — | text channel |
| 0x1002de10 `SetTransformAndDestinationFromPoints` | no length match | — | text channel |

**What I would do next, in order:**

1. **Close `GetRefCount` 0x10083bc0** and the `GetActorROI` landing follows
   immediately — the op and all nine other donors are measured and the op's
   render is dry-run-proven byte-exact (§12). Search the two unswept donor
   dimensions first: the free `prefix`/`width` parameters of
   `forward_declaration_run`, and `force_include` placement.
2. **Run the same treatment on `0x10045c20 PlaceActor`** (nd=2, never swept
   before tonight): include-perm product and the interior-record axis on
   legopathcontroller.cpp.
3. **Decide the `0x100574a0` trade** (§8): one line of text buys the row but
   contradicts BETA10 and needs five re-covers; it needs a coordinator-level
   call plus one 653-state sweep on the reverted text.
4. **Take the three surviving one-byte ties to the C2 pool instrument**
   (fresh-eyes C4). They are all vendor-template register/CMPDIR ties, all
   invariant across every declaration-record axis we have; that is exactly the
   signature of a decision made inside C2's allocator, not in the record
   stream.
5. **Re-run every "closed" sweep whose oracle was length-wrong** (the
   coordinator's correction) with the exact-length rule *and* with best-nd
   logging. Four of my eight "text-channel" rows turned out to be 1-4 bytes
   away on the carrier axis once the oracle was right.

---

# Wave 4b — after the merge (stacked carriers, `pad_shape`/`after_includes`)

Worktree rebased onto `entropy-stabilization` **16620ba9**; baseline
re-measured from a full gated run: **LEGO1 4838/4933**, ISLE 172/172,
CONFIG 111/111. All five of my TU shadow sources are byte-identical to their
pre-merge state, and every row in my queue kept its exact `matching` value, so
the wave-4a distances above transferred — but they were all re-measured anyway
(`vec.h` was restored to pristine in this window and `legocharactermanager.cpp`
and `legopathactor.cpp` both include it).

## 16. LANDED: `0x10045c20 LegoPathController::PlaceActor(LegoPathActor*, const char*, int, float, int, float)`

`.9442 -> 1.0`, commit `56c4e430`, gate **LEGO1 4838 -> 4839/4933**,
ISLE 172/172, CONFIG 111/111, **zero LOST rows**.

This is the row that had no oracle anywhere in the prior corpus and had never
been swept by anybody; wave-4a's first measurement put it at nd=2 @[195,232]
and no single-axis state closed it. **The stacked carrier closes it.** Crossing
the `fwdE` axis with the declaration-shape lattice produced **35
retail-masked-exact states at 338 bytes**; the landed one is

```
stkE-6-1-3  =  forward_declaration_run(MxUnkRecVC, count 6, width 3) @ suffix
             + declaration_shape(classes 1, functions 3) force-included
```

as a `forward_run_with_shape` donor, splice class `same_slot_resize`
(seed 331 -> donor 338 = retail span).

Semantic-relocation guard before landing: **9/9 relocation targets agree** with
retail's callee identities (`RemoveActor`, `GetPathBoundary`, `Timer`,
`g_lastTimeTimerStarted`, `g_lastTimeCalculated`, `_Nil` x2, `iterator::_Dec`,
`_Insert`), and the donor's relocation sequence is identical to the seed's — no
`$L`/`$T` renumbering even.

Note for the bench: `land_into.py` now understands `stkE-K-C-F` / `stkL-K-C-F`
labels and emits the `forward_run_with_shape` recipe (my copy in
`nm/bench/land_into.py`).

## 17. The stacked axis on the other three priority rows — measured, negative

| row | best single-axis | best stacked | states | verdict |
|---|---|---|---|---|
| 0x1002bff0 `_Tree<LegoPathActor*>::erase` | **1** @434 (`extern-0-9`, `fwdE-9`) | **20** (`stkE-41-2-4`) | 120 | the shape half destroys the extern/fwd state; stacking is strictly worse here |
| 0x10082ca0 charmgr `erase` | **1** @145 (`fwdL-69`) | **2** @[145,434] (`stkL-68-2-6`) | 180 | worse |
| 0x100574a0 `RemoveActor` | **1** @240 | **1** @129 / @137 | 625 | *different byte*, see below |

**The `RemoveActor` finding is the interesting one.** Pooling all 1,278 states
measured for that row (653 flat + 120 stacked-lattice + 505 stacked-full-grid),
the residue distribution is:

| nd | offsets | states |
|---|---|---|
| 1 | [240] | 21 |
| 1 | [129] | 6 |
| 1 | [137] | 2 |
| 2 | [104,137] / [129,137] / [129,240] / [137,240] | 13 |
| 3 | [45,129,203] / [51,62,240] | 6 |

There are **three independent single-byte defects** (129, 137, 240). Every one
of them is individually fixable, and states exist with any *two* of the three
fixed — but **no state in 1,278 fixes all three**. The declaration-record state
space simply does not have a third dimension for this row.

That retro-explains §8: the one-line dtor-loop spelling change is exactly that
missing dimension — on the `d32` text `pad-10-12` gives nd=0, i.e. all three at
once. So `0x100574a0` is a genuine **text-channel** row after all, and the
"STATE-CLASS" verdict in `docs/beta10-foundry-ledger.md` should be revised.

Also re-derived on today's shadow, per the coordinator's request: **`pad-10-12`
does NOT give `RemoveActor` nd=0 on the current text** (it never did — the
retained corpus object that scored 0 was compiled from the pre-`!=` text). The
newly-landable `pad_shape` kind therefore does not hand this row over; it makes
the §8 recipe *landable* if the text trade is ever taken.

## 18. What the newly-landable kinds actually unlock in this lane (audit)

I re-mined every measurement I have taken (11 rescore files, ~4,900 scored
bodies) for hits that were unlandable before `pad_shape` / `after_includes`
existed. **There is exactly one, and it is not a landing:**

* `0x100586e0 RemovePresenter` — best nd goes from 4 (`fwdL-52`, landable) to
  **3** (`fwdP-15`, `fwdP-51`, `pad-7-9`, now landable).

No previously-discarded nd=0 exists at a `pad-*` or `fwdP-*` state anywhere in
my lane. The grammar gap was real and worth closing, but in this lane it buys
one byte on one row rather than a row.

## 19. `0x10083500 GetActorROI` — re-measured; the trade is confirmed, not taken

Re-verified on today's shadow, and the picture is now fully resolved:

* On the **h12** text alone: `GetActorROI` nd=0, and **every** other mover has
  an nd=0 donor state — `~_Tree`, `SwitchSound`, `ReleaseAutoROI`,
  `~list<ROI*>`, **and `GetRefCount` (nd=0, it is not a victim here)**. The one
  and only uncovered victim is `Exists` (nd=6 @118-123).
* On the **h12 + interior-record op** text (`h12j`): `Exists` is exact in the
  seed, and `GetRefCount` becomes the one uncovered victim (nd=1 @84).

So the interior op does not *solve* the problem, it *moves* it. Both halves are
now searched to exhaustion:

| blocker | text | axes searched | states | best |
|---|---|---|---|---|
| `Exists` | h12 | flat carriers, full 505-shape grid, interior records (`insf` all anchors, `insc`+`insf` around `Exists`), 5 comparison/declaration text cells, **stacked `stkE`/`stkL` x lattice** | **2,271** | 6 @[118..123] |
| `GetRefCount` | h12j | flat carriers x2 anchor variants, full 505-shape grid, second interior op, new prefixes/placements, 5 text cells inside `GetRefCount`, **stacked `stkE` x lattice** | **2,437** | 1 @84 |

`GetRefCount 0x10083bc0` is **1.0 today**, so per the coordinator's rule the
h12j landing is +1/−1 and is **not taken**. Recorded, with both donor sets
measured, for whoever closes either blocker.

## 20. `0x10084030 CreateActorROI` — the header lane, opened and closed by measurement

I built a header-variant axis for this (`probe.py --include-root <mirror>`,
null-probe verified: compiling through an unmodified mirror of the shadow tree
reproduces the base object's distances exactly).

The decisive measurement is not a sweep, it is three rows:

| rung of the inline ladder | row | status today |
|---|---|---|
| `Mx3DPointFloat::Mx3DPointFloat()` | 0x1001d170 | **1.0** |
| `Vector3::Vector3(float*)` | 0x1001d150 | **1.0** |
| `Vector2::Vector2(float*)` | 0x1000c0f0 | **1.0** |

**All three rungs are already byte-exact against retail.** Their cost inputs to
C2's inline pool are therefore identical to 1997's, and our `CreateActorROI`
body is byte-identical to retail's apart from which of the three symbols the
third construction calls. There is consequently **no header edit that changes
the ladder without breaking a row that is already exact** — confirmed by the
one cell I ran: rewriting `Vector2(float* p_data) { SetData(p_data); }` as
`{ m_data = p_data; }` (semantically identical, period-plausible) removes the
relocations at 101 *and* 1220 entirely — both constructions become fully inline,
which is the wrong direction — and it necessarily rewrites `Vector2::Vector2`'s
own 1.0 body.

**Verdict: `0x10084030` is not a source-channel row in any file.** It is a pure
C2 budget-accounting difference on the caller side. It belongs to the C4
pool-dump instrument and nothing else; I recommend removing it from every text
and carrier queue. (Blast-radius note for the record: `realtime/vector.h` is
included by essentially every geometry-touching TU, so even a working cell
would have had to be measured tree-wide.)
