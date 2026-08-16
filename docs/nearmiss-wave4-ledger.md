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
