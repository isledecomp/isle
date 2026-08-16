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
