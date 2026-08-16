# Fresh-Eyes 2 — validated breakthrough candidates

2026-08-15 late. Second fresh-eyes pass; everything below was MEASURED this
session (compiles + binary reads in the session scratchpad `fresh2/`), not
speculated. Baseline note: the live report at `isle-build-lean/LEGO1-report.json`
(ts 17:39) already reads **4826/4933 — 107 open rows** (memory's 4821/112 is
stale; the queue9/shrink landings are in).

Scratchpad tools referenced below:
`<scratch>/fresh2/{nearmiss,rederive,incperm,product,novelty,closest,dist,winner,winners_all,dispmap,orphans,c2check,perecon}.py`
where `<scratch> = /private/tmp/claude-501/-Users-foxtacles-Projects-isle/aa9d0cc1-fd32-4a6b-8d7e-b872f4bc8732/scratchpad`.

---

## C1. The near-miss ledger — the corpus already contains the next landings (VALIDATED: 2 rows land-ready tonight)

**Mechanism (new).** Every sweep to date used a *binary* oracle (masked nd==0
= HIT, else silence). All nd=1..7 states were discarded unrecorded. The
retained probe objects (~40k compiles across `sweep-bench/sweep2-*`) are a
mineable corpus. `nearmiss.py` scanned all of them against the wave2 retail
oracles, with a pad-verified flex rule (candidate len ≤ retail span AND the
uncovered tail is all `0xCC`).

**Measured results (kill-tests RUN):**

1. **`LegoAnimationManager::FUN_10064b50` 0x10064b50 (.9365) — retail-exact
   donor EXISTS and REPRODUCES on today's shadow.**
   State: `extern m=6 k=6` (sweep2 extern axis, `g_h` 6-run header seat +
   `g_p` 6-run post-include seat). Re-derived fresh (`rederive.py
   all2-legoanimationmanager extern-6-6 FUN_10064b50`):
   `len=912 = retail span, pad_ok, nd=0`. Relocation sequence differs from
   seed ONLY by uniform compiler-local `$T`-id renumbering (+12) — the
   standard landable shape of every wave2 landing. **Land via land.py**
   (merge into the TU's existing unit; stale-seed protocol; zero-loss gate).
2. **`LegoPathController::RemoveActor` 0x10046770 (.8534) — retail-exact
   donor EXISTS and REPRODUCES on today's shadow.**
   State: `fwdE k=94` (94 forward declarations appended at EOF). Re-derived:
   `len=328 (span 329, pad_ok), nd=0`, relocation sequence **identical to
   seed**. Land the same way (legopathcontroller already has a 4-row unit —
   land.py must MERGE; verify function count goes 4→5).

   Why the sweeps missed both: the queue7 runs for these states checked the
   *older/other* oracle stems; the all2-* oracles that cover these functions
   were built later. Nobody ever re-scored old objects against new oracles.

3. **The nd≤2 target list (current-shadow states unless marked stale):**

   | row | m | state | nd | note |
   |---|---|---|---|---|
   | 0x1002bff0 `_Tree<LegoPathActor*>::erase` | .709 | extern-0-9 (legoextraactor) | **1** | body 1096 = retail TRUE body (span 1104 ends `c2 08 00` + 8×CC pad) |
   | 0x1002b980 LegoExtraActor::CheckPresenterAndActorIntersections | .983 | shape-10-48 | **1** | the byte is a pure CMPDIR: ours `39 75 ac` vs retail `3b 75 ac` @ body+0x156 |
   | 0x1002e8d0 LegoPathActor::CheckPresenterAndActorIntersections | .984 | fwdL-6 | **1** | (base is len-exact at nd=2: offsets 47, 98) |
   | 0x10082ca0 `_Tree<..LegoCharacter*>::erase` | .685 | fwdL-69 (legocharactermanager) | **1** | |
   | 0x100ccd00 MXIOINFO::Advance | .992 | fwdE-1 | **1** | known 1-CMP-tie row |
   | 0x1009c070 EnumDirectDrawCallback | .978 | fwdE-2 (mxdirectxinfo) | **2** | "text-drift-dead" is OVERSTATED — it is 2 tie bytes away in a known state |
   | 0x10069b10 BuildROIMap | .884 | fwdL-95 | **2 (STALE)** | pre-landing shadow; on today's shadow fwdL-95 gives nd=109 — the TU re-dialed; queue a post-landing re-sweep |
   | 0x10083500 GetActorROI | .968 | fwdE-23 | 4 | donor-debt row — the state channel is closer than archaeology assumed |
   | 0x1002f770 UpdatePlane | .932 | — | 5 | plus AlphaMask ctor 5, StepState 6, AddRect 6, IsHit 6, HitActor 7, `_Erase`(lpb) 7 |

   Excluded as known relocation-target false positives: CreateActorROI
   (fwdL-82 nd=0) and LegoROI::Intersect (fwdL-62 nd=0) — `rederive.py`'s
   reloc-sequence check is exactly the missing oracle guard; wire it into
   sweep2/land as a standard gate.

4. **Doctrine change (one line of code, permanent):** sweeps must log
   best-nd per target, not just hits. Corollary triage: rows whose min-nd
   across the WHOLE corpus is large are text-channel, not state-channel —
   measured: FindPath 1741, ParseExtra 1229, FUN_10061010 546,
   ~MxStreamController 347, LegoOmni::Create 1386, Notify 78. Take them OUT
   of every carrier queue permanently; leave only the nd≤~10 tail in.

5. **Landings re-dial their TU (measured):** legopathboundary
   `RemoveActor` had an nd=0 state (pad-10-12) and BuildROIMap an nd=2 state
   (fwdL-95) on the PRE-landing shadow; both evaporate on today's shadow.
   ⇒ after every landing batch, re-sweep the landed TUs against the full
   oracle set — near-misses regenerate at different states.

**Execution recipe (main session):**
land FUN_10064b50 (extern-6-6) + RemoveActor (fwdE-94) via land.py with the
stale-seed protocol → expected 4826→4828 at zero loss; then run the nd≤2
product searches (C2 below) on the six one-byte rows; add best-nd logging +
reloc-sequence guard to sweep2.py.

---

## C2. The include-order axis — the first genuinely new state family since the carrier grammar (VALIDATED novel reach; no hit yet)

**Mechanism (new).** Every carrier to date (shapes, fwd runs, extern runs,
pads) APPENDS records around a fixed include stream. The decomp's
`#include` order is ALPHABETIZED BY MODERN CONVENTION — 1997's order is
unknown, i.e. free, source-authentic entropy. Permuting the quoted-include
block PERMUTES the composition of the whole record/id stream, a dimension no
flat carrier reaches.

**Measured (kill-tests RUN, `incperm.py` + `novelty.py`):**
- legopathactor.cpp (15 includes, 39 perms): every rotation/shuffle moves
  4–9 function bodies — including `CheckPresenterAndActorIntersections`
  (queue10-SEALED) and the `_Tree<LegoPathActor*>` erase/find/_Copy family.
  Adjacent swaps are mostly inert — the effect localizes to 2–3 impactful
  headers, so the effective search space is small.
- **Novelty proof vs the saturated corpus:** against 954 flat-carrier states,
  39 include-perms produced 2 NOVEL `CheckPresenter` bodies (one at retail's
  exact 561 length), 15 NOVEL `_Tree::erase` bodies (corpus had 254 distinct),
  6 NOVEL `find` bodies. The axis reaches states the whole carrier grammar
  cannot.
- legoextraactor.cpp (8 includes, 28 perms): same shape — `erase/find/
  _Copy/_Erase`, HitActor, CheckPresenter move; `swap03/swap04` localize the
  impactful headers.
- **Honest negative:** the 120-perm × shape(10,48) product (`product.py`) did
  NOT flip 0x1002b980's final CMPDIR byte (90× nd=1, 25× nd=5, 5× nd=3).
  One-byte ties stay hard; this axis multiplies the reachable set but is not
  a precision screwdriver.

**Landing channel:** either (a) an authentic source refactor (reorder the
includes in checked source — the alphabetical order is our invention, any
order is equally plausible 1997 style; check repo lint/format), or (b) a
typed manifest transform "include_order permutation of TU X" rendered into
the shadow like the existing carriers. Both respect the mandates.

**Execution recipe:** per near-miss TU: (1) n−1 adjacent swaps to find the
impactful headers (~10 compiles); (2) full perms of the impactful subset ×
the near-miss carrier and its grid neighbors (~100–300 compiles/TU on the
existing bench); (3) hits land through the composer as usual. First targets:
legoextraactor (2 rows at nd=1), legocharactermanager (fwdL-69 nd=1),
legoanimpresenter post-landing re-sweep with perms included.

---

## C3. Goal-2 is NOT waiting for goal-1 — start the layout program now (VALIDATED premise)

**Measured (`dispmap.py`, current report):** 459 KB of .text address space
is displaced (240 constant-delta runs). Attribution of run starts:
**only 134 KB begins at an open row; 325 KB (71%) begins at an m=1.0
boundary** (size/order defects on exact rows, missing COMDATs, CRT/library
regions — e.g. −48/58.8KB after a 1.0 vtordisp, −640/11.9KB after
`__fseek_lk`, +6672 in the library tail). Closing all 107 rows therefore
CANNOT collapse the goal-2 .text distance. The "closing rows collapses it"
law only covers the ~30% minority.

**Design consequence (this is the reframing):** the parked COMDAT
transposition pass was parked because units were defined against the CURRENT
layout (churns with every landing). Anchor them to RETAIL's per-object
contribution order instead — retail never changes, so units are
churn-immune, idempotent, and safe to land before 4933: raw row scoring is
displacement-independent (the span-shift landing 80760d7a already proved a
16-byte span change costs zero rows).

**Execution recipe:** compute once, from retail attribution + the rsp order,
each object's retail-order ledger; emit `swap_comdat_group_order` /
same-slot order units per object for the ~20 m=1.0 transpositions
(evidence.json list) ranked by downstream run length (biggest: the
−48/58.8KB, −48/37.7KB, −32/33KB runs); after each batch re-derive the
displacement map (2 s, no build). The −144/28.1KB run after
~MxStreamController is the missing `list<MxDSObject*>::erase` COMDAT — it is
goal-1-coupled (needs the dtor to reference erase out-of-line); leave it to
C4/C5.

---

## C4. The C2 pool-dump instrument — make inline/tie search DIRECTED (addresses byte-verified; spec, not yet built)

**Verified this session (`c2check.py` against
`MSVC420/bin/c2.exe`, md5-matched to tools/patch_c2.py's original):**
- `0x413f51: 0f bf 5a 68` = `movsx ebx, word [edx+0x68]` (callee cost) ✔
- `0x413f6e: 0f bf 6d 68 3b eb 7f 07` = `movsx ebp,[ebp+0x68]; cmp ebp,ebx;
  jg` — **the pool insertion is a STABLE ascending sort: equal-cost
  candidates keep statement-walk ENCOUNTER order.** The open
  candidate-ordering question (project-inline-budget-model) is thus half
  answered statically: order = (cost asc, then first-encounter order in the
  IL walk, re-entrant after each expansion). What remains unknown is the
  budget counters' semantics (`[esp+0x38] − [esp+0x40]`).
- `0x413ea1: 68 c6 02 00 00` C4710 push ✔ · `0x4124e7` cost read ✔ ·
  `0x4029b3` cost write (from C1XX varint) ✔.

**Instrument:** sandboxed C2 (precedent: `isle-tools/s40-c2color/sandbox.sh`,
length-matched path; the repo already ships C2-patch machinery in
`tools/patch_c2.py`) with a stub in the 234B .text slack that logs, per
caller: the pool (callee, cost) in final order, each accept/decline, and the
two budget counters at each decision. Fit against the two known-correct
tables (legoanim: which 4 of 6 expansions; OrientableROI 2/2/1/3). Output is
EVIDENCE ONLY — it selects which authentic record/text states to try, it
never lands bytes.

**Payoff if the fit lands:** the ~6 inline-class rows (~MxStreamController,
FUN_10061010, CalculateCameraTransform, the Vector3 trio) get a computed
state condition instead of blind search, and the erase-out-of-line condition
would simultaneously restore the 0x100c14d0 COMDAT (+28.1KB of goal-2 run).

---

## C5. Cheap closures + corrections (RUN)

- **/YX auto-PCH is INERT** (`incperm.py all2-legopathactor yx`): pch
  created (222KB `vc41.pch`) and present on the reuse compile; all 128
  bodies bit-identical both ways. The last untested flag axis closes. (A
  deep `/Yc`-boundary variant remains theoretically open; not promising.)
- **Winner census for the open `_Tree` rows (`winners_all.py`):** every
  swept family is being swept in its true link-winning TU — LegoPathActorSet
  trio → legoextraactor; LegoAnimSubst/AnimStruct/HideAnimStruct →
  legoanimpresenter; LegoCharacter trio → legocharactermanager; CoreSet
  erase → legoworld; CacheSound pair → legosoundmanager; LegoTextureInfo
  erase → **legomain** (not legocontainer), _Insert →
  legotexturepresenter; AnimPresenterSet `_Erase` → legopathboundary.
  Three winners live OUTSIDE lego1's objects1.rsp (library members):
  BEWithMidpoint::insert, MxAtom::erase, ViewLODList::erase — name them
  precisely (omni/viewmanager lib members) before ever sweeping those rows.
  No mis-targeted sweep found ⇒ the "emission-set/wrong-TU" hypothesis for
  the _Tree block is CLOSED; the block is body-state in the right TUs
  (include-perm axis + post-landing re-sweeps are the live levers).
- **ALPHA.DLL recon (`perecon.py`):** Oct-29-1996 build, /Od WinDebug, NB10
  `D:\Lego\LegoOmni\Src\Dll\WinDebug\Lego1d.pdb`, essentially unmined.
  Use as a BRACKET oracle on the BETA10-contradicts-retail rows (BuildROIMap
  loop spelling, TriggerHitSound one-step form, Notify key constant,
  CreateROIAndBuildMap key local, Act1State layout): where ALPHA agrees with
  retail's form, June was the outlier and the retail spelling is readable
  from ALPHA at /Od. Hand to the foundry lane; do not build a new lane.

---

## Ranked execution order for the main session

1. **Land the two C1 donors** (recipes above) → 4828, zero risk beyond the
   standard gates. Add best-nd logging + reloc-sequence guard to the bench.
2. **Queue post-landing re-sweeps** (legoanimpresenter, legopathboundary)
   with include-perms in the axis mix (C1.5 + C2), targeted at the nd≤2 list.
3. **Start the retail-anchored goal-2 order pass** (C3) — it no longer waits
   for rows; rank by displaced-run length.
4. **Build the C2 pool-dump stub** (C4) when a session can afford the RE
   hour; fit the budget counters; then reopen the inline class as a computed
   search.
5. Foundry lane: add the ALPHA bracket check to each contradiction row (C6).

Everything above respects the binding mandates: donors are generated states
over current rendered source; include order is authentic source entropy or a
typed transform; the C2 instrument is evidence-only; no vendor edits; no
recorded blobs as landing material.
