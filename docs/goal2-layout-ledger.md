# Goal-2 layout ledger (first pass, 2026-08-15)

Scope: LEGO1 terminal byte distance, retail-anchored order transforms only.
Bench: worktree `agent-a9a0361619a7aa873` at `084ff6bd` + this branch's
manifest edits; own build dir `/Users/foxtacles/Projects/isle-build-layt`
(see "harness trap" below for why that exact name length). Every number in
this document is measured (real builds through `tools/isle_build.py
--md5-distance`, pinned reccmp, iteration gate = exact accepted-set pin, so
any row gain OR loss fails the build).

## Verified state landed on this branch

| state | LEGO1 rows | LEGO1 terminal distance | ISLE | CONFIG |
|---|---|---|---|---|
| baseline (084ff6bd manifest) | 4829/4933 exact set | 637,971 | MD5 identical | MD5 identical |
| + legoentity swap unit | 4829/4933 exact set | 637,873 | identical | identical |
| + mxsmkpresenter, mxvideomanager, mxdsstreamingaction units | 4829/4933 exact set | **637,871** | identical | identical |

Four new `swap_comdat_group_order` units are in this worktree's
`tools/byte_identity_manifest.json`, all validated by full runs (rows exact,
composer fail-closed checks green, ISLE/CONFIG MD5 unchanged):

1. `lego1:LEGO1/lego/legoomni/src/entity/legoentity.cpp`
   first `??4Vector3@@QAEAAV0@ABV0@@Z`,
   second `??4Mx3DPointFloat@@QAEAAV0@ABV0@@Z`.
   Collapsed the +48/−32 displacement pair at 0x10010be0; −98 bytes distance.
2. `omni:LEGO1/omni/src/video/mxsmkpresenter.cpp`
   first `?Compare@?$MxCollection@PAVMxRect32@@@@UAECPAVMxRect32@@0@Z`,
   second `??0?$MxCollection@PAVMxRect32@@@@QAE@XZ`.
3. `omni:LEGO1/omni/src/video/mxvideomanager.cpp`
   first `?UpdateView@MxVideoManager@@UAEXIIII@Z`,
   second `??_GMxVideoManager@@UAEPAXI@Z`.
4. `omni:LEGO1/omni/src/action/mxdsstreamingaction.cpp`
   first `?HasId@MxDSStreamingAction@@UAEEI@Z`,
   second `??_GMxDSStreamingAction@@UAEPAXI@Z`.

Units 2–4 together were −2 bytes (their windows are small); their real value
is run-count collapse (.text constant-delta runs 252 → 240 across the three
landings) and proving the batch mechanics. Distance yield of intra-object
pair swaps is proportional to the displaced window size, and most pair
windows are tiny; the big distance lives elsewhere (below).

## The displacement ledger (measured attribution)

Input: `/Users/foxtacles/Projects/isle-build-layt/LEGO1-report.json`
(byte-identical row set to `isle-build-lean`'s) joined with a `/MAP` relink
(`link ... /MAP`, zero compiles; script
`scratchpad/layout/mkmap.sh`). 4487 .text function rows, all matched to map
publics; 252 constant-delta runs at baseline, 459.4 KB displaced span.

Run-boundary attribution (boundary = the row/gap immediately before each
nonzero-delta run):

| class | displaced span | runs | fix channel |
|---|---|---|---|
| (b) cross-object / link-input order | 212.3 KB | 67 | rsp/member order (not touched this pass) |
| (d) open row with size delta | 128.5 KB | 18 | goal-1 rows |
| (a) intra-object COMDAT transposition | 97.0 KB | 142 | `swap_comdat_group_order` + extension |
| (c) missing/extra contribution at exact rows (gaps at object boundaries) | 21.7 KB | 13 | per-case (e.g. the 0x100c14d0 missing `list<MxDSObject*>::erase` is goal-1-coupled; skip) |

The biggest single runs (baseline report, retail-order spans): −48 over
58.8 KB after an m=1.0 vtordisp row, −48/37.7 KB, −32/33 KB, +16/21.1 KB
after `_Tree<LegoCacheSoundEntry>...`, −640/11.9 KB after `__fseek_lk`
(CRT), +6672/11.7 KB library tail after
`MxDSStreamingAction::FUN_100cd2d0`. One 48-byte slot defect displaces
59 KB of address space; collapsing the handful of large-boundary defects is
worth more distance than every pair swap combined. These boundaries are
class (c)/(d)/(b), not transpositions.

## Class (a) worklist (from `scratchpad/layout/pairs.py`, measured)

Expressible with TODAY'S composer (strict two-position exchange, no
existing unit on the TU): the four landed above. Everything else needs one
of the two extensions below.

Blocked on the **duplicate-owner rule** (TU already carries a
`compose_equal_body_comdat` unit; one unit per (target, source)):
act3actors (41 rows moved, one window), tglrl40 (47 moved, 3 windows),
legoroi (30), legomain (43, 2 windows), legoracespecial (24),
legopathcontroller (6), mxdsselectaction (16), viewmanager (20),
viewlodlist (18), legocachesoundmanager (3), legopathactor (4),
legoworld (adjacent pair `_Construct`/`InsertEntry`).

Blocked on **pair-only semantics** (permutation is not a two-position
exchange): legoanim (39 moved), legolod (19), mxmain (37, 3 windows),
legopartpresenter (21), orientableroi (20), legoinputmanager (26),
mxdsaction (8), mxramstreamprovider (11), mxutilities (19), legotree (9),
legostorage (13), mxstreamer (3), mxdsserialaction (4),
mxdsparallelaction (3), legosoundmanager (3), mxthread (8), helicopter (6),
mxdsstreamingaction-class small TUs. Recorded negative: submitting the
3-element front-rotations as pair units fails the composer's final check
("more than the target contribution pair moved") — measured on mxstreamer,
mxdsserialaction, mxdsparallelaction, legosoundmanager,
legoanimpresentercontainer.

## Composer extension spec (prototyped, NOT yet build-validated)

`scratchpad/layout/listcompose.py` implements
`compose_restore_comdat_group_order(seed_bytes, order_list)`:

- `group_order` becomes a LIST of mangled names in the desired (retail)
  first-to-last order; each name owns its compiler-produced group
  (primary + selection-5 children).
- Window = contiguous section-number range [min..max] over all listed
  groups; every section inside the window must belong to a listed group
  (fail-closed), so the transform is a pure whole-group permutation.
- Renumbering, association rewrite and the full invariant suite are copied
  from the pair composer; final check = primaries appear in exactly the
  listed order.
- Runner change needed: either allow `group_order` as an optional post-step
  on `compose_equal_body_comdat` units (applied after body composition) or
  drop the one-unit-per-owner restriction across modes — 12 of the class-(a)
  TUs already carry compose units.
- A data-COMDAT variant is also needed for .rdata vftables:
  `function_section` currently requires `.text` + type 0x20.

Status: the byte surgery was NOT validated by a relink before the session
was closed out — the act3actors proof run (14.25 KB window, 41 groups) is
specced but unexecuted. Treat the extension as designed, not proven.

## Class (b) cross-object order — NOT executed

212.3 KB of displaced span starts at object boundaries. No rsp-permutation
relink was run this session; no findings to report. The link map +
`ledger2.json` (scratchpad) carry the per-object `d_in`/spans needed to plan
the first permutation experiments. Historical context (s22–s26 memory):
library decomposition and link-line order are already retail's; the residue
is member pull order (reference graph) plus lego1's explicit rsp order.

## .rdata vtable ledger — partial

Measured from the type-5 rows: 446 vtable rows (all m=1.0), 141
constant-delta runs, 22.2 KB displaced span, with both intra-object
inversions (e.g. legoworld's `LegoWorld::vftable` vs the two PtrList
vftables) and large cross-object deltas (±1–3 KB). Object attribution via
the map's 0002-section publics works (`scratchpad/layout/objdump.py` prints
both orders per object). No vtable fix was attempted: the current composer
cannot move .rdata COMDATs (see extension spec). Quantified classification
not completed.

## Harness traps (measured this session, will bite the next agent)

1. **Build-dir path length is load-bearing.** A build dir 2 chars longer
   than `isle-build-lean` (i.e. `isle-build-layout`) flipped the fragile
   `_Tree`/legoracespecial donor bodies — 10 compose units failed their
   body pins ("seed/donor body delta changed"). With a same-length dir
   (`isle-build-layt`) everything reproduces bit-exactly (4829, distance
   637,971, zero row deltas vs the lean report). This is the known C1XX
   arena path-length sensitivity reaching the compose pins.
2. **Derive swap specs from FRESH seeds or the link map, never from
   on-disk objects** — after a partially-failed compose batch the objects
   on disk are a mix of composed and fresh states (one wrong "linker
   exchanges pairs" hypothesis this session came from reading a composed
   object; the map disproved it: image order follows object section order).
3. **Use the OBJECT's symbol name in units.** The map/report may show the
   `??_E` alias where the object defines `??_G` (measured on
   MxDSStreamingAction: `??_E...` has 0 definitions in the object).
4. The compose pool aborts on first failure and cancels siblings silently;
   `scratchpad/layout/swapreplay.py` replays all swap units offline to
   find the failing one.
5. The manifest JSON round-trips byte-identically through
   `json.dump(..., indent=1)` — safe to edit programmatically
   (`scratchpad/layout/addunit.py`).

## Honest unknowns

- Whether the list extension's byte surgery survives a real relink with
  rows intact (act3actors is the designated proof; unexecuted).
- Which class-(b) rsp permutations collapse which of the 67 cross-object
  runs, and whether any permutation moves rows (unexecuted).
- The per-boundary diagnosis of the six largest runs (the −48/58.8 KB one
  above all) — each needs the s39-style slot arithmetic against the map;
  not done at session close.
- Total distance recoverable by class (a) alone: the four landed units
  collapsed 12 runs for −100 bytes; the remaining class-(a) yield is
  bounded by its 97 KB span but the realized byte distance depends on how
  much of each window actually differs — unmeasured.

## Tooling left in the session scratchpad
(`/private/tmp/claude-501/-Users-foxtacles-Projects-isle/aa9d0cc1-fd32-4a6b-8d7e-b872f4bc8732/scratchpad/layout/`)

`env.sh` + `run_build.sh` (bench invocation), `mkmap.sh` (map relink),
`ledger1.py` (runs), `ledger2.py` (attribution, writes `ledger2.json`),
`pairs.py`/`rotcheck.py` (class-a worklist), `objdump.py`/`symdump.py`
(order dumps), `addunit.py`/`batch1.py` (manifest editing),
`swapreplay.py` (offline unit replay), `listcompose.py` (extension
prototype), `whichfail.py` (compose-failure isolation).

---

# Second pass (Lane FIN, 2026-08-16) — re-derived at 4853, and class (b) measured

Bench: worktree `agent-af3e1ee806b530baf` at `d00493ae`, build dir
`/Users/foxtacles/Projects/isle-build-fin1` (15 chars — harness trap 1).
Every number below is from a real `tools/isle_build.py --md5-distance` run or a
`/MAP` relink of that build's objects.

## Baseline on today's tree

| | first pass (4829) | today (4853) |
|---|---|---|
| terminal LEGO1 byte distance | 637,971 | **661,705** |
| `.text` rows / constant-delta runs | 4487 / 252 | 4488 / **234** |
| displaced span | 459.4 KB | **506.9 KB** |
| (b) cross-object / link order | 212.3 KB (67) | **272.5 KB (69)** |
| (d) open row with size delta | 128.5 KB (18) | 110.2 KB (8) |
| (a) intra-object transposition | 97.0 KB (142) | 82.0 KB (131) |
| (c) gap at object boundary | 21.7 KB (13) | 42.3 KB (14) |

ISLE and CONFIG remain **IDENTICAL**.

## 1. Goal 1 is currently making goal 2 worse, and it is quantified

Twenty-four rows closed between the two passes. Over the same interval the
**displaced span grew by 47.5 KB** and class (b) grew by **60.2 KB**. Closing a
row that changes a function's size shifts every function after it, and the
run-boundary attribution charges that shift to the next object boundary.

This is the whole-image version of the local effect already on record (removing
48 bytes of `.text` cost 15 address-aligned rows because those rows had been
propped up by 48 bytes retail does not have). The two goals are **not
independent**, and goal-2 work done before the size-delta rows close will be
partly undone by closing them.

## 2. The headline number is a positional Hamming distance — do not optimise against it

`tools/isle_build.py:368`:

```python
distance = sum(1 for a, b in zip(stamped, original) if a != b)
```

Every byte after a single inserted or removed byte counts as different. So the
metric saturates on displacement and is **not comparable across tree states or
lanes**. The three numbers in circulation — 545,273, 637,971 and 661,705 — were
measured on different trees and none of them measures "how much of the image is
right".

Use the displacement ledger (`ledger1.py`/`ledger2.py`: runs, displaced span,
class attribution) as the objective. It is already built, it is monotone in the
thing we actually want, and it is what the table above reports.

## 3. Class (b) is mostly shadow, not ordering — the measurement that was missing

The first pass attributed 212.3 KB (now 272.5 KB) to "cross-object / link-input
order" and never tested it. Tested now (`objorder.py`, no compiles: join the
`/MAP` publics with the reccmp report, order objects by minimum **our** VA and
by median **retail** VA, then take the longest common subsequence):

```
4488 .text rows, 0 without a map public, 338 objects
longest already-ordered run: 308 of 338  ->  30 objects would have to move
total span carried by out-of-order objects: 37.9 KB
by input: libcmt 21, lego1-own 4, roi 1, omni 1, misc 1, viewmanager 1, smackw32 1
```

**Only 37.9 KB of the 272.5 KB is carried by objects that are actually in the
wrong order.** The rest is inherited displacement — a size defect upstream
shifts everything downstream, and the attribution charges it to the next object
boundary. Class (b) is therefore **not** the largest actionable bucket; it is
the largest *shadow*.

And 21 of the 30 misordered objects are `libcmt` CRT members, pulled by the
linker's reference graph and not ours to order; together they carry ~1 KB.

## 4. Only four of lego1's 114 own objects are misordered

`ownorder.py` restricts to the objects lego1 links explicitly:

| object | our # | retail # | span |
|---|---|---|---|
| `legopathcontroller.cpp` (real source) | 66 | 59 | **18.5 KB** |
| `legocachesoundlist.cpp` (generated) | 44 | 45 | 1.5 KB |
| `legoanimpresenterset.cpp` (generated) | 53 | 58 | 0.0 KB |
| `legoanimpresentercontainer.cpp` (generated) | 79 | 80 | 0.1 KB |

Everything else in lego1's own order is already retail's.

## 5. The control surface, corrected

`source_overlay.graph.generated_tus[]` carries `ordinal`, `after`, `before`.
Reading `cmake/byte_identity.cmake`:

* **`ordinal` is the control** — `list(INSERT _sources ${ordinal-1} …)`;
* **`after`/`before` are assertions** verified against the resulting
  neighbours.

Editing only the anchors fails configure with *"Source overlay TU graph seat
differs"*. Both must move together. (Recorded because the ledger's first pass
described these as neighbour anchors without saying which one moves the TU.)

## 6. Experiment 1 — NEGATIVE, fail-closed, and it found the real constraint

Moved the two generated supplier TUs whose defect looked like a simple pair
inversion: `legocachesoundlist` after `legocachesoundmanager` (ordinal 46→47)
and `legoanimpresentercontainer` after `legopathboundary` (81→82).

```
isle_build: refusing: LEGO1: iteration reccmp accepted raw-1.0 row set differs from its exact pin
[isle_build] terminal LEGO1: distance 662860        (baseline 661,705  -> +1,155 WORSE)
[isle_build] LEGO1 rows 4850/4934 at 1.0            (pin 4853          -> -3 rows)
[isle_build] terminal ISLE: IDENTICAL   terminal CONFIG: IDENTICAL
```

Reverted; nothing landed. The gate did its job.

**The three lost rows name the mechanism:**

```
LOST 0x1003d450 _Tree<LegoCacheSoundEntry,…>::insert
LOST 0x100583a0 _Tree<LegoAnimPresenter*,…>::_Insert
LOST 0x100588e0 _Tree<LegoAnimPresenter*,…>::equal_range
```

Those are exactly the template instantiations the two moved supplier TUs exist
to provide. **Moving a supplier TU does not just move addresses — it changes
which object wins COMDAT selection for the templates it supplies, and therefore
changes those bodies.** A supplier TU's position is a *codegen* input, not a
layout input.

That constrains all future class-(b) work on generated TUs: their ordinals
cannot be tuned for layout independently of the rows they supply. The four
misordered lego1-own objects split accordingly — three are supplier TUs and are
coupled to rows; the fourth, `legopathcontroller.cpp`, is a **real source** and
is the only one whose position is a pure link-order change. It also carries by
far the most span (18.5 KB), and it is the one experiment worth running next.

## 7. What the next pass should do first

1. **`legopathcontroller.cpp` alone** — move it in `CMakeLists.txt` from after
   `legobewithmidpointcomparator` to before `legoboundaryedge` (retail #59).
   It is a real source, so no COMDAT-selection coupling; 18.5 KB of span.
   Note the generated chain 56–67 anchors around it, so their `after`/`before`
   assertions must be updated in the same edit.
2. **Stop quoting the Hamming distance** and re-baseline the objective on
   displaced span (§2).
3. **Do not spend the class-(b) budget on the 272.5 KB figure** — 37.9 KB of it
   is real ordering and 21 of the 30 misordered objects are CRT (§3).

## 8. Experiment 2 — the window in RETAIL's order: **−28 KB distance, +158 aligned rows, −6 rows**

Experiment 1 moved two supplier TUs to positions inferred from very few rows and
made everything worse. Experiment 2 corrects the **whole** `paths/` window to
retail's order instead of guessing at individual TUs.

Method (`ordinals.py`, `solve.py`), and the model is validated before it is
used:

1. Model the lego1 source list exactly as `cmake/byte_identity.cmake` builds it
   — real sources from `add_library(${NAME} SHARED …)`, then each generated TU
   inserted at `list(INSERT _sources ordinal-1 …)` in ascending ordinal.
2. **Verify the model reproduces the linked image's object order.** It does,
   exactly (`model reproduces the image object order: True`). Nothing below
   rests on a guess about the build system.
3. Rewrite `final[54:68]` into retail's measured order, solve for the ordinals
   that realise it (the index at insertion time *is* the desired final index),
   and **round-trip the solution back through the model** before writing.

The window, ours → retail:

```
ours    aps  pce pces pas pasc pasi  be pcei pcec pcl pec bwm bwmc  PATHCTRL
retail  pce pces pas pasc pasi  aps  PATHCTRL  be pcei pcec pcl pec bwm bwmc
```

— 12 inversions, all fixed by the rewrite. 13 ordinals changed; the CMakeLists
edit turned out to be a no-op because `legopathcontroller.cpp`'s position
*among the real sources* is unchanged.

### Result

```
[isle_build] terminal LEGO1: distance 633559     (baseline 661,705 -> -28,146)
[isle_build] LEGO1 rows 4847/4934, 1674 address-aligned
                                                (baseline 4853 / 1516 -> -6 rows, +158 aligned)
[isle_build] terminal ISLE: IDENTICAL   terminal CONFIG: IDENTICAL
isle_build: refusing: ... accepted raw-1.0 row set differs from its exact pin
```

Fail-closed; reverted. **This is the first measured proof that the class-(b)
channel is real and large**: one window of fourteen objects is worth **28 KB of
byte distance and 158 address-aligned rows**.

### The six lost rows are the finding

```
0x10048f10 list<LegoBoundaryEdge>::insert
0x10049290 _Tree<LegoPathCtrlEdge*>::…            (3 rows)
0x10049890 _Tree<LegoBEWithMidpoint*>::…          (2 rows)
```

Every one is a template instantiation living **inside `legopathcontroller`'s own
retail address range** (`0x10048f10`–`0x10049d10`). COMDAT selection takes the
first definition in link order. Before the move, `legopathcontroller.cpp` came
*after* the supplier TUs, so the **suppliers'** copies won. After the move it
comes before them — as it does in retail — so **its own** copies win, and they
do not match retail.

So those six rows were at 1.0 only because the wrong object was supplying them.
This is the "propped-up" phenomenon one level deeper than the 48-byte case: not
alignment propped up by extra bytes, but **row scores propped up by the wrong
link order**. Correcting the layout does not break them; it *exposes* six
codegen defects in `legopathcontroller.cpp`'s own template instantiations that
the supplier TUs were masking.

### What this means for sequencing the two goals

Goal 2 and goal 1 are coupled through **COMDAT selection**, not just through
addresses:

* a layout fix can change which object supplies a template, and therefore
  change row bodies;
* conversely, some current rows are only at 1.0 because the layout is wrong.

The honest consequence is that **class (b) cannot be landed incrementally under
a zero-row-loss gate wherever a supplier TU is involved** — the correct link
order and the current row set are inconsistent. Either the six
`legopathcontroller.cpp` instantiations are fixed first (goal-1 work, now with a
precise target list), or the gate needs a mode that accepts a net-negative row
step in exchange for a measured layout gain, which is a policy question for the
coordinator and not something a lane should decide.

**Recommended next step**: treat those six rows as a goal-1 work item. They are
fully specified — the required bodies are exactly retail's at
`0x10048f10`/`0x10049290`/`0x100492f0`/`0x10049370`/`0x10049890`/`0x10049d10`,
and the compile that must produce them is `legopathcontroller.cpp`'s own. When
they close, experiment 2 becomes a clean +28 KB with zero row loss.

---

# Wave 8 — closing the six borrowed rows

Base `e1288e1a`. The coordinator's decision was: the gate stays, the six close
first. The mechanical point that makes it ordinary work: **the COMDATs already
exist in `legopathcontroller.cpp.obj`; the linker just discards them in favour
of the suppliers' copies.** So they can be scored and fixed without touching
the link order, and the gate will neither reward nor punish it.

## 9. The real accounting was −6, not smaller

`layout/six.py` scores the object's own copies against retail's bodies at the
six addresses. None was exact:

| address | function | ours/retail | residue |
|---|---|---|---|
| `0x10048f10` | `list<LegoBoundaryEdge>::insert` | 84/84 | nd=6 |
| `0x10049290` | `_Tree<LegoPathCtrlEdge*>::find` | 92/92 | nd=23 |
| `0x100492f0` | `_Tree<LegoPathCtrlEdge*>::_Copy` | 126/126 | nd=29 |
| `0x10049370` | `_Tree<LegoPathCtrlEdge*>::_Ubound` | 45/45 | nd=2 |
| `0x10049890` | `_Tree<LegoBEWithMidpoint*>::erase` | 1102/**1110** | length −8 |
| `0x10049d10` | `_Tree<LegoBEWithMidpoint*>::_Erase` | 57/57 | nd=16 |

So the score of 4853 is inflated by exactly six, as the coordinator recorded.

## 10. Five closed. The accounting is now **−1**

`layout/mkoracle6.py` adds a `fin-lpc6` stem to this lane's `oracles-v2.json`
(the shared bench corpus is never mutated; `sw.py` was repointed at the lane's
own copy), which lets the ordinary carrier sweep and the ordinary lander work
on these COMDATs like any other row.

A `m,k = 0..40` extern sweep of `legopathcontroller.cpp` produced exact donors
for five of the six, and `layout/cover6.py` reduces them to **two** states:

| donor state | functions it makes exact |
|---|---|
| `extern-18-34` | `find`, `_Copy`, `_Erase` |
| `extern-15-20` | `insert`, `erase` (1110 B, `same_slot_resize`) |

Landed onto the TU's existing unit (7 functions → **12**, 5 donors → 7).

```
[isle_build] composed 12 function(s) into lego1:…/legopathcontroller.cpp
[isle_build] ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE:
             LEGO1 4853/4934, ISLE 172/172, CONFIG 111/111
```

**Zero row change, exactly as predicted** — the composed COMDATs are discarded
in the current link order, so the image is unchanged. The proof is out-of-band:

```
layout/six.py  ->  5 of 6 EXACT  ->  the real accounting is -1
```

This is a landing whose value the row score cannot see, and it is the whole
point of the wave: it converts experiment 2 from **−28 KB / −6 rows** into
**−28 KB / −1 row**.

## 11. The one that is left is a `cmpdir`, and it is the session's most familiar shape

`0x10049370 _Tree<LegoPathCtrlEdge*>::_Ubound`, 45 bytes, nd=2 at offsets
[6, 34] across **1,167 extern states**:

```
ours    +6/+34   39 15 …   cmp dword ptr [_Nil], edx
retail  +6/+34   3b 15 …   cmp edx, dword ptr [_Nil]
```

Two sites, both the `cmp reg,[_Nil]` ⟷ `cmp [_Nil],reg` inversion in the
inlined `_Tree` walk — the same defect as `LegoPartPresenter::Read` (§28 of the
finish-line ledger), `_Tree<LegoAnimPresenter*>::_Erase`, and the other five
`cmpdir` rows in the census. Not source-addressable (canonicalisation law; five
negative text cells on `Read`).

Worth noting the direction: here **retail** emits `3b` and we emit `39`; on
`Read`'s `_Nil` sites it was the other way round. The same template's compare
direction differs on both sides between two TUs, which is what an allocator tie
looks like rather than a property of the template.

The `declaration_shape` and `pad_shape` grids on this TU are queued and
unfinished (`layout/queue9.sh`, idempotent, resumable). §20/§21 of the
finish-line ledger established that a second generator sometimes reaches where
the first cannot — that is the remaining shot for this row, and it is the last
byte-pair between experiment 2 and a clean layout landing.

## 12. Closed by the second generator. The accounting is **−0**

The `cmpdir` reading in §11 was correct about the shape and wrong about the
consequence. `cmpdir` is not source-addressable, but it *is* carrier-reachable:
the `declaration_shape` grid reaches `_Ubound` at **`shape-2-4`, nd=0**, where
all 1,681 states of the extern rectangle sat at nd=2 with the residue frozen at
offsets [6, 34] and the length frozen at 45.

That is §20/§21 of the finish-line ledger paying out for the sixth time, and it
is now the strongest instance of it in the session: an entire generator family,
swept exhaustively, showed a completely invariant residue — the exact signature
this lane has repeatedly (and correctly) read as "the channel is closed" — and a
different generator closed it on the 124th state.

The refinement to carry forward: **residue invariance across an exhausted family
is evidence about that family, not about the row.** The extern rectangle never
perturbed the allocator tie that picks the compare direction; the shape family
does. `cmpdir` sites should be re-read as *allocator-tie* residue rather than
*canonicalisation* residue whenever a second generator is still unswept.

Landed state (13 fns / 8 donors on `paths/legopathcontroller.cpp`):

| donor | functions |
|---|---|
| `extern-18-34` | `_Tree<LegoPathCtrlEdge*>::find`, `::_Copy`, `_Tree<LegoBEWithMidpoint*>::_Erase` |
| `extern-15-20` | `list<LegoBoundaryEdge>::insert`, `_Tree<LegoBEWithMidpoint*>::erase` |
| `shape-2-4` | `_Tree<LegoPathCtrlEdge*>::_Ubound` |

Gate: `LEGO1 4853/4934, ISLE 172/172, CONFIG 111/111`, zero row change — as
predicted, since these COMDATs are still discarded in the current link order.
`layout/six.py`, which scores the object's own copies against retail directly,
reads **6 of 6 EXACT**.

**Experiment 2 is therefore unblocked at zero row cost**: −28,146 distance and
+158 address-aligned rows, with the gate left exactly as it is.

## 13. Experiment 2 re-measured after the six closed — and it does **not** pay

Landed the window and measured it properly against today's tree. The row cost is
exactly what §12 predicted, and the benefit is not:

| | rows | aligned | distance |
|---|---|---|---|
| baseline | 4853 | 1516 | 661,705 |
| exp2 **today** | 4853 | **1516** | 660,971 |
| exp2 as recorded in §8 (pre-landing) | 4847 | 1674 | 633,559 |

**The +158 aligned rows and −28 KB in §8 do not reproduce.** Today the reorder
changes 92 rows' displacement, and **not one of them lands on zero** — no row is
newly aligned and none is de-aligned. The images genuinely differ (21,979 bytes),
the link order genuinely changed (`ordinals.py`: model reproduces image = True),
and out-of-order lego1-own objects drop 4 → 2, carried span 37.9 KB → 19.5 KB.
So the reorder does what it was supposed to do structurally; it just does not
buy alignment.

The §8 number was measured with the six rows **broken**, and its gain was a
property of that state, not of the ordering. Recording it as "+158 aligned rows"
was wrong: it was +158 aligned rows *and* six wrong-sized bodies, and the two
were not separable. This is the layout analogue of the nd trap, and it caught
this lane.

Landed regardless: retail's order is the correct order, it costs zero rows, and
it is a precondition for alignment rather than a payer of it.

### The right ruler for goal 2 is the plateau histogram, not the distance

`layout/delta.py` groups every matched row by displacement (our VA − retail VA).
Alignment is cumulative, so the question is never "how many rows are aligned"
but "how many plateaus are there, and what single upstream size correction
collapses each":

| delta | rows | dominant owners |
|---|---|---|
| **0** | 1516 | (aligned) |
| **−16** | 617 | legoanimpresenter, legoanimationmanager, legocharactermanager, act3 |
| **+16** | 452 | legoutils, legoanimmmpresenter, legoact2, act3actors |
| −192 | 319 | `omni:` mxsmkpresenter, mxnotificationmanager, mxwavepresenter |
| −144 | 241 | `omni:` mxregion, mxstreamcontroller, mxdiskstreamcontroller |
| −176 | 153 | `omni:` mxdsmultiaction, mxdsmediaaction, mxdssound, mxio |

**1,069 rows — 22% of the image — sit at ±16 bytes.** That is one 16-byte size
defect on each side, not a thousand problems, and it dwarfs anything the paths
window could ever have returned. The −192/−144/−176 plateaus are all inside
`omni:`, i.e. one library's internal accumulation, and they are adjacent
(−144/−176/−192 differ by 32 and 16), which reads as the same few defects seen
from different points in the accumulation.

Next pass should bisect the ±16 plateaus by address: find the last aligned row
before each plateau starts and read the size difference of the slot between it
and the first displaced row. That is a bounded, purely measured search, and it
is where goal 2 actually lives.
