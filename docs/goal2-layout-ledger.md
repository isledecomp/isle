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
