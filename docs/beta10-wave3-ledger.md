# BETA10/ALPHA transcription foundry — wave 3 ledger

Session date: 2026-08-15 evening (agent worktree `agent-a5aefcec25afa6ac1`,
branch reset to entropy-stabilization d97afb77 + checksum-rsync snapshot of the
main checkout's working tree taken 18:33; the main session was actively editing
— the manifest in this worktree is the 18:32 snapshot + my repin).
Baseline at session start: LEGO1 4829/4933 (isle-build-lean/LEGO1-report.json,
mtime 18:02). Session was cut short by coordinator directive; Lane B is
NOT-REACHED (baselines and BETA10 addresses are recorded below for wave 4).

Probe evidence lives in the session scratchpad
`/private/tmp/claude-501/-Users-foxtacles-Projects-isle/aa9d0cc1-fd32-4a6b-8d7e-b872f4bc8732/scratchpad/wave3/`
(harness `w3.py`, one-shot `one_probe.py`, verifiers `verify_hit1.py`,
`hit1_eh_check.py`, lane tests `name_test*.py`, kept objects under
`sweep-extra-ep/varab_pad-*`, `vh1-*`, `probe-exact-seed/`).

## METHOD CORRECTION 1 (major, measured): the source-path string is compile state

MSVC 4.2 /O2 codegen depends on the SOURCE FILE ARGUMENT string passed to cl.
Measured on legoextraactor.cpp (identical text, identical flags, only the
source-arg path varied; full 149-body map compared against an exact-replica
build compile):

| source arg | len | CPI body | erase body |
|---|---|---|---|
| build's abs shadow path | 94 | 1375/nd=8 | 1104/nd=960 |
| abs, other dir, same basename | 94 | FAITHFUL (all 149 bodies identical) | |
| abs, other dir, other basename | 94 | FAITHFUL | |
| abs mirror root(45)+true subpath | 94 | FAITHFUL | |
| abs, len 95 | 95 | FAITHFUL | |
| rel `s.cpp` | 5 | 1370/nd=1103 | 1097/nd=573 |
| rel `legoextraactor.cpp` | 18 | 1370 | |
| rel 44 chars | 44 | 1375 | |
| abs `.../probe-nt2-abs-scpp/s.cpp` | 133 | 1370 | |
| abs `.../probe-name-copy-scpp-abs/s.cpp` | 139 | 1375 | |

Not pure length; a coarser bucket (139 and 94 faithful, 133 not). Operational
rule adopted and verified: LENGTH-MATCHED absolute paths are faithful (3/3 at
94, 1/1 at 95); content of dir/basename is irrelevant. cwd, extra `/I`,
`/Fo`/`/Fd` redirection are all inert (measured). Sensitivity is TU/state
dependent (other TUs' probe->gate transfers succeeded historically).

## METHOD CORRECTION 2 (major): there are TWO lanes, and both are now exactly reproducible

Reading `tools/isle_build.py compose_translation_units`:
- **SEED lane** = the build's own compile: absolute shadow path (94 chars for
  this TU). Reproduce with an exact-replica command (only /Fo /Fd redirected)
  or a length-matched mirror tree (`/private/tmp/claude-501/w3-shadow-mirror-xyzq`,
  root length == len('/Users/foxtacles/Projects/isle-build-lean/src') = 45).
- **DONOR lane** = the composer's donor compile: `s.cpp` RELATIVE, cwd=probe
  dir, extra `/I{source.parent}`, `/FIrun.h`, `/Foo.obj`, `/Fdo.pdb`.
  This is EXACTLY the sweep-bench/rederive/one_probe construction — the whole
  historical carrier corpus is donor-lane-faithful (why donor landings always
  transferred). Only /FI header NAME differs historically (`shape.h` vs
  pipeline `run.h`) — re-verified HIT#1 with `run.h`: identical result.
- Consequence: carrier sweeps stay as they are; **text-edit VICTIM accounting
  must run in the seed lane** (wave-2's s.cpp-lane victim lists for this TU
  were measuring the wrong lane: today's true seed showed NONE of the
  erase/find/_Copy supplier regressions wave-2 recorded for the flip).
- Validation for this TU: exact-replica seed vs built object differs in
  EXACTLY the two spliced pins (find f084c2bb->8e107d4a, _Copy
  af6d89af->0d94b686), nothing else.

## ND0-FOUND + TEXT LANDED: 0x1002b980 LegoExtraActor::CheckPresenterAndActorIntersections (.9833)

**Recipe = text flip + new donor; every composer gate dry-run PASSES.**

1. TEXT (landed in this worktree, commit db6811a4, repinned via
   tools/repin_overlay.py; re-rendered effective = byte-equal to the verified
   probe text, sha 1cb7f952695d...):
```diff
-		if (plpas.find(*itpa) != plpas.end()) {
+		if (plpas.end() != plpas.find(*itpa)) {
```
   (legoextraactor.cpp:457; same BETA10 0x100b1010-backed spelling as wave 2's
   sibling landing. Line-neutral.)
   Seed-lane victims (exact-replica, edited text at length-matched mirror
   path): EXACTLY ONE body changes — the target itself,
   1375B 90b14bf503c65365... -> 539c857523069ddb...; erase/find/_Copy/
   StepState/HitActor and the other 148 bodies bit-identical. Seed row
   improves nd 8 -> 7 (fixes offset 342 = the CMPDIR `39 75 ac` -> retail
   `3b 75 ac` at the now out-of-line find call boundary — wave-2 method
   finding 4 confirmed again).
2. DONOR (pipeline-exact donor lane, s.cpp + /I + /FIrun.h):
   `declaration_shape(10,48)`, header sha
   91cb3e339eea53da78540d65b3fbae5a2dc9b773215896cf6b036a73e1a95b38
   (id d_91cb3e339eea). Target body retail masked-EXACT: 1375/0, sha
   `90f510f99952233ae82b36e8c0af354c5ccd5f9a0391e4365cf65e8eaab16341`.
3. SPLICE fields (verified by running byte_identity.compose_equal_body_comdat
   on the real seed/donor objects — dry-run OK, composed object validates):
   - splice_class: `equal_body_eh_structural_local` (closure (.debug$S,
     .xdata$x), xdata byte-identical, seats equal at section 421)
   - expected_body_length 1375; expected_changed_offsets
     [321, 324, 330, 332, 343, 356, 401] (none relocated)
   - expected_code_renames [[12,"L"],[710,"T"],[761,"T"],[773,"T"],[792,"T"],
     [815,"T"],[829,"T"],[852,"T"],[990,"T"],[1006,"T"],[1358,"T"]]
   - expected_xdata_rename_offsets [8, 36, 44, 52, 60]
   - verify_non_emitting_donor: OK (149 functions, 479 sections preserved)
4. EXISTING UNIT: shape(5,21) donor re-verified on the edited text in the
   pipeline-exact donor lane — find pin 8e107d4a... HIT, _Copy pin
   0d94b686... HIT. No re-derivation needed.
5. NOT done (directive cut): full isle_build gate run from this worktree.
   The main session lands via: text commit db6811a4 (or replay the one-line
   diff) + add the d_91cb3e339eea donor and the function entry above to the
   legoextraactor TU unit + accepted-row-set re-pin. Expected: +1 (4830).

## RECIPE (CONFLICTED, donor-lane objects kept): 0x1002bff0 _Tree<LegoPathActor*>::erase (.709)

- On CURRENT text (and on flip457 text) the extern axis maxes out at nd=1:
  EVERY extern-M-K state on the diagonal M+K=9 gives 1096/nd=1 (offsets vary:
  434 at extern-0-9, 145 at fwdL... see sweep). The residual byte at
  extern-0-9 is a REGISTER-ROLE tie, not a CMPDIR: ours `3b fa` (cmp edi,edx)
  vs retail `3b d7` (cmp edx,edi) at body+434. Full extern(161) + padgrid(144)
  on cur and flip457: no nd=0.
- On **varab** text (bisect-ledger hunks: StepState era form
  `m_scheduledTime = p_time + 2000.0f;` without the g_hitAnimationDelay
  static, + HitActor cast-revert `Vector3 positionRef(local[3])`):
  **erase nd=0** at `pad_shape(7,11)` and `pad_shape(10,7)` — body
  1096/16 relocs, sha `89ac1595e9a3ac4c0e1bbb9c9a076857a77f6bf1c090e63e2b9a1ae6c3363dfd`
  = the bisect ledger's recorded exact body, now reproduced on TODAY'S shadow
  on a NEW carrier axis (objects kept: sweep-extra-ep/varab_pad-7-11,
  varab_pad-10-7). Measured with /FIshape.h; /FIrun.h re-verification not run
  (directive cut).
- CONFLICT UNCHANGED: in those varab objects find = e01d887d... != pin
  8e107d4a... — the donor-debt law holds (find pin exists only with the cast
  present). varab also recolours HitActor massively in the donor lane
  (best nd 735 on varab/varb vs 7 on cur) — HitActor (.979) and StepState
  (.931) would need their own re-cover on varab, plus seed-lane victim
  accounting was NOT run for varab. Do not land without a find re-cover on
  varab text (extern/pad axes on varab for FIND was swept here: zero pin
  hits in 305 states) AND a HitActor/StepState story.
- Verdict: erase stays blocked behind the HitActor `(const float*)` cast,
  exactly as the bisect ledger said; the new pad states only re-confirm the
  1997 body is reachable the moment the true HitActor/StepState source form
  is found.

## Lane A neighborhood re-derivations (today's shadow, donor lane)

| row | recorded state | today |
|---|---|---|
| 0x1002b980 CPI (extraactor) | shape-10-48 nd=1 | HOLDS: nd=1 @342 -> closed by HIT#1 above |
| 0x1002bff0 erase (extraactor) | extern-0-9 nd=1 | HOLDS: nd=1 @434 (reg tie, whole M+K=9 diagonal) |
| 0x10082ca0 erase (charactermanager) | fwdL-69 nd=1 | HOLDS: nd=1 @145 (reloc sequence vs seed IDENTICAL, 16/16) — one reg/CMP byte from a landable donor; product search NOT run (directive cut) |
| 0x1002e8d0 CPI (pathactor) | fwdL-6 nd=1 | RE-DIALED: today nd=2 @[47,261] (fresh-eyes law "landings re-dial their TU" confirmed); base seed still nd=2 @[47,98] |

## Sweep record (extern 161 + padgrid 144 states x 4 texts, donor lane, 1220 compiles)

Texts: cur, flip457, varb (cast-revert), varab (cast-revert + StepState era).
Best nd per (text, target) — full per-state map in
`wave3/sweep-extra-ep/results.jsonl`:

| text | CPI | StepState | HitActor | erase |
|---|---|---|---|---|
| cur | 5 (pad-1-5) | 6 (extern-1-12) | 7 (extern-5-11) | 1 (extern-0-9 et al.) |
| flip457 | 4 (pad-1-5) | 6 (extern-1-12) | 7 (extern-5-11) | 1 (extern-0-9) |
| varb | 1 (extern-7-4) | 6 (extern-1-13) | 735 (text self-hit) | 2 |
| varab | 1 (pad-9-5) | 11 | 735 | **0 (pad-7-11, pad-10-7)** |

StepState/HitActor near-misses at extern states (nd=6/7 on cur) are candidate
one-byte rows for the next carrier product pass; note both rows' BETA10 forms
(0x10080b4c / 0x1008114a) were NOT read this session (directive cut) — the
varab hunks are era-repo forms, not BETA10-verified.

## Lane B: NOT-REACHED (queue for wave 4, with today's measured baselines)

Baselines measured from today's built TU objects (masked nd vs retail span;
script `wave3/baseline_nd.py`):

| row | addr | BETA10 | today len/nd |
|---|---|---|---|
| CarRace::HandlePathStruct | 0x100170e0 | 0x100c87ac | 1391/111 |
| JetskiRace::HandlePathStruct | 0x100166a0 | — | 645/22 |
| Act3Cop::FUN_10040360 | 0x10040360 | 0x10018c6a | 2496/68 |
| Act3Brickster::FUN_100417c0 | 0x100417c0 | 0x1001a407 | 2875/132 |
| Act3Shark?::Animate (act3actors) | 0x10041050 | — | 1628/1149 |
| CalculateSpline | 0x10080be0 | 0x100cdc54 | 779/646 (needs full transcription) |
| LegoCarRaceActor::CPI | 0x10081840 | 0x100cf680 | 1163/930 |
| ~LegoROI | 0x100a83c0 | 0x10189a42 | 206/118 |
| TowTrack::HandlePathStruct | 0x1004d330 | 0x100f74c0 | 856/11 |
| LegoOmni::Create | 0x10058e70 | 0x1008d6bf | 2616/1386 (text channel per C1.4) |
| Act3Ammo::Animate | 0x10054050 | 0x1001e362 | 2665/935 |
| PlaceActor(4-arg) | 0x10046050 | 0x100b6f35 | 693/589 |
| GetActorROI | 0x10083500 | — | 822/9 |
| StepState / HitActor (extraactor) | 0x1002a720/0x1002aba0 | 0x10080b4c/0x1008114a | 876/32, 1617/29 |

ALPHA.DLL bracket reads (TriggerHitSound, CreateROIAndBuildMap): NOT-REACHED.

## Caveats / handover notes

- The commit db6811a4's manifest file is the main checkout's 18:32 manifest
  snapshot + my repin (the main session was mid-edit; merge accordingly —
  the two flip-relevant facts are the legoextraactor output entry
  {clean 49e409f406a7..., effective 1cb7f952695d..., size 15647} and the TU
  source_sha256 update).
- Historical sweep-bench nd records are DONOR-lane-faithful by construction
  (Method Correction 2); no invalidation of the corpus — but any TEXT-edit
  victim list ever measured via s.cpp compiles should be re-checked in the
  seed lane before being believed (wave-2's flip victim analysis for
  legoextraactor was lane-wrong and is superseded by this ledger).
- Kept nd=0 objects: `wave3/vh1-donor-shape-10-48/o.obj` (CPI donor),
  `wave3/sweep-extra-ep/varab_pad-7-11/o.obj`, `.../varab_pad-10-7/o.obj`
  (erase, conflicted), plus `wave3/probe-exact-seed/o.obj` (true seed
  replica) and `wave3/vh1-seed/o.obj` (flip457 true seed).

## Session summary

- 1 ND0-FOUND fully verified through the real composer code path
  (CPI 0x1002b980: text landed + donor recipe with every splice field
  dry-run-proven; expected +1 once the main session adds the manifest unit).
- 1 CONFLICTED nd=0 recipe re-confirmed on new axes (erase 0x1002bff0,
  varab + pad states; blocked on find pin + HitActor/StepState as before).
- 2 method corrections that affect every future probe (path-string compile
  state; seed-vs-donor lane split), both measured.
- 1 one-byte state confirmed live for wave 4 (charmgr erase fwdL-69 nd=1)
  and 1 stale record corrected (pathactor fwdL-6 is nd=2 today).
- Lane B untouched (directive cut). 0 unverified claims; every number above
  is a fresh measurement from this session.
