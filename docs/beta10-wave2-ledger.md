# BETA10 transcription foundry — wave 2 ledger

Session date: 2026-08-15 (wave-2 agent worktree `worktree-agent-ac4103b0b38d05ae1`,
reset to `entropy-stabilization` 9dcb9513 at session start).

Method: identical to wave 1 (docs/beta10-foundry-ledger.md), with one measurement
upgrade — every probe compiles the **effective (overlay-rendered) source**, not the
clean tree. The manifest's `source_overlay` ops are carrier state: compiling clean
text reproduces neither the lean baselines nor the gate. Probe harness:
scratchpad `wave2/probe.py` (rendered shadow tree via `isle_build.render_overlay`
+ `sync_shadow`; per-TU compile from isle-build-perf's compile_commands with
include paths re-seated onto the shadow; masked body diff via
`tools/byte_identity.py` CoffObject/detailed_relocations). Every landed edit was
followed by `tools/repin_overlay.py <path>` so the in-tree manifest pins stay
green, and re-verified through a fresh overlay render.

A hit = masked diffs 0 at retail length AND no other .text COMDAT in the TU
changes body bytes (recolour check over every COMDAT, pre/post).

## HITS (landed in this worktree, commits listed)

### 0x100ccd00 MXIOINFO::Advance — HIT, landed 3e3511c8 (.9925 -> exact body)

BETA10 0x1015eb8f /Od frame: `bytesCounter` at -0xc ABOVE `cch` at -0x10 (and
`rwmode` -4 above `result` -8). Our /Od probe of current text put `result` at -4 —
proving the June declaration set differs from ours in a slot-visible way; the /O2
probe matrix found the payload cell:

```diff
 	if (pchBuffer) {
-		MxLong cch = cchBuffer;
 		MxLong bytesCounter;
+		MxLong cch = cchBuffer;
```
(landed with a 2-line DECOMP comment; comment verified byte-neutral in this TU).

Measured: 343-byte body, 1 masked diff (offset 121, retail `3b d8` cmp ebx,eax)
-> 343/0. Pre/post body sha256 (16 hex): bd9304f3e16f4338 -> 534157794af4499f.
Recolour victims: NONE (all other COMDATs bit-identical, verified against the
effective render pre/post). Inert cells recorded: rwmode decl split (before and
after result), comparison flip `cch != bytesCounter` (canonicalized, bit-inert).

### 0x10080590 LegoCarRaceActor::UpdateWorldSpeed — HIT, landed 9b66b2c0 (.9926 -> exact body)

BETA10 0x100cd8cf interleaves the `m_lastAcceleration` store inside the
changeInSpeed computation (fld p_time; fsub lastAcc; **fst temp**; mov lastAcc;
fmul acc; fstp). The retail-shaped text:

```diff
 	MxFloat deltaSpeed = maxSpeed - m_worldSpeed;
-	MxFloat changeInSpeed = (p_time - m_lastAcceleration) * m_acceleration;
+	MxFloat changeInSpeed = p_time - m_lastAcceleration;
 	m_lastAcceleration = p_time;
+	changeInSpeed *= m_acceleration;
```

Measured: 429/9 (offsets 321-329, p_time-load scheduling permutation) -> 429/0.
Body sha: d06fcb7b71f74ac8 -> 1b572502f865d315. Recolour victims: NONE.
IMPORTANT TRAP found while landing: adding a 3-line comment to this TU recolours
4 COMDATs (vendor _Tree dtor/erase/find + CheckPresenterAndActorIntersections)
— MSVC 4.2 codegen in this TU is **line-count sensitive**; the edit landed
comment-free. Inert/regressing cells: named `deltaTime` intermediate (recolours
HandleJump x2 + CalculateSpline), statement reorder cis-first (103 diffs),
oldAcceleration temp (6 diffs elsewhere), plain decl split (no change).

### 0x100a9410 LegoROI::Intersect — HIT, landed 1e5dde4c (.9904 -> exact body)

Retail + BETA10 0x1018b324 both emit `fld intersectionDistance; fcomp
p_rayLength; test ah,0x41` at the box-path ray test; ours emitted the mirror.
The comparison spelling flip is CANONICALIZED (bit-inert — measured), but the
declaration POSITION of `intersectionDistance` is the lever:

```diff
+		float intersectionDistance;
 		LegoS32 i;
 		for (i = 0; i < 6; i++) {
 			boxFacePlanes[i] = m_local2world[i % 3];
 			...
 		}

-		float intersectionDistance;
 		for (i = 0; i < 6; i++) {
 			intersectionDistance = p_rayDirection.Dot(p_rayDirection, boxFacePlanes[i]);
```

Measured: 1553/4 (936, 939, 944, 946) -> 1553/0. Body sha 3d1e7b4b782b3aab ->
fb8815d45c5c5a00. Recolour victims: NONE (~LegoROI and LegoROI::Read bodies
unchanged). Other cells: decl-in-loop 54 diffs, `LegoS32 i, j;` merge 5 diffs.

## IMPROVED (landed)

### 0x1002e8d0 LegoPathActor::CheckPresenterAndActorIntersections — landed ad82dfe1 (.9838, 3 -> 2 masked diffs)

```diff
-		if (plpas.find(*itpa) != plpas.end()) {
+		if (plpas.end() != plpas.find(*itpa)) {
```
Fixes the find/end CMPDIR at offset 261 (retail `3b 5d d8`). Recolour victims:
NONE. Remaining residue (compile-state class): offset 47 loop-entry reg-reg CMP
tie, offset 98 _Nil-walk CMPDIR inside the inlined `itap++`.
BETA10 0x100b1010 evidence: June spelled this membership test as the MEMBER
`!(find == end)` (evaluation order end-then-find, thiscall operator==). That
June form probe-REGRESSES retail (566-byte body, 138 diffs, +record ripple) —
post-BETA refactor to the free `!=`; retail's cmp direction matches end-first
spelling. June also confirms `itap++`/`itpa++` POSTincrement (push 0 before the
iterator ++ thunk) — matches ours; `!(it == end())` loop spellings regress
(140 diffs + 9-13 recolours); loop-condition mirrors bit-inert.

## IMPROVED-RECIPE (NOT landed — needs supplier compensation)

### 0x1002b980 LegoExtraActor::CheckPresenterAndActorIntersections (.9833)

Same single edit as above (`plpas.end() != plpas.find(*itpa)` at
legoextraactor.cpp:457) measures: target 1370/1103-misaligned (body 5 bytes
SHORT of retail — a structural walk-exit difference in loop 1) ->
**1375/7** (offsets 321,324,330,332,343,356,401 — end-load scheduling + one
reg tie). BUT it recolours the TU's `_Tree<LegoPathActor*>` COMDATs, and THIS
TU is retail's supplier for them (retail places erase/find/_Copy at
0x1002bff0/0x1002c440/0x1002c5b0 adjacent to this function):
find 92/15 -> 92/10 (better), _Copy 230/189 unchanged, erase 1097/573 ->
1104/960 (WORSE, length shift). Do not land without pairing with an erase
compensation; the flip cell is otherwise the strongest single-text-edit gain
found this session. Neutralizing interactions measured: hoisting `actor` (or
`roi`) CANCELS the flip entirely; loop-1 mirror inert alone.

## CONTRADICTS-RETAIL / structurally unusable BETA10

### 0x1007ca30 LegoPartPresenter::Read (.9953) — BETA10 is a different function

Located the unannotated BETA10 body at **0x1009845e** (bracketed by
legomodelpresenter's 0x10099061 and confirmed by GetData/VideoManager/
TextureContainer call chain; worth adding `// FUNCTION: BETA10 0x1009845e`).
June Read: format-version word (!= 0x13 -> fail), m_parts deleted+recreated up
front, per-texture palette min/step extraction into a stride-3 byte array,
single LegoROI::Read of the whole tree + LegoAnim + Mx3DPointFloat transform
setup — the retail numROIs/numLODs/LOD-loop structure DOES NOT EXIST in June.
No declaration/statement transcription is possible for the residue sites.

Residue (effective baseline reproduces the recorded 4 bytes exactly):
1143/1216 = `_Tree<LegoTextureInfo>` find-walk vs `_Nil` (0x100f0100) CMPDIR
pair (vendor inline, immovable in 30 cells); 2397/2401 = ROI-loop bottom
CMP+Jcc mirror. Toggle map measured over the declaration block (for a future
carrier/text combination sweep; all cells recolour NOTHING else in the TU):

| cell | tex(1448) | cfg(1849) | lod(2208) | roi(2397) | walk pair |
|---|---|---|---|---|---|
| base (current) | ok | ok | ok | WRONG | WRONG |
| `i, j, textureInfoOffset, numTextures` (K) | flip | ok | ok | FIXED | wrong |
| u32-line before numROIs line (B/C) | ok | flip | flip | FIXED | wrong |
| numROIs/numLODs after pointers (E) | flip | ok | flip | FIXED | wrong |
| `i` last in its line (T) | flip | ok | ok | wrong | wrong |
| numROIs split first / numLODs after u32b (U) | flip | ok | ok | FIXED | wrong |
| u32b before u32a (N) | ok | flip | flip | wrong | wrong |
| loop-spelling mirrors (F/G/H/I), i<->j swap (J) | inert | inert | inert | inert | inert |
| June-shaped full reorder (A) / pointers-first (Q) | 51 / 49 diffs — chaos |
No tested cell reaches ok/ok/ok/FIXED; the walk pair never moved. Combination
toggles are NON-LINEAR (X1-X3 composites all give {tex,lod} + roi-wrong).
June scrap worth keeping: June spelled the texture loop `numTextures > i`
(memory operand left under /Od) — retail's mirrored texture-loop bottom is
consistent with that spelling but ours already matches post-overlay.

## NO-LEVER-FOUND (cells listed; residues are compile-state class)

- **0x100035e0 Helicopter::HandleControl (.9907)**: residue = 19-byte store
  scheduling permutation across the four inlined Mx3DPointFloat ctors
  (v68/va4/up/v90) at body 748-766. BETA10 0x1002a587 CONFIRMS our declaration
  and statement order (ctors v68,va4,up then v90(0,1.0f,0), GetWorldUp after).
  9 cells: all 6 permutations of (v68,va4,up) shift the residue (17-82 diffs,
  best `v68,up,va4` 17), v90-first 82, split-lines inert. Base is June-true.
- **0x1002aba0 LegoExtraActor::HitActor (.9791)**: 1617/29 at 411-416 (i++ vs
  m_boundary load order at the edge-loop bottom), 889-977 reg ties, 1154-1160.
  4 cells (i hoist, `GetNumEdges() > i` mirror, both, normal-pointer hoist):
  all bit-inert. BETA10 not conclusive (June actor code differs heavily).
- **0x100c3750 MxRegion::AddRect (.9739)**: 1157/10 at 640-723 = esi/edi/ebx
  role permutation inside ONE inlined `cursor.Prepend` (MxList node insert).
  8 cells: per-site newSpan hoists (5) bit-inert, hoist-all 39 diffs + 6
  recolours, span/cursor decl swap inert.
- **0x100d0d80 ReadData (.9722)**: 424/18 = the final
  `Size(data2) + (data2 - p_buffer)` add-chain association + pop scheduling.
  7 cells: term swap and re-parenthesization BIT-INERT (confirms the wave-1
  int-chain law even with an embedded SUB), id/data/data2 decl permutations (4)
  inert, data3 hoist worse (20).
- **0x10083500 LegoCharacterManager::GetActorROI (.9684)**: 822/9 = 5 CMPDIR
  (3 one way, 2 the other) + one push-pair swap. Source already uses
  `!(it == m_characters->end())` — the free `!=` DOES NOT COMPILE here
  (const_iterator vs iterator, C2679), explaining the spelling. 4 cells:
  end-mirror 549 diffs, decl swap 648 (length change), iterator-typed `it`
  557 + 9 recolours. Base is a sharp local optimum.
- **0x1003d170 LegoCacheSoundManager::FindSoundByKey (.9552)**: divergence at
  +60: retail spills `key` to its slot immediately after `operator new` and
  keeps EAX; ours copies to EDX and spills late; downstream register-role
  ripple (181 raw bytes, length equal). 5 cells: key decl split inert,
  it-decl-first 153/2-recolours, end-mirror inert, named entry temp worse,
  int-chain shapes inert. (Source itself notes the function was rewritten
  after BETA10.)
- **0x10038b10 Pizza::HandleEndAction (.9538)**: 1232/14 = whole-body ecx/edx
  role swap starting at the first statement pair (`result` / `objectId`).
  3 cells (decl swap = 35 diffs worse, both split forms inert). BETA10
  0x100ee4f5 not deeply read (time); candidate for a wave-3 frame read.

## NOT-REACHED (queued for wave 3, in priority order)

0x1009c070 MxDeviceEnumerate::EnumDirectDrawCallback (.9780, BETA10 0x1011dedf;
CONFIG-shared TU — coordinate with CONFIG donors before touching);
0x100170e0 CarRace::HandlePathStruct (.9752, 1391/111 baseline measured);
0x10040360 Act3Cop::FUN_10040360 (.9730); 0x10080be0 CalculateSpline (.9545,
779/646 deep register divergence from +40 — needs full BETA10 0x100cdc54
transcription session); 0x100a83c0 ~LegoROI (.9538); 0x1004d330
TowTrack::HandlePathStruct (.9536, 856/11 — x87 st-index + reg-role class, low
odds); 0x10058e70 LegoOmni::Create (.9510, 2616/1386 deep); 0x10081840
LegoCarRaceActor::CheckPresenterAndActorIntersections (.9498); 0x100417c0
Act3Brickster::FUN_100417c0 (.9496); 0x10054050 Act3Ammo::Animate (.9476,
2665/935); 0x10046050 PlaceActor (.9552); rows below .95 untouched except
those triaged above. Act1State ctor (843/24) left alone per wave-1 closure
(BETA10 layout differs); LegoWEGEdge::LinkEdgesAndFaces left per prior closure.

## Method findings (new, measured this session)

1. **Probes must compile the effective overlay-rendered source.** Clean-tree
   compiles reproduce neither the lean residues (legopartpresenter: 18 vs 4
   diffs) nor the gate. Harness renders the shadow from the worktree manifest;
   landings repin with tools/repin_overlay.py.
2. **Line-count sensitivity**: in at least legoracespecial.cpp, adding a
   3-line comment (no tokens) recolours vendor _Tree COMDAT bodies and a
   sibling function. Land text edits line-neutral where possible and always
   re-verify the exact landed text (comments included).
3. **/Od slot law (calibrated)**: within a scope, uninitialized locals receive
   frame slots before initialized ones; ties textual; statement position of
   `x = expr` (vs `T x = expr`) is otherwise emission-identical at /Od. Slot
   reading therefore UNDERDETERMINES declaration order — pairs like
   {uninit A; init B} and {init B; uninit A} produce identical /Od frames but
   DIFFERENT /O2 register-role/CMP-direction ties (Advance's hit).
4. **Comparison-spelling mirrors are canonicalized for scalar/int AND for many
   fp compares** (Intersect: the fld/fcomp operand order did not respond to
   `a <= b` vs `b >= a`); the responsive axis is declaration POSITION/order of
   the operands' vregs. Mirrors DID work once at an inlined-call boundary
   (find != end with the callee un-inlined) — when one side is a call result
   and the other is fully inline, the mirror flips the cmp.
5. Int +/- chain association at function tails is canonicalized (ReadData) —
   extends the wave-1 BIT-INERT law to chains containing a subtraction.

## Session summary

- Landed: 3 byte-exact bodies (MXIOINFO::Advance, LegoCarRaceActor::
  UpdateWorldSpeed, LegoROI::Intersect) + 1 two-thirds-residue improvement
  (LegoPathActor::CheckPresenterAndActorIntersections), all with ZERO recolour
  victims, all re-verified through the effective overlay render after
  manifest repin. Commits 3e3511c8, 9b66b2c0, 1e5dde4c, ad82dfe1 on
  worktree-agent-ac4103b0b38d05ae1.
- 1 strong unlanded recipe (LegoExtraActor sibling flip) blocked on a supplier
  (_Tree erase) regression.
- 0 unverified claims; every number above is a fresh probe measurement.
