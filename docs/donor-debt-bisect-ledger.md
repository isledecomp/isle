# Donor-debt git-bisect foundry — ledger (FINAL)

Session: donor-debt bisect agent, 2026-08-15/16.
Lane: out-of-tree probe compiles against /Users/foxtacles/Projects/isle-build-beta,
reconfigured and gate-verified from this worktree (baseline run: LEGO1 4820/4933,
ISLE 172/172, CONFIG 111/111 — identical to the main session's state). The probe
lane is proven bit-identical to the build lane (null-probe reproduced the build
objects' bodies byte-for-byte). Every pin used below was verified masked-exact
against `legobin/LEGO1.DLL` before use. ~7,000 probe compiles total.

Conventions: body sha256 = sha256 of the COMDAT `.text` raw section bytes
(`tools/byte_identity.py` CoffObject + coff_body). "retail masked-exact" =
non-relocation bytes equal to the retail span at the row VA.
"shape(c,f)" = `entropy.generate_shape(c,f)` force-included (/FI);
"fwd(P,k)" = `entropy.generate_forward_run(P,k,3)` at the stated placement.
Evidence objects for every claim are kept under the session scratchpad
(`sweep-*/work/*/probe.obj`, `probes/*/probe.obj`).

## Scoreboard

| Row | Address | Verdict |
|---|---|---|
| 1 | 0x1006a3c0 UpdateStructMapAndROIIndex | RECIPE-FOUND (obj-proven; one composer-grammar gap for landing) |
| 2 | 0x1006abb0 VerifyAnimationNode | RECIPE-FOUND + **landed end-to-end in this worktree: linked-image GAIN 4820→4821** |
| 3 | 0x1002c440 _Tree<LegoPathActor*>::find | RECIPE-FOUND (no source edit) |
| 4 | 0x1002c5b0 _Tree<LegoPathActor*>::_Copy | RECIPE-FOUND (same donor as row 3) |
| 5 | 0x10083500 GetActorROI | RECIPE-FOUND (source edit + donor; one victim [Exists] needs a positional retune) |
| 6 | 0x1009c070 EnumDirectDrawCallback | RECIPE-FOUND (alive today — lane was wrong, not text) with a CONFIG-side landing blocker |
| 7 | 0x1002bff0 _Tree<LegoPathActor*>::erase | ERA-FOUND-BUT-CONFLICTED (exact states exist; mutually exclusive with row 3's) |

---

## Rows 1+2 — LegoAnimPresenter::UpdateStructMapAndROIIndex / VerifyAnimationNode

Pins (verified masked-exact vs retail):
row1 `fa63e966986dde3776a5f0766b9b03fdfe1c3de5a24ed1447ea6a1c47ea7ef67` (290 B, 12 relocs),
row2 `c542bd5460d257dced76cd6b4910d3ab94352b8755ea1f2cd030891bc8c264eb` (213 B, 7 relocs).

**Flip commit / era**: the last blob with the pin-producing spelling is
1ce6d832 ("Make LegoAnimPresenter::AppendROIToScene reachable", blob sha256
163783f0…); the drift entered with the later declaration-position retunes
(4e7b5620, f4318559). Replaying the recorded s113 recipe (era blob + ClassPad
carrier) is DEAD against today's headers (gives 291 B b98154f7…, measured) —
the historical carriers no longer bite; the TEXT is what transfers.

**Minimal source edit ("e12"), verified on current text** — restore the era
declaration order (it produces the retail bytes, so it is the plausible 1997
spelling):

```diff
--- a/LEGO1/lego/legoomni/src/video/legoanimpresenter.cpp
+++ b/LEGO1/lego/legoomni/src/video/legoanimpresenter.cpp
@@ void LegoAnimPresenter::UpdateStructMapAndROIIndex(...)
-	LegoAnimNodeData* data = (LegoAnimNodeData*) p_node->GetData();
+	LegoROI* roi = p_roi;
 	LegoChar* und = NULL;
 	LegoChar* und2 = NULL;
+	LegoAnimNodeData* data = (LegoAnimNodeData*) p_node->GetData();
 	const LegoChar* name = data->GetName();
-	LegoROI* roi = p_roi;
@@ MxBool LegoAnimPresenter::VerifyAnimationNode(...)
+	MxBool result = FALSE;
 	LegoROI* roi = p_roi;
 	LegoChar* varOrName = NULL;
 	LegoAnimNodeData* data = (LegoAnimNodeData*) p_node->GetData();
 	const LegoChar* name = data->GetName();
 	MxS32 i, count;
-	MxBool result = FALSE;
```

**Carrier**: with e12, ONE `/FI shape(c,f)` donor state produces BOTH pins in one
object. Verified joint states: (2,16), (3,24), (4,32), (5,40), (6,6), (7,14),
(10,50). The hunks are separable (e1 alone flips only row 1, e2 alone only
row 2, each under the same carriers).

**Recolour victims / compensation (measured)**:
- e12 seed (existing overlay untouched, no /FI): exactly the two targets change
  (row1 290→291 b98154f7…/27 lines; row2 213 f97e26c5…); all other ~100 bodies
  byte-identical.
- All 7 existing composed pins of this TU reproduce EXACTLY on e12 under their
  existing donor recipes (replayed suffix VC15 / suffix VC1 / prefix VA40:
  7/7 PIN-OK).
- One overlay op (#6, the empty-class insert before UpdateStructMapAndROIIndex)
  needs re-anchoring (token-context hash); mechanical — done in this worktree
  (`scratchpad fix_anchors.py` recipe: same physical line seat, recomputed
  ctx/line shas).

**END-TO-END PROOF (this worktree, commit trail)**: e12 landed in the checked
source; manifest TU entry updated (source_sha256
c672620e487fc35c7e305b94e13d3594ffc8b5f1909fb54064a31c30f74c7259, overlay
clean/effective pins updated, effective
19f495a42cad4c1b0fe3d6ff2001c18eef6c45d1273d2e44a5aec6f2e58f3c75 size 43027);
donor `declaration_shape` classes=2 functions=16 (header sha
31e36d131642decc78958672d6c6b512ff487efd79b9aa76b97f0b0e497957db, id
d_31e36d131642); row2 composed as `equal_body_strict` (len 213, pin sha,
changed offsets [10,11,13,15,16,18,33,36,40,50,54,64,75,89,91,96,98,99,113,
145,147,150,156,171]). Full isle_build gate run: **0x1006abb0 GAIN, LEGO1
4821/4933 in the linked image**; the only refusal is the iteration
accepted-raw-row-set pin, which any legitimate gain requires re-pinning.

**Row 1 landing gap (the one open item)**: seed 291 B/27 COFF line rows vs
donor 290 B/28 rows. `same_slot_resize` requires equal line_count, so it
refuses ("target header shape changed" — reproduced). All seven donor states
carry 28 rows, so the pair is (27,28) everywhere. Two clean resolutions, both
main-session-sized: (a) extend same_slot_resize with explicit
expected_seed_line_count/expected_donor_line_count (the FPO class
`compose_equal_linked_span_fpo` ALREADY has exactly these split keys and
handles the line-table resize); or (b) admit an FPO-span function inside a
compose_equal_body_comdat TU. Everything else about row 1 is verified: donor
body = pin, span 304 = (290+15)//16*16, relocs 12=12, characteristics equal,
closure (.debug$F,.debug$S).

---

## Rows 3+4 — _Tree<LegoPathActor*>::find / ::_Copy(node,node) — no source edit

Link winner verified from the lean objects1.rsp scan: first definer =
`lego1.dir/.../paths/legoextraactor.cpp.obj` (rsp#32; other definers:
legopathactor#36, legopathcontroller#67, act3ammo#78, legoracespecial#112).

Pins (recovered from s68-comdat-hybrid/direct-batch/manifest.json, re-measured
from the recorded donor objects, and verified masked-exact vs retail):
find `8e107d4a821eb26c06e8e59fd63ec9ce5f411b66403e1c25124e71d8596d0050` (92 B, 2
relocs); _Copy(node) `0d94b68698c1b8ddba753a982fe3cc82a9d66036f4003cd7663718287ec72205`
(126 B, 5 relocs). The historical donors came from two DIFFERENT TUs (an
lpc_C2 legopathcontroller probe; a July-26 legopathactor obj snapshot); neither
ever satisfied both pins at once — the splices were independent.

**Recipe (verified, donor object kept)**: on the UNEDITED current effective
text, donor `declaration_shape(5,21)` (also (10,32)) produces BOTH pins in one
object. Compose both into the legoextraactor seat as equal-length splices
(seed find f084c2bb… 92/2 → 10 changed bytes; seed _Copy af6d89af… 126/5 → 3
changed bytes at offsets 23/52/97 per the s68 record). Zero victims (donor-only).
Single-pin fallbacks: find at shape(4,12)/fwd(*,12); copy at shape(6,30),
shape(7,56), fwd(*,28), fwd(VC,11), fwd(VC,63) and 30+ more.

---

## Row 7 — _Tree<LegoPathActor*>::erase(iterator) 0x1002bff0 — CONFLICTED

Retail: 1096 B body in an 1104 B span; the retail layout places the whole
_Tree<LegoPathActor*> family inside the legoextraactor contribution region
(0x1002bee0–0x1002c6c0), i.e. ONE 1997 compile produced erase+find+_Copy
together.

**Era**: 971fe939 ("Clear unknowns in LegoPathActor", 2026-01-31) compiled bare
against CURRENT headers gives erase 1096/42-diff, _Copy = PIN, find 20-diff.
The flip is 45d6dfe2 ("Reshape LegoExtraActor::HitActor to the original's
inline depth") — two hunks: (a) StepState
`static const float g_hitAnimationDelay = 2000.0f;` + operand order
`g_hitAnimationDelay + p_time` (era: `p_time + 2000.0f`); (b) HitActor
`Vector3 positionRef((const float*) local[3])` (era: no cast).

**Full-grid results (~4,300 states across 4 texts: shape c=1..10 × f=c..10c
@fi, fwd k=1..96 ×3 prefixes @fi, plus @append/@after_includes)**:
- erase retail-EXACT states exist ONLY with hunk (b) reverted:
  varb (cast-revert only): shape(7,34), shape(8,53), shape(10,27);
  varab (both): shape(8,64), (6,58), (9,51), (10,70). Measured body
  89ac1595e9a3ac4c0e1bbb9c9a076857a77f6bf1c090e63e2b9a1ae6c3363dfd (1096/16,
  masked-exact; obj kept).
- find's pin exists ONLY with the cast present (cur: 14 states, vara: 10);
  ZERO find-pin states on varb/varab.
- copy's pin exists on all four texts.
The `(const float*)` cast in HitActor is a hard switch between the two rows.
StepState (.931) and HitActor (.979) are OPEN today, so the 45d6dfe2 reshape
closes no row the revert would lose; but a varab/varb SEED recolours 13 bodies
in the winner obj including currently-exact Restart and CalculateSpline.

**Verdict**: land rows 3/4 now (cur-text donor, no conflict). erase's true fix
is most likely the authentic 1997 HitActor/StepState source form (the same
root as those two open rows — when HitActor's real text is found, re-run the
erase grid on it). Alternative if erase is wanted before that: land the
cast-revert + shape(7,34) donor and re-cover find… is NOT possible (find-pin
unreachable on that text at full-grid depth) — the two cannot ship together
from one seed today.

---

## Row 5 — LegoCharacterManager::GetActorROI 0x10083500

Retail body: 822 B of code (the roadmap's 0x339=825 includes 3 int3 pad bytes).
Current seed 725b3369… = 9 masked diffs (three cmp-direction bytes in the
inlined map-find, two opposite-direction in the insert path, and an eax/ecx
pairing swap at the iterator::_Dec call site).

**Recovered retail-exact body**:
`a574d9690310e6f37896d160f1e68625f56e297ffbb21012f033ef2d8339e5d5` (822/32) —
found in ~20 recorded agentBR probe objects across many carriers
(carrier-insensitive → text-driven), source `isle-tools/probes/agentBR/z_ra3.cpp`.

**Minimal source edit ("h12"), verified on current effective text** — two
named-temporary hoists in GetActorROI (idiomatic 1997 style; they produce the
retail bytes):

```diff
--- a/LEGO1/lego/legoomni/src/common/legocharactermanager.cpp
+++ b/LEGO1/lego/legoomni/src/common/legocharactermanager.cpp
@@ LegoROI* LegoCharacterManager::GetActorROI(...)
-			char* name = new char[strlen(p_name) + 1];
+			MxU32 length = strlen(p_name) + 1;
+			char* name = new char[length];
@@
-			GetActorInfo(p_name)->m_actor = actor;
+			LegoActorInfo* info = GetActorInfo(p_name);
+			info->m_actor = actor;
```

Bare h12 = 822 B, miss shrinks 9 → 2 bytes; each hoist alone regresses (825/630).
**With a carrier the row closes**: h12 + shape(7,52) → body = a574d969… (retail
masked-EXACT; also shape(8,50), shape(10,45), and fwd(VA/VB/VC, k∈{4,5,6,56})
@suffix — 15 donor states, objects kept). On the UNEDITED text every carrier
axis missed (confirming the S96 record; 242+ states, plus a full grid).

**Victims / cover (measured, h12 seed vs current seed: 9 changed bodies)**:
- Only THREE victims are currently-exact rows: ~_Tree<char*…> dtor 0x10082b90
  (cover: 65 shape states), Exists 0x10083b20 (**no cover found in ~2,000
  swept states** — 4 distinct h12 Exists forms, none retail-masked; needs the
  positional-record lever, i.e. an in-file overlay op near Exists), and the
  composed pair below. erase/insert/_Insert<LegoCharacter…> victims are all
  currently OPEN rows (0.68–0.92) — no obligation.
- Existing composed pins replayed on h12: SwitchSound PIN-OK (VA10 prefix),
  ReleaseAutoROI PIN-OK (VC2 suffix); ~list<ROI*> donor (VC27 suffix) drifts
  but has 216 covering shape states → retune its donor.

**Landing shape**: h12 edit + new donor shape(7,52) composing GetActorROI
(equal_body, 822=822) + retuned ~list<ROI*> donor + a positional record op for
Exists (main-session lever) + accepted-set re-pin.

---

## Row 6 — MxDeviceEnumerate::EnumDirectDrawCallback 0x1009c070

Pin `1ddfbc889bff6bc99c22049eb8808a17eb13442b611ab05d3706234a066d5ec8`
(541 B/28 relocs, masked-exact vs retail, re-verified).

**The recipe was never dead — it was replayed in the wrong lane.** Verified
TODAY on the CURRENT effective text:
- transform (exact s113 substitutions; line-count-neutral): wrap the
  MxAssignedDevice ctor+dtor definitions in `#if !defined(MXDIRECTX_FOR_CONFIG)`
  / `#endif`;
- compile the TU in the CONFIG lane (config.dir flags: -DMXDIRECTX_FOR_CONFIG
  -D_AFXDLL -DDIRECT3D_VERSION=0x500 -MD, no SMRTHEAP /FI) with
  `/FI shape(1,1)` → body sha = PIN, retail masked-exact (probe kept:
  dx-curguard-shape11-cfg).
- Minimality: guarded bare → miss (b3baa955…); unguarded + shape(1,1) → miss
  (536-form c008a4f9…); the same replay in the mxdirectx lane → miss
  (9b4b7402…). Both ingredients (guard, carrier) and the LANE are load-bearing.
- Own-lane alternative exhausted: full shape grids in the mxdirectx lane on
  the current AND inverted-guard texts (2,200 states) + 2×139-state sweeps of
  both lanes on unguarded text: ZERO pin hits. The pin lives only in the
  CONFIG-lane compile state.

**Landing blocker (measured)**: the guard is byte-inert for the LEGO1/mxdirectx
lane (0/30 bodies change) but flips the CONFIG lane's own seed: removes
MxAssignedDevice ctor/dtor and recolours 4 bodies including CONFIG's own
EnumDirectDrawCallback 0x00401770 (536-form → 541-form). CONFIG.EXE is
111/111+MD5 today; s73's 505-shape grid on the guarded source recovered
0x401070/0x401650/0x401990/0x401cd0 but NEVER 0x401770 — the CONFIG row needs
the presence-entropy 536-form that the guarded text cannot produce.
**Landing the guard would break CONFIG 401770 with no known recover.**

Recommended path: donor grammar allows compile_lane selection by define — the
composer donor can be `declaration_shape(1,1)` with
compile_lane required_define=MXDIRECTX_FOR_CONFIG — but the guard must live in
the checked text, and that text is shared with CONFIG's own build. Options for
the main session: (i) a wider CONFIG-side sweep on the guarded text (fwd runs,
positions — s73 tried shapes only) hunting a 401770 re-cover; (ii) the
TU-partition route (MxAssignedDevice ctor/dtor genuinely belong to a
CONFIG-only TU per the 7881f47f doctrine), which requires re-homing LEGO1's
0x1009b8b0/0x1009b8d0 (their retail seats sit INSIDE this TU's contribution
span, so a naive move breaks placement — check the map first); (iii) hold row 6
until CONFIG's 401770 has an independent cover. The recipe itself is verified
and pinned.

---

## Cross-cutting notes for the main session

- The historically-recorded carriers (ClassPad/ZzM headers, s70 random-seed
  entropy.h) are NOT reproducible by the current typed generator and are no
  longer effective anyway (header-closure drift killed them, measured for
  rows 1/2). The s73-era c/f grid IS the current `entropy.generate_shape`
  (byte-identical output — verified).
- The retail truth for a COMDAT family (rows 3/4/7) comes from ONE winner-TU
  compile; per-function splices hid that historically. Two of the family's
  three bodies are jointly reachable today; the third is text-locked behind
  the HitActor cast.
- Off-multiple shape f values matter: the deciding states here were (5,21),
  (7,52), (8,64) — none on the f∈{c,2c,3c,5c,8c,10c} lattice. Full f=c..10c
  grids are ~550 compiles/TU (~25 min at -j3) and worth it.
- All sweep result maps (every state × every text body sha) are in the session
  scratchpad `sweep-*/results.jsonl` for further cover mining.
