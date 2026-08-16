# Donor-debt git-bisect foundry — ledger

Session: donor-debt bisect agent, 2026-08-15/16.
Lane: out-of-tree probe compiles against /Users/foxtacles/Projects/isle-build-beta
(reconfigured and gate-verified from this worktree: LEGO1 4820/4933, ISLE 172/172,
CONFIG 111/111 — identical to the main session's state). Probe lane proven
bit-identical to the build lane (null-probe of legoanimpresenter reproduced the
build objects' bodies byte-for-byte). All pins verified masked-exact against
`legobin/LEGO1.DLL` before use.

Body sha256 convention: sha256 of the COMDAT `.text` raw section bytes
(`tools/byte_identity.py` CoffObject + coff_body). "retail masked-exact" =
non-relocation bytes equal to the retail span at the row VA.

---

## Row 1 — 0x1006a3c0 LegoAnimPresenter::UpdateStructMapAndROIIndex — RECIPE-FOUND
## Row 2 — 0x1006abb0 LegoAnimPresenter::VerifyAnimationNode — RECIPE-FOUND

Pins: row1 `fa63e966986dde3776a5f0766b9b03fdfe1c3de5a24ed1447ea6a1c47ea7ef67` (290 B,
12 relocs), row2 `c542bd5460d257dced76cd6b4910d3ab94352b8755ea1f2cd030891bc8c264eb`
(213 B, 7 relocs). Both masked-exact vs retail (verified).

**Flip commit**: 1ce6d832e185958af812575ea13f2b60a3a9743d is the last commit whose
blob (sha256 163783f0…) carries the era spelling; the drift entered with the later
declaration-position retunes (4e7b5620 "Declare the result variable last",
f4318559). s113's SOURCE-RECIPE already pointed at this blob + ClassPad carriers,
but that recipe is dead against today's headers (measured: era blob + recorded
carrier gives 291 B body b98154f7…, not the pin — header-closure drift, not text).

**Minimal edit (verified on CURRENT effective text)** — restore the era (and
retail-producing, hence plausibly 1997) local-declaration order in both functions:

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

(referred to as "e12" below; e1 = first hunk only, e2 = second hunk only.)

**Carrier state**: with the e12 text, a single `/FI` declaration-shape donor
produces BOTH pinned bodies at once. Verified joint hits (pins measured, retail
masked-exact): `entropy.generate_shape(c,f)` at (2,16), (3,24), (4,32), (5,40),
(6,6), (7,14), (10,50). e1 alone + those carriers flips only row 1; e2 alone only
row 2 (clean separability). Bare e12 (no carrier) gives 291 B/213 B non-pin bodies.

**Landing shape** (grammar-expressible today):
- land the e12 source edit (readable; matches the pre-drift repo spelling and
  produces the retail bytes);
- keep the TU's existing overlay ops unchanged;
- add donor `declaration_shape` classes=2 functions=16 (or any of the seven
  verified states) to the TU's `compose_equal_body_comdat` entry;
- compose row 2 as equal-body (213=213) and row 1 as same_slot_resize
  (seed 291 → donor 290; retail linked span 304);
- update the TU seed source_sha256 and the source_overlay clean/effective pins.

**Recolour victims / compensation — measured**:
- Seed compile with e12 (existing overlay, no extra carrier): exactly TWO bodies
  change vs today's seed — the two targets themselves (row1 290→291 b98154f7…,
  row2 213→213 f97e26c5…). Zero collateral in the other ~100 text bodies.
- All 7 currently-composed function pins of this TU reproduce EXACTLY on the e12
  text under their existing manifest donor recipes (replayed: suffix VC15,
  suffix VC1, prefix VA40 → 7/7 pins, including AssignIndiciesWithMap-adjacent
  set: e7dd1b8d…, 53c49db8…, 6d237e25…, c6081a91…, fd0c8773…, 81544adb…,
  7dba54f1…). No donor retune needed.

---

## Row 3 — 0x1002c440 _Tree<LegoPathActor*…>::find — RECIPE-FOUND (carrier-only, no source edit)
## Row 4 — 0x1002c5b0 _Tree<LegoPathActor*…>::_Copy(node,node) — RECIPE-FOUND (same donor)

Link winner (verified against the lean objects1.rsp scan): first definer =
`CMakeFiles/lego1.dir/LEGO1/lego/legoomni/src/paths/legoextraactor.cpp.obj`
(rsp#32; other definers legopathactor#36, legopathcontroller#67, act3ammo#78,
legoracespecial#112).

Pins recovered from s68-comdat-hybrid/direct-batch/manifest.json and re-measured
from the recorded donor objects:
- find `8e107d4a821eb26c06e8e59fd63ec9ce5f411b66403e1c25124e71d8596d0050`
  (92 B, 2 relocs) — masked-exact vs retail (verified);
- _Copy(node) `0d94b68698c1b8ddba753a982fe3cc82a9d66036f4003cd7663718287ec72205`
  (126 B, 5 relocs) — masked-exact vs retail (verified).
Historical donors were from two DIFFERENT TUs (a legopathcontroller probe and a
July-26 legopathactor obj snapshot) — neither ever satisfied both pins at once.

**Recipe (verified)**: NO source edit. On the current effective legoextraactor
text, donor `declaration_shape(5,21)` via /FI produces BOTH pins simultaneously
(also (10,32); measured from the kept probe objects). Compose find + _Copy(node)
into the legoextraactor seat as equal-body splices (seed find f084c2bb… same
92/2, seed _Copy af6d89af… same 126/5; s68 measured 10 and 3 changed bytes).

Single-pin fallback states also measured: find at shape(4,12) and
forward_run(*,12); copy at shape(6,30), shape(7,56), forward_run(*,28), VC_11,
VC_63.

**Recolour victims**: none — donor-only landing; the seed object is unchanged.

---

## Row 7 (scope addition) — 0x1002bff0 _Tree<LegoPathActor*…>::erase(iterator) — ERA-FOUND-BUT-UNMINIMIZED

Retail truth: 1096 B body inside an 1104 B span (roadmap size 0x458 includes
padding). Current winner body: 1104 B, structurally different.

**Era**: commit 971fe939 ("Clear unknowns in LegoPathActor", 2026-01-31, blob
91d07cb8…) compiled bare against CURRENT headers gives erase 1096 B at 42 masked
diffs, _Copy = PIN (masked-exact), find 20 diffs. The flip into today's
behaviour is commit 45d6dfe2 ("Reshape LegoExtraActor::HitActor to the
original's inline depth", 2026-07-26) — exactly two code hunks in
legoextraactor.cpp (StepState `static const float g_hitAnimationDelay = 2000.0f;`
+ `g_hitAnimationDelay + p_time` instead of `p_time + 2000.0f`, and
`Vector3 positionRef((const float*) local[3])` instead of
`Vector3 positionRef(local[3])` in HitActor).

**Best measured states** ("varab" = both hunks reverted on current effective
text): erase retail masked-EXACT (1096/0) at declaration_shape (8,64), (6,58),
(9,51), (10,70). On the UNEDITED current text erase was never exact in ~700
carrier states (full shape grid c1..10 × f=c..10c, forward runs, positions fi) —
consistent with the main session's failed sweeps.

**Conflict to resolve**: find's pin appears ONLY on the un-reverted text
(0 find-pin states in ~800 varab states incl. the full shape grid); erase appears
ONLY on the reverted text. A varab seed also recolours 13 bodies in the winner
obj including currently-exact rows (Restart 199, CalculateSpline 223,
HitActor 1617→1563, StepState 876, CheckPresenterAndActorIntersections
1375→1370, two vector COMDATs dropped, tree dtor + both _Copy overloads + find +
erase). StepState (.931) and HitActor (.979) are OPEN today, so the 45d6dfe2
reshape closes no row that the revert would lose, but the seed swap needs a full
re-cover pass.
Single-hunk splits were also measured: hunk-a alone is byte-inert bare
(= current seed); hunk-b alone changes the family but had no erase-exact state
in the sparse sweep; full grids for vara/varb were queued (see addendum below).

Verdict: era and minimal text delta identified and verified; a single TU state
serving find+copy+erase together is NOT yet found. Recommended interim landing:
rows 3/4 via the cur-text donor above (no conflict), row 7 held pending either a
varb-grid hit or a two-seed strategy decided by the main session.

---

## Row 5 — 0x10083500 LegoCharacterManager::GetActorROI — RECIPE-CANDIDATE (2 bytes from exact)

Retail truth: 822 B of code (roadmap 0x339=825 includes 3 bytes of int3
padding). Current seed body 725b3369… = 9 masked diffs: three `cmp` operand-order
bytes (0x34/0x59/0xA2 want 3b) in the inlined map-find, two (0x16a/0x198 want 39)
in the insert path, and an eax/ecx pairing swap at 0x1f5-0x1fc near the
iterator::_Dec call.

**Evidence**: retail-EXACT bodies (sha a574d969…, 822/0 masked) exist in ~20
recorded agentBR probe objects (oobj_agentBR_R*/R3* legocharactermanager) across
MANY carriers — carrier-insensitive, text-driven. Their source
(isle-tools/probes/agentBR/z_ra3.cpp) differs from current GetActorROI in exactly
two named-temporary hoists:

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

**Measured on current effective text**: both hoists together ("h12") = 822 B,
maskdiff 9 → **2** (only the two insert-path cmp bytes 0x16a/0x198 remain,
3b→39). Each hoist alone regresses to 825/630. Spelling variants matching the
exact sibling `Exists` (iterator + `it != end()`) are structurally wrong
(810-813 B; `const_iterator != iterator` does not even compile in mxstl).
Carrier sweeps on the UNEDITED text (bare + shape multiples + forward runs +
decl-swap variant, 242 states) produced no state below 8 diffs, no exact.

Note: the agentBR probes also used modified header packages
(probes/agentBO/i_view + m_r_pkg realtime variants) — the last 2 bytes may be
theirs; the full shape grid over h12 was queued (addendum below).

---

## Row 6 — 0x1009c070 MxDeviceEnumerate::EnumDirectDrawCallback — RECIPE-FOUND (alive today; lane was wrong, not the text) — WITH A CONFIG-SIDE BLOCKER

Pin `1ddfbc889bff6bc99c22049eb8808a17eb13442b611ab05d3706234a066d5ec8` (541 B,
28 relocs) — masked-exact vs retail (verified).

**Root cause of the "DEAD" verdict**: the recipe never ran in its lane. The pin
reproduces TODAY, on the CURRENT effective text, with the s113 guard transform
applied, compiled in the CONFIG lane (config.dir flags: -DMXDIRECTX_FOR_CONFIG
-D_AFXDLL -DDIRECT3D_VERSION=0x500, -MD, no SMRTHEAP /FI) plus
`/FI entropy.generate_shape(1,1)`:

- exact transform (s113 verify_native.py wording, anchors verified on current
  text — line-count neutral, blank lines become the guard lines):
  wrap MxAssignedDevice ctor+dtor in `#if !defined(MXDIRECTX_FOR_CONFIG)` /
  `#endif`;
- measured: guarded + shape(1,1), CONFIG lane → body sha = PIN, 541 B, retail
  masked-exact (probe dx-curguard-shape11-cfg);
- minimality: guarded bare → b3baa955… (miss); unguarded + shape(1,1) → 536 B
  c008a4f9… (miss); both components required;
- the same replay in the mxdirectx lane misses (9b4b7402…), and 2×139-state
  sweeps of both lanes on the unguarded text found nothing — the guard is
  load-bearing, the LANE selection was the lost ingredient.

**Landing cost (measured)**: the guard is preprocessing-inert for the LEGO1 lane
(objdiff: 0 of 30 bodies change in mxdirectx.dir), but in the CONFIG lane it
removes MxAssignedDevice ctor/dtor and recolours 4 bodies (~list<MxDriver>,
EnumDirectDrawCallback-CONFIG 536→541, MxDriver copy-ctor, EnumDevicesCallback).
CONFIG.EXE is currently 111/111 + MD5. s73's 505-shape grid on the guarded
source recovered CONFIG 0x401070/0x401650/0x401990/0x401cd0 but NEVER CONFIG
0x401770 (EnumDirectDrawCallback's own CONFIG row wants the 536-form, which only
the unguarded text produces in that lane). **Landing the guard as-is would break
CONFIG 401770 with no known recover** — this recipe is verified but its source
edit is CONFIG-hostile.

**Structural alternative (partial evidence)**: the lane-dependence data says
1997's CONFIG compile had MxAssignedDevice ctor/dtor present (536-form exact
today) while 1997's LEGO1 EnumDirectDrawCallback carries absent-form entropy
(541 pin from the guarded CONFIG lane). An inverted guard
(`#if defined(MXDIRECTX_FOR_CONFIG)`) keeps CONFIG untouched and puts the
mxdirectx lane in the absent state: measured mxdirectx-lane victims = ctor/dtor
removed + 3 recolours; EnumDirectDrawCallback stays 541-form (bare 9eb73dbf…,
shape(1,1) 7ec746d3… — pin not yet hit in this lane; full shape grid queued,
addendum below). This route requires re-homing MxAssignedDevice ctor/dtor for
the LEGO1 link (0x1009b8b0/0x1009b8d0 currently exact from this TU) — the
7881f47f TU-partition precedent applies, but placement inside the retail
contribution span must be checked before committing.

---

## Addendum — queued grids (results to be appended)
- varb/vara full shape grids (erase/find/copy joint hunt on single-hunk texts).
- h12 full shape grid + forward runs (row 5 last-2-bytes hunt).
- mxdirectx-lane full shape grid on cur + inverted-guard texts (row 6 own-lane pin hunt).
