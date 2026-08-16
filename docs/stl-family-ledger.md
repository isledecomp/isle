# The `_Tree` / container-instantiation family — ledger

Lane STL, 2026-08-15 night wave. Worktree `agent-a30c03b93e670e7be`
(branch reset to `entropy-stabilization` 53a19e9c), build dir
`/Users/foxtacles/Projects/isle-build-tr03`.

Baseline verified in this worktree before any change:
`ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE: LEGO1 4831/4933,
ISLE 172/172, CONFIG 111/111 in 80.8s`.

Measurement tooling for everything below lives in the session scratchpad
`.../3233884b-.../scratchpad/stl/`:
`famextract.py` (retail bodies of every `_Tree` row), `symmap.py` (our
COMDATs + winner objects), `ourdiff.py` (ours-vs-retail structural diff,
relocation-masked), `summary.py` (the family map table), `lendelta.py`
(instruction-count / ModRM census), `nm2.py` (corpus near-miss against the
corrected oracle). Every number in this ledger is a measurement from this
session; nothing is inherited.

---

## 1. The family map

### 1.1 Scope — the family is 135 rows, 19 open

`_Tree<...>` member instantiations in `LEGO1.DLL`: **135 scored rows,
116 exact, 19 open.** Open by method:

| method | open | exact |
|---|---|---|
| `erase(iterator)` | **10** | 2 |
| `_Insert` | 5 | 8 |
| `_Erase` | 2 | 11 |
| `insert` | 2 | 4 |
| `find` / `_Lbound` / `lower_bound` / `_Copy` / rotations | 0 | all |

The first line is the whole story: **`erase(iterator)` is wrong in 10 of
its 12 instantiations, including in TUs where every other `_Tree` member
of the same instantiation is byte-exact.** `legoworld.cpp` emits
`CoreSetCompare`'s `_Insert`, `_Erase`, `find`, `insert`, `_Lbound`,
`lower_bound` all at 1.0 — and `erase` at .9027. So the defect is not a
whole-TU property and not a header property; it is per-function.

### 1.2 The map (ours vs retail, measured this session)

`d` = our body length − retail body length. `sim` = insn-level similarity
after relocation masking; it reproduces reccmp's ratio to 4 decimals, so it
is the same metric the gate uses.

| addr | m | method | retail | ours | d | winner object | instantiation |
|---|---|---|---|---|---|---|---|
| 0x10049890 | 1.0000 | erase | 1110 | 1110 | +0 | legopathedgecontainer.cpp | LegoBEWithMidpoint (multiset) |
| 0x10029d50 | 0.9212 | erase | 1119 | 1117 | −2 | legosoundmanager.cpp | LegoCacheSoundEntry |
| 0x1001d890 | 0.9027 | erase | 1106 | 1106 | +0 | legoworld.cpp | MxCore* / CoreSetCompare |
| 0x100a7960 | 0.8780 | erase | 1100 | 1101 | +1 | viewlodlist.cpp | ViewLODList* |
| 0x1006dec0 | 0.8205 | erase | 1104 | 1113 | +9 | legoanimpresenter.cpp | LegoHideAnimStruct |
| 0x10059dc0 | 0.7913 | erase | 1102 | 1103 | +1 | legomain.cpp | LegoTextureInfo* |
| 0x10069e90 | 0.7745 | erase | 1096 | 1104 | +8 | legoanimpresenter.cpp | LegoAnimStruct |
| 0x10068b20 | 0.7680 | erase | 1096 | 1104 | +8 | legoanimpresenter.cpp | LegoAnimSubst |
| 0x100af7e0 | 0.7273 | erase | 1107 | 1103 | −4 | mxmain.cpp | MxAtom* |
| 0x1002bff0 | 0.7092 | erase | 1096 | 1104 | +8 | legoextraactor.cpp | LegoPathActor* |
| 0x10082ca0 | 0.6848 | erase | 1096 | 1104 | +8 | legocharactermanager.cpp | LegoCharacter* |
| 0x100ad4d0 | 1.0000 | _Insert | 679 | 679 | +0 | mxatom.cpp | MxAtom* |
| 0x100a7df0 | 1.0000 | _Insert | 681 | 681 | +0 | viewlodlist.cpp | ViewLODList* |
| 0x1006e720 | 0.8475 | _Insert | 689 | 686 | −3 | legoanimpresenter.cpp | LegoHideAnimStruct |
| 0x1004f9b0 | 0.8051 | _Insert | 679 | 681 | +2 | legotexturepresenter.cpp | LegoTextureInfo* |
| 0x1006a7a0 | 0.7983 | _Insert | 690 | 686 | −4 | legoanimpresenter.cpp | LegoAnimStruct |
| 0x1006c200 | 0.7828 | _Insert | 682 | 678 | −4 | legoanimpresenter.cpp | LegoAnimSubst |
| 0x10083890 | 0.7075 | _Insert | 653 | 652 | −1 | legocharactermanager.cpp | LegoCharacter* |
| 0x1002a1b0 | 0.7059 | _Erase | 82 | 82 | +0 | legosoundmanager.cpp | LegoCacheSoundEntry |
| 0x10057180 | 0.6522 | _Erase | 57 | 57 | +0 | legopathboundary.cpp | LegoAnimPresenter* |
| 0x10085500 | 0.9244 | insert | 653 | 653 | +0 | legocharactermanager.cpp | LegoCharacter* |
| 0x100495b0 | 0.6532 | insert | 648 | 648 | +0 | legopathcontroller.cpp | LegoBEWithMidpoint |

Reference rows that are already exact and share the identical template
body: `_Insert` at 0x100ad4d0 / 0x100a7df0 / 0x10020bd0 / 0x1003d760 /
0x10045dd0 / 0x10047550 / 0x10049e00 / 0x100583a0; `erase` at 0x10049890;
every `_Erase` at 57 bytes except the two above.

### 1.3 What the residues actually are

I disassembled and aligned every open row against its retail body with
relocation operands masked. The residues are not miscellaneous — they fall
into **three shapes, all of them register-allocation consequences**:

**(a) Pure register-pair role swap.**
`0x1002a1b0 _Erase<LegoCacheSoundEntry>` (82 vs 82 bytes) is the cleanest
specimen in the whole tree: the two bodies are byte-identical except that
**every occurrence of `ebx` and `edi` is exchanged**. Seven divergent
blocks, all of the form `mov edi,[esp+0x10]` / `mov ebx,[esp+0x10]`,
`push edi` / `push ebx`. No instruction added, removed, reordered or
re-selected.

`0x1001d890 erase<CoreSetCompare>` (1106 vs 1106) is the same defect at
scale: `ebx`↔`edi` exchanged inside the two *inlined* `_Lrotate`/`_Rrotate`
bodies (offsets 809–890 and 1004–1040), plus exactly one CMPDIR at offset
145 (`cmp ecx,[esp+0x10]` vs retail `cmp [esp+0x10],ecx`).

`0x1004f9b0 _Insert<LegoTextureInfo*>` is the same again with two pairs:
`ebx`↔`ebp` **and** `edx`↔`edi`.

**(b) The same swap, seen inside retail itself.** Retail's own
`_Insert` for `map<const char*,ViewLODList*>` (0x100a7df0, exact for us)
and for `map<const char*,LegoTextureInfo*>` (0x1004f9b0, open) are
byte-identical template bodies that differ *only* by the `ebx`↔`ebp` /
`edx`↔`edi` role assignment. Our build emits the ViewLODList assignment
for both. So the two assignments are both reachable, retail picked
different ones in different TUs, and the choice is therefore a per-TU
compile-state tie — not something the source text of `xtree` can express.

**(c) Basic-block layout inversion.** In the `erase` rows the two mirror
arms of the red-black rebalance (`_X == _Left(_Parent(_X))` and its
mirror) are emitted in the opposite order from retail, with the branch
conditions inverted to match (`je`↔`jne` counts differ by exactly 1 in
every affected row). Example, 0x10068b20: our block at +438 is retail's
block at +553, and our block at +572 is retail's at +460.

### 1.4 The length deltas are NOT statement-count deltas (decisive)

This is the measurement that reframes the lane. For every row I counted
instructions and the mnemonic multiset on both sides (`lendelta.py`):

| row | ours | retail | d | #insn ours | #insn retail | mnemonic multiset equal? |
|---|---|---|---|---|---|---|
| `_Erase` CacheSound | 82 | 82 | +0 | 34 | 34 | **YES** |
| erase CacheSound | 1117 | 1119 | −2 | 375 | 375 | **YES** |
| erase CoreSet | 1106 | 1106 | +0 | 370 | 370 | **YES** |
| erase ViewLODList | 1101 | 1100 | +1 | 369 | 369 | no (`add`+1 `lea`−1, `je`/`jne` swap) |
| erase TextureInfo | 1103 | 1102 | +1 | 369 | 369 | no (same shape) |
| `_Insert` TextureInfo | 681 | 679 | +2 | 234 | 233 | no (`mov` **+1**, `je`/`jne` swap) |
| `_Insert` AnimSubst | 678 | 682 | −4 | 233 | 234 | no (`mov` **−1**, `je`/`jne` swap) |
| `_Insert` AnimStruct | 686 | 690 | −4 | 236 | 237 | no (`mov` −1, `je`/`jne` swap) |
| `_Insert` HideAnim | 686 | 689 | −3 | 236 | 237 | no (`mov` −1, `je`/`jne` swap) |
| erase MxAtom | 1103 | 1107 | −4 | 369 | 370 | no (`mov` −2, `jmp` +1) |
| erase AnimSubst | 1104 | 1096 | +8 | 370 | 367 | no (`mov` +3) |
| erase AnimStruct | 1104 | 1096 | +8 | 369 | 367 | no (`mov` +1, `jmp`+1, `je`−1, `jne`+1) |
| erase HideAnim | 1113 | 1104 | +9 | 372 | 369 | no (`mov` +3) |

Three findings, each of which kills a plausible-sounding text hypothesis:

1. **`erase CacheSound` is −2 bytes with an identical instruction
   multiset.** The whole delta is ModRM encoding: a zero-displacement
   `[ebp]` operand costs one byte more than `[ebx]`/`[edi]`, and retail
   has 5 such operands where we have 3. A source edit cannot produce a
   length change with an identical instruction multiset; a register-role
   tie can, and does.
2. **The `_Insert` family's delta has opposite sign in different TUs for
   the same template body.** `_Insert<LegoTextureInfo*>` is `mov` +1
   (ours longer); `_Insert<LegoAnimSubst>` / `<LegoAnimStruct>` /
   `<LegoHideAnimStruct>` are `mov` −1 (ours shorter). Identical
   `xtree` text, identical node layout (0x18), opposite signed deltas.
   **No source-text defect can do that.** It is TU compile state.
3. **`erase` never calls the comparator.** `_Tree::erase(iterator)`
   performs only unlink + recolour + rotations; there is no `_Kfn`, no
   `comp()`, no `strcmp` in any of the retail bodies (verified by
   disassembly — the byte-compare loop present in `_Insert` at +93..+134
   is absent from every `erase`). So the comparator spelling
   (`strcmp(a,b) < 0` in the three legoanimpresenter comparators versus
   `strcmp(a,b) > 0` in `ROINameComparator` / `MxAtomCompare` /
   `LegoContainerInfoComparator` / `Set100d6b4cComparator`) **cannot** be
   the cause of the erase deltas. It is not a candidate.

**Family verdict.** The open `_Tree` block is one mechanism: a per-TU
register-allocation tie (which vreg lands in `EBX` / `EBP` / `EDI`) plus
the block-layout inversion that follows from it. The length deltas are
downstream of that tie via ModRM encoding and redundant-copy elimination,
not upstream of it via statement count. Therefore the compile-state
(carrier / include-order) channel is the right channel for this family,
and the text channel is not indicated for any `_Tree` row.

### 1.5 Why it never closed: the oracle excluded the answer

`sweep-bench/wave2-oracles.json` records each target's `retail_hex` as
`retail_image[addr : addr + len(our_seed_body)]` — the retail bytes cut to
**our** body's length. `sweep2.py`'s hit test is
`elif len(body) != len(retail): continue`. Consequence: for every row
where our length differs from retail's, **a donor of the correct retail
length was discarded before it was ever compared.**

Measured on this lane's 13 `_Tree` oracles (independently, before the
coordinator's note arrived — the two derivations agree on all 43 `_Tree`
row instances):

| row | oracle length | true retail body | verdict |
|---|---|---|---|
| 0x10068b20 erase AnimSubst | 1104 | 1096 | broken |
| 0x10069e90 erase AnimStruct | 1104 | 1096 | broken |
| 0x1006dec0 erase HideAnim | 1105 | 1104 | broken (overruns by 1 byte into the next function, `0x53 push ebx`) |
| 0x1006c200 `_Insert` AnimSubst | 678 | 682 | broken |
| 0x1006a7a0 `_Insert` AnimStruct | 686 | 690 | broken |
| 0x1006e720 `_Insert` HideAnim | 686 | 689 | broken |
| 0x1004f9b0 `_Insert` TextureInfo | 681 | 679 | broken |
| 0x100a7960 erase ViewLODList | 1101 | 1100 | broken |
| 0x10059dc0 erase TextureInfo | 1103 | 1102 | broken |
| 0x100af7e0 erase MxAtom | 1103 | 1107 | broken |
| 0x10029d50 erase CacheSound | 1117 | 1119 | broken |
| 0x1001d890 erase CoreSet | 1106 | 1106 | OK |
| 0x1002a1b0 `_Erase` CacheSound | 82 | 82 | OK |

Eleven of thirteen. The two sound ones are exactly the two rows whose
length already matches retail — which is the tell: the oracle length is
always our seed length.

**Prior verdicts this invalidates (do not trust them):**
* "0x10068b20 is **sealed carrier-closed** by queue12/13 (shapefull +
  extern + padgrid all swept)" — void. Those sweeps demanded a 1104-byte
  body; retail's is 1096. A correct donor could not have been reported.
* The queue7/queue10–13 `_Tree` sweeps for 0x1006c200, 0x1006a7a0,
  0x1006e720, 0x1006dec0, 0x1004f9b0, 0x100a7960, 0x10059dc0, 0x100af7e0,
  0x10029d50 — same defect, same void.
* `fresh2/nearmiss.py`'s flex rule (`len(body) <= len(retail)` and the
  uncovered tail all `0xCC`) inherits the truncation, so the published
  near-miss `nd` values for the truncated rows are distances to a
  *prefix*, not to the row.
* The corpus min-nd triage in `docs/fresh-eyes-2-plan.md` §C1.4 is
  computed from the same truncated oracles for these rows.

Corrected oracle in use: `scratchpad/bench/oracles-v2.json` (coordinator's,
validated by me against an independent extraction from `legobin/LEGO1.DLL`
— 43/43 `_Tree` rows agree). My own extraction is `stl/tree-retail.json`.

### 1.6 What "closes several rows at once" looks like

`legoanimpresenter.cpp` alone emits **six** open `_Tree` rows
(0x10068b20, 0x10069e90, 0x1006dec0, 0x1006c200, 0x1006a7a0, 0x1006e720)
and all six carry the same residue shape. All three of its `erase`
instantiations show *the same* signed deviation (+3, +2, +3 `mov`s), and
all three of its `_Insert` instantiations show *the same* signed deviation
(−1 `mov`, `je`/`jne` swapped). That is one TU state, six rows. It is the
highest-value single state in the lane.

---

## 2. The corrected bench

`scratchpad/stl/sw.py` is sweep2 with three fixes:
* oracle = `oracles-v2.json`, trimmed to the TRUE retail body length;
* **best-nd and body length recorded for every (state, target)**, never a bare
  hit/miss (the doctrine change fresh-eyes-2 §C1.4 asked for);
* a `--pre <axis>:<k>` product mode (base carrier applied first, then the
  swept axis on top) and an `inc` axis (quoted-include permutations).

`scratchpad/stl/landin.py` is `land_into.py` repointed at this worktree, with
an added **S72 guard**: it prints the seed-vs-donor relocation *symbol*
sequence and flags any target-identity change before writing the manifest.

Re-sweep of `legoanimpresenter.cpp` on today's shadow: **713 states**
(shape 60, fwdL 96, fwdP 96, fwdE 96, extern 161, padgrid 144, inc 60),
0 failed. Best nd per target, against the corrected oracle:

| addr | row | retail | best nd | state | residue offsets |
|---|---|---|---|---|---|
| 0x1006bac0 | ParseExtra | 1763 | **0** | `extern-8-17` | — |
| 0x1006dc10 | AssignIndiciesWithMap | 412 | 0 | base (already exact) | — |
| 0x10068b20 | erase AnimSubst | 1096 | **1** | `fwdE-19` | [145] |
| 0x1006c200 | `_Insert` AnimSubst | 682 | 4 | `shape-5-25` | [486,488,491,492] |
| 0x1006e720 | `_Insert` HideAnim | 689 | 4 | `pad-12-11` | [494,496,499,500] |
| 0x1006a7a0 | `_Insert` AnimStruct | 690 | 5 | `fwdE-37` | [178,494,496,499,500] |
| 0x10069b10 | BuildROIMap | 617 | 10 | `shape-1-5` | [345,356,368,380,…] |
| 0x1006dec0 | erase HideAnim | 1104 | 55 | `fwdE-70` | [273,275,278,286,…] |
| 0x10069e90 | erase AnimStruct | 1096 | 348 | `fwdE-75` | [252,267,269,272,…] |
| 0x1006b140 | CopyTransform | 948 | — | **length 941 in all 713 states** | text channel |

## 3. LANDED: 0x1006bac0 LegoAnimPresenter::ParseExtra (.9613 → exact)

**Gated:** `ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE: LEGO1 4832/4933,
ISLE 172/172, CONFIG 111/111`. GAIN 0x1006bac0, zero LOST. Commit
`2619970f`; accepted-row set re-pinned 4831 → 4832
(sha 84b6715b… → 51b6d880…).

Recipe (reproducible from scratch):
* donor state `extern-8-17` = `extern_run_pair` header `g_h` count 8 /
  seat `g_p` count 17, width 2, on the **current rendered source** — no text
  edit. Body 1763/1763, masked nd 0.
* splice class `same_slot_resize`, seed 1746 → donor 1763,
  linked span 1760 → 1776.
* S72 check: the donor's relocation **symbol sequence is identical** to a
  fresh pipeline seed compile's (63/63), so no callee-identity substitution.

Why it was previously "closed": the memory records ParseExtra as a sealed
negative (corrected-source 2-D dial plane, baseline 4764, plane max 4764) and
`fresh-eyes-2` §C1.4 puts it in the permanent text-only triage at corpus
min-nd 1229. Both numbers were computed against
`retail[0x1006bac0 : +1746]` — our seed's length. Retail's body is **1763**.
At the true length the corpus already contained three nd=0 states
(`sweep2-animdebt/extern-8-17`, `sweep2-open-legoanimpresenter/extern-8-16`,
`sweep2-substerase/extern-8-17`) and one at nd=1 (`extern-7-17`).
The `animdebt` stem is a text variant (its base is the pre-`e12`
legoanimpresenter text), so I re-derived on today's shadow rather than trust
it — `extern-8-17` is nd=0 on today's text too, which is the stronger result
and the one that was landed.

## 4. Measured negatives (record these; do not re-run)

### 4.1 Include-order permutation is inert on `legoanimpresenter.cpp`
60 permutations of the 26-header quoted `#include` block (all adjacent swaps,
all rotations, plus seeded shuffles), compiled on today's shadow. Body-sha
comparison against the base compile:

* **9 of the 10 targets are byte-identical in all 60 permutations** —
  including all six open `_Tree` rows and BuildROIMap and CopyTransform.
* Only `ParseExtra` responds, and only in 13 of 60 permutations.

So fresh-eyes-2 §C2's "include order permutes the whole record/id stream" is
**TU-specific, not general**. The likely reason here: `legoanimpresenter.h` is
included first and transitively pulls in most of the rest, so permuting the
remaining directives cannot change the order in which declarations are
actually processed. Corollary for the next wave: before spending a
permutation budget on a TU, check how much of its include list is already
inside the first header's transitive closure.

### 4.2 The `_Insert` cluster's 4-byte residue is one tie, and the flat
### carrier grammar cannot flip it in this TU

All four open `_Insert` rows have the same residue, a 7-byte window
(`0x1006c200`+485, `0x1006a7a0`/`0x1006e720`+494, `0x1004f9b0`+483):

```
ours  : mov ebx,[edi] ; lea eax,[ebx+8] ; cmp [eax],ecx ; je  +4
retail: mov eax,[edi] ; lea ebx,[eax+8] ; cmp [ebx],ecx ; jne +4
```

Same length, same semantics — an `eax`↔`ebx` role swap plus the branch
polarity inverted with the two successor blocks exchanged. It is the
`_Right(_Parent(_Z)) == _Z` test at the end of `_Insert`.

Census over all **714** states of the today-shadow sweep for `0x1006c200`:
the retail form of that window occurs **0 times**. Every state, at every one
of the four reachable body lengths (678×547, 681×124, 679×31, 682×12),
emits our form. The flat carrier axes (shape, pad, fwdL/P/E, extern,
include-perm) do not reach it.

### 4.3 The `erase` byte-145 tie is coupled to the block layout

`0x10068b20`'s best state is nd=1 at offset 145: ours `3b 4c 24 10`
(`cmp ecx,[esp+0x10]`), retail `39 4c 24 10` (`cmp [esp+0x10],ecx`) — the
`if (_Y != _Z)` test in `XTREE`'s `erase(iterator)` (line 256), which is
vendor source we may not touch. Retail itself emits **both** directions
across instantiations (`39` for CoreSet / AnimSubst / AnimStruct /
LegoCharacter / LegoTextureInfo / CacheSound, `3b` for BEWithMidpoint /
HideAnim / MxAtom / ViewLODList / LegoPathActor), so it is a pure per-TU tie.

Census over the 714 states: 11 states reach length 1096 **with** byte 145 =
`0x39`, but every one of them is in the *block-swapped* family
(nd 286–349, first residue at offset 210 or 252). The 3 states that get the
block layout right (`fwdE-19/51/83`, period 32) all carry `3b`.
**The two properties are anti-correlated across the whole flat grammar** —
that is the precise obstacle for this row, and it is why "one byte away" has
not converted. The live lever is the product axis (a second carrier on top of
`fwdE-19`), which is running; if that fails, the tie needs the C2 inliner /
register-allocator model rather than more blind states.

## 5. Per-row status
