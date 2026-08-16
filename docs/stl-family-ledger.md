# The `_Tree` / container-instantiation family — ledger

> ⚠ **READ §10.5, §10.5a AND §11 BEFORE ACTING ON §10.2**, and the
> **RETRACTION above §11.2** before acting on anything that cites the
> count-only law: a carrier run is count-only in `mxmain.cpp` but NOT in
> general, so the extern `(m,k)` split is a real 2-D lattice. The wave-2 conclusion
> "the carrier axis does not move register colour" — which reached the merge
> commit title `c52a89d8` — is **wrong as stated**. It was drawn from a
> partial sample of a sweep that later completed and contradicted it. Two
> independent refutations are now measured: a `_Tree` regrole tie moves on
> the stacked axis (`erase<MxAtom*>` +434), and an *authored* function's
> colouring takes nine values under pure carrier states, retail's among them
> (`LegoPathBoundary::RemoveActor`, nd=0 at `pad-10-12`). The correct
> statement is "the **flat** axis is near-inert on colouring".

Lane STL, 2026-08-15 night wave. Worktree `agent-a30c03b93e670e7be`
(branch reset to `entropy-stabilization` 53a19e9c), build dir
`/Users/foxtacles/Projects/isle-build-tr03`.

Baseline verified in this worktree before any change:
`ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE: LEGO1 4831/4933,
ISLE 172/172, CONFIG 111/111 in 80.8s`.

**Result: LEGO1 4831 → 4833, zero LOST, ISLE 172/172 and CONFIG 111/111
intact.** Verified with a terminal (no-debug) link as well:
`terminal ISLE: IDENTICAL`, `terminal CONFIG: IDENTICAL`,
`terminal LEGO1: distance 633207` — the two MD5-identical images stay
MD5-identical. Two rows landed (`ParseExtra` 0x1006bac0, `~ViewLODListManager`
0x100a7130); both had been unreachable by construction because the bench
scored them at the wrong length, and one of them additionally needed a
carrier the composer could not render until this session. The durable
products are the family map (§1), the two bench defects (§1.5, §5), the
`forward_run_with_shape` recipe (§6), and the hard negatives (§4).

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
and, in the *default* state, all six carry the same residue shape: all three
`erase` instantiations show the same signed deviation (+3, +2, +3 `mov`s)
and all three `_Insert` instantiations the same one (−1 `mov`, `je`/`jne`
swapped).

**But that does not make them one state — MEASURED, and it corrects the
obvious hypothesis.** The three instantiations dial *independently* under
the carrier:

| state | 0x10068b20 erase | 0x10069e90 erase | 0x1006dec0 erase | 0x1006c200 `_Insert` |
|---|---|---|---|---|
| base | +8 len | +8 len | +9 len | −4 len |
| `fwdE-19` | **nd=1** | +11 len | +1 len | −4 len |
| `extern-8-17` | nd=372 | +1 len | −8 len | −4 len |

So "one fix closes several rows" is **false** for this family: each
instantiation needs its own donor state. That is fine mechanically (a
`compose_equal_body_comdat` unit takes many donors and many functions — the
legoanimpresenter unit already carries 5 donors / 10 functions), but it
means the lane's cost is per-row, not per-TU, and it rules out the
"comparator or key-type spelling" explanation a second time: a shared source
cause would move the three together.

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

All four rows want the **identical** 9 retail bytes
`8b 07 8d 58 08 39 0b 75 04` in that window, in three different TUs.

Census (`wincensus.py`) over the **entire** retained corpus plus every state
this session compiled — `sweep-bench/sweep2-*`, `sweep-*`, `probe-*`,
`landinto-*` and my `sw-*` roots:

```
0x1006c200: 0 / 11303 bodies contain the retail window
0x1006a7a0: 0 / 11303
0x1006e720: 0 / 11303
0x1004f9b0: 0 /  3180
```

**Zero out of 37,089 body samples.** Every state, at every reachable body
length, emits our form. The declaration-carrier grammar — shapes (lattice
and full grid), pad shapes, forward runs at three seats, extern pairs,
include permutations, and the stacked products — does not reach this tie in
any of the three emitting TUs. This is a hard negative and it is the single
most useful thing to know about the `_Insert` block: **more states will not
close those four rows.**

### 4.3 The `erase` byte-145 tie is coupled to the block layout

`0x10068b20`'s best state is nd=1 at offset 145: ours `3b 4c 24 10`
(`cmp ecx,[esp+0x10]`), retail `39 4c 24 10` (`cmp [esp+0x10],ecx`) — the
`if (_Y != _Z)` test in `XTREE`'s `erase(iterator)` (line 256), which is
vendor source we may not touch. Retail itself emits **both** directions
across instantiations (`39` for CoreSet / AnimSubst / AnimStruct /
LegoCharacter / LegoTextureInfo / CacheSound, `3b` for BEWithMidpoint /
HideAnim / MxAtom / ViewLODList / LegoPathActor), so it is a pure per-TU tie.

Census over the 714 flat states: 11 reach length 1096 **with** byte 145 =
`0x39`, but every one of them is in the *block-swapped* family
(nd 286–349, first residue at offset 210 or 252). The 3 states that get the
block layout right (`fwdE-19/51/83`, period 32) all carry `3b`.
Across the flat grammar the two properties are **anti-correlated**.

**The stacked product breaks the anti-correlation** (`fwdE:19 × shapefull`,
324 of 550 cells at the time of writing): 22 cells reach length 1096 with
byte 145 = `0x39`, and one of them — `shape-6-39` — is **nd=1 with the
residue at a completely different offset**:

| state | nd | residue |
|---|---|---|
| `fwdE-19` (flat) | 1 | +145 `3b 4c 24 10` vs retail `39 4c 24 10` |
| `fwdE:19 × shape-6-39` | 1 | +431 `3b fa` (`cmp edi,edx`) vs retail `3b d7` (`cmp edx,edi`) |

So the erase family has exactly **two** residual tie bytes and each is
individually reachable; no cell yet has both. Note the second one is the
*same instruction, same defect* that the wave-3 ledger recorded for
`_Tree<LegoPathActor*>::erase` at body+434 ("ours `3b fa` vs retail `3b d7`,
a REGISTER-ROLE tie, not a CMPDIR") — two different instantiations in two
different TUs stuck on the identical byte. That is the family's true signature,
and it is what a C2 register-allocator model would have to predict.

### 4.4 `~LegoCacheSoundManager` (0x1003cf20): the named-iterator hypothesis is dead

Our body is 274, retail 258 (+16), 94 insns vs 87. The structural diff shows
one extra inlined block at ours+146:
`cmp [ecx],0 ; jne ; mov eax,[eax+0xc] ; test eax,eax ; je ; push eax ;
call ; add esp,4` — an inline that retail does not have (retail simply does
`mov ecx,[ebp-0x14] ; push ecx`). The source already carries a TODO on that
exact line ("LegoCacheSoundEntry::~LegoCacheSoundEntry should not be inlined
here"), so this is the documented defect.

Four text variants compiled and measured (donor lane, today's headers):

| variant | body |
|---|---|
| base (`m_list.erase(m_list.begin())`, two `begin()` calls) | 274 |
| v1 named iterator `it`, mirroring the `m_set` loop above (line-neutral) | 274 |
| v2 named iterator `it2` | 274 |
| v3 base minus the TODO comment line (line-count control) | 274 |
| v4 `LegoCacheSoundEntry entry = *m_list.begin();` | **330** (worse) |

The obvious symmetry fix (make the `m_list` loop look like the `m_set` loop)
is **bit-inert**. The extra inline is not driven by the iterator spelling.
Next hypothesis for this row: the inline is inside `list<>::erase` /
`~LegoCacheSoundEntry`, so it belongs to the C2 inline-budget class, not the
statement-spelling class.

### 4.5 `LegoTextureContainer::GetCached` (0x100998e0): one extra frame slot

Ours 995 / retail 987, 341 insns vs 338. The whole divergence is anchored on
a **4-byte frame-size difference**: ours `sub esp,0xfc` with `desc` at
`[ebp-0x108]`, retail `sub esp,0xf8` with `desc` at `[ebp-0x104]`. Retail
therefore references **one fewer distinct 4-byte local slot** than we do, and
uses the freed register to keep `p_textureInfo->m_surface` live in `ESI`
(retail +66 `mov esi,[eax+4]`, then `push esi` at the Lock call; ours
reloads through `EAX` and spills). Per the named-local rule this is a real
source constraint (distinct slots referenced), so the lever is to eliminate
one named local in `GetCached` — most likely the `cached` / `surface` pair
inside the match branch. Not attempted this session; the carrier axis cannot
change frame size.

## 5. A second bench defect: the carrier grammar was never fully swept

`sweep2.py`'s three forward-run axes conflate the **declaration prefix** with
the **placement**:

| bench axis | identifier prefix | placement | composer can render it? |
|---|---|---|---|
| `fwdL` | `MxUnkRecVA` | top of file | yes (`placement: prefix`) |
| `fwdP` | `MxUnkRecVB` | after the last `#include` | **NO** |
| `fwdE` | `MxUnkRecVC` | end of file | yes (`placement: suffix`) |

Two consequences, both measured:

1. **`fwdP` states are not landable.** `isle_build.py`
   `compose_translation_units` renders `forward_declaration_run` only at
   `prefix` (very top), `suffix` (EOF) or `force_include`; "after the last
   include" exists only in the bench. Any recorded `fwdP` hit has to be
   re-derived at a renderable placement before it can be landed. (`fwdP-95`
   is exactly the state `fresh-eyes-2` §C1.3 records for BuildROIMap.)
2. **Six of the nine (prefix × placement) combinations were never swept**,
   and one whole placement — `force_include` of a *forward run*, which the
   manifest validator explicitly permits
   (`placement in ("prefix","force_include","suffix")`) — has never been
   tried at all. I added generic axes `f<A|B|C><P|S|I>` to `sw.py` for this,
   plus `externL` (single-sided `extern_run_pair` runs with counts 9..96,
   where the historical `extern` axis stopped at 8×17).

Also: the historical `shape` axis only samples the lattice
f ∈ {c, 2c, 3c, 5c, 8c, 10c}. The donor-debt ledger already noted that the
deciding states are usually *off* that lattice ((5,21), (7,52), (8,64)); the
full grid is 550 states per TU and is now the `shapefull` axis.

## 6. Framework growth: the `forward_run_with_shape` stacked carrier

**The composer could render exactly one carrier per donor.** `isle_build.py`
`compose_translation_units` renders `declaration_shape` at `force_include`,
`forward_declaration_run` at `prefix`/`suffix`/`force_include`, and
`extern_run_pair` at its two seats — but never a *shape and a run together*.
The bench, however, can stack them (`sw.py --pre`), and the stacked space is
where the remaining near-misses actually close.

Measured on `ViewLODListManager::~ViewLODListManager` (0x100a7130):

| state space | states | best |
|---|---|---|
| single carrier (shape lattice, fwdL/P/E, extern, padgrid, inc) | 457 | nd=1 (`fwdE-96`, offset 222); the 398-byte retail length is reached in only 6 states |
| `shapefull` alone (full c×f grid) | 83 | length 395 in **every** state — /FI shapes never reach 398 |
| `fAI`/`fBI`/`fCI` (forward runs force-included) | 68 | length 395 in every state |
| **`fwdE:96` × `shapefull`** | 221 | **nd=0 at `shape-6-60`** |

So I added a typed recipe kind (commit `4ba1ac13`):

```
kind: forward_run_with_shape
placement: prefix | suffix        # the forward run's seat
prefix / count / width            # entropy.generate_forward_run
classes / functions               # entropy.generate_shape, force-included
generated_header_sha256 = sha256(forward_run_bytes + shape_bytes)
```

It stacks the two **existing** typed generators exactly the way
`extern_run_pair` already stacks two extern runs at two seats. No literal
text, no new generator, no gate relaxed. Validation mirrors the
`extern_run_pair` branch in `byte_identity.py`; rendering adds one
`placement == "run_with_shape"` branch in `isle_build.py`.

**This roughly squares the reachable donor space for every open row in the
project**, and it is the reason the second landing below exists.

## 7. LANDED: 0x100a7130 ViewLODListManager::~ViewLODListManager (.9281 → exact)

**Gated:** `ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE: LEGO1 4833/4933,
ISLE 172/172, CONFIG 111/111`; GAIN 0x1006bac0 + 0x100a7130, zero LOST.
Commit `c1582751`; accepted-row set re-pinned 4832 → 4833.

* donor: `forward_run_with_shape`, `MxUnkRecVC` × 96 at **suffix** plus
  `declaration_shape(6, 60)` force-included, on the current rendered source
  (no text edit). Body 398/398 masked-exact.
* splice `same_slot_resize` 395 → 398.
* S72 check: donor relocation symbol sequence identical to a fresh pipeline
  seed (17/17).

Why it had never been seen: `wave2-oracles.json` scored this row against
`retail[0x100a7130 : +395]` (our seed's length) while retail's body is
**398**, so nothing of the correct length could be reported. Four text
variants of the destructor were also measured and all regress (§8.3).

## 8. Per-row status

All `nd` values below are **against the corrected oracle** and were measured
in this session, in the donor lane, on today's shadow unless stated.
"state" = the sweep label; `pre X × Y` = a stacked carrier (landable only
through the new `forward_run_with_shape` recipe, and only when the pre half
is `prefix` or `suffix` — `fwdP` is *not* renderable).

| addr | row | m | ours/retail | best state | nd | verdict |
|---|---|---|---|---|---|---|
| 0x1006bac0 | ParseExtra | .9613 | 1746/1763 | `extern-8-17` | **0** | **LANDED** |
| 0x100a7130 | ~ViewLODListManager | .9281 | 395/398 | `fwdE:96 × shape-6-60` | **0** | **LANDED** |
| 0x10068b20 | erase AnimSubst | .7680 | 1104/1096 | `fwdE-19` (=51, =83) and `fwdE:19 × shape-5-20/7-58/10-51` | 1 | one CMPDIR at +145; §4.3. A second, disjoint nd=1 at `fwdE:19 × shape-6-39` (residue at +431 only). `fwdE:19 × shapefull` is **exhausted (505 states, 0 failed)** with no nd=0 |
| 0x1006c200 | `_Insert` AnimSubst | .7828 | 678/682 | `shape-5-25` | 4 | the shared `_Insert` window; §4.2 |
| 0x1006e720 | `_Insert` HideAnim | .8475 | 686/689 | `pad-12-11` | 4 | same window (pad is not landable) |
| 0x1004f9b0 | `_Insert` TextureInfo | .8051 | 681/679 | `fwdL-35` (=36, =68); `fwdL:35 × shape-*` | 4 | same window; **469 stacked states measured, nd=4 with the identical 4 offsets in every one** |
| 0x1006a7a0 | `_Insert` AnimStruct | .7983 | 686/690 | `fwdE-37` | 5 | same window + one byte at +178 |
| 0x10069b10 | BuildROIMap | .8842 | 622/617 | `fwdE:19 × shape-6-60` | 3 | offsets 304, 534, 540 |
| 0x1001d890 | erase CoreSet | .9027 | 1106/1106 | `fwdE-31` (=`fwdP-31`) | 35 | all residue in the two inlined rotations (ebx↔edi) |
| 0x1004ebd0 | LegoTexturePresenter::Read | .8446 | 745/739 | `fwdE-2..5` | 47 | |
| 0x1006dec0 | erase HideAnim | .8205 | 1113/1104 | `fwdE-70` | 55 | |
| 0x10069e90 | erase AnimStruct | .7745 | 1104/1096 | `fwdE-75` | 348 | |
| 0x100a7960 | erase ViewLODList | .8780 | 1101/1100 | `fwdL-4` | 260 | |
| 0x1006b140 | CopyTransform | .8149 | 941/948 | — | — | length 941 in **1138** states: TEXT channel |
| 0x1003cf20 | ~LegoCacheSoundManager | .8950 | 274/258 | — | — | length never reached; 4 text variants measured (§4.4) |
| 0x1003d170 | FindSoundByKey | .9552 | 282/281 | — | — | length never reached in the corpus |
| 0x100998e0 | GetCached | .8571 | 995/987 | — | — | one extra 4-byte frame slot (§4.5): TEXT |
| 0x10061010 | FUN_10061010 | .5481 | 726/731 | — | — | length never reached; TEXT (corpus min-nd 546) |
| 0x10062e20 | FUN_10062e20 | .8856 | 1098/1098 | `shape-2-2` (corpus) | 30 | size-clean, carrier axis live |

Rows in my queue whose **link winner is outside my TU list** (the row is
annotated in a header I own, but the emitting TU belongs to another lane):

| addr | row | winner object | best nd |
|---|---|---|---|
| 0x10029d50 | erase CacheSound | `legosoundmanager.cpp` | 316 |
| 0x1002a1b0 | `_Erase` CacheSound | `legosoundmanager.cpp` | 9 (pure ebx↔edi swap, §1.3) |
| 0x10059dc0 | erase TextureInfo | `legomain.cpp` | 20 |
| 0x100af7e0 | erase MxAtom | `mxmain.cpp` | 2 (offsets 145, 434) |

`0x100af7e0` at **nd=2** and `0x1002a1b0` at **nd=9 with a residue that is a
single register-pair exchange** are the two best unclaimed rows in the whole
family. Whoever owns `mxmain.cpp` / `legosoundmanager.cpp` should run
`sw.py <stem> --pre <best carrier> --axes shapefull` on them; the recipe is
in §6 and the bench is in `scratchpad/stl/`.

## 9. Ranked next steps

> **Superseded in part by §10.** Step 2 below ("more stacked cells on the
> nd≤5 rows") is now measured as low-yield for any row whose floor residue is
> `regrole`; see §10.2 and §10.7. The revised order is in §10.8.

1. **Re-run the whole project's sweep queue against `oracles-v2.json` with
   the stacked-carrier axis.** Two rows landed this session from states that
   the old bench could not even *report*, and one of them needed a carrier
   the composer could not render. Both defects were in the bench, not in the
   search. Every "carrier-closed" verdict older than this wave should be
   treated as untested.
2. **`sw.py <stem> --pre <best landable carrier> --axes shapefull`** for
   every row now sitting at nd ≤ 5. That is exactly the move that closed
   0x100a7130 (nd=1 → nd=0). Queue in priority order:
   `0x100af7e0` (nd=2, mxmain), `0x10068b20` (nd=1, legoanimpresenter),
   `0x1004f9b0` (nd=4, legotexturepresenter), `0x1006c200` / `0x1006e720` /
   `0x1006a7a0` (nd=4–5, legoanimpresenter), `0x1002a1b0` (nd=9,
   legosoundmanager), `0x10069b10` (nd=2 at `fwdE:19 × shape-4-22`).
3. **Sweep the six never-tried (prefix × placement) combinations** and the
   force-included forward run (§5), plus `externL`/`externG` (extern runs
   are currently swept only to 8×17 out of a landable range of 96×96).
4. **The C2 inliner / register-allocator model (fresh-eyes-2 §C4) is now the
   critical path, not a nice-to-have.** Two specific ties are the whole
   remaining `_Tree` family:
   * the `_Insert` window (`mov eax,[edi]; lea ebx,[eax+8]; cmp [ebx],ecx;
     jne` vs our `eax`↔`ebx` + inverted polarity) — shared by four rows in
     three TUs, retail form observed **0 times** in the corpus;
   * `erase` +145 (`if (_Y != _Z)` operand direction) — anti-correlated with
     the correct block layout across 1138 states.
   Both are `<XTREE>` vendor code, so there is no text lever; a computed
   condition from the C2 model is the only remaining directed approach.
5. **Text-channel rows** (no carrier state reaches retail's length, so do not
   spend states on them): `CopyTransform` (941 vs 948, 1138 states),
   `~LegoCacheSoundManager` (274 vs 258 — and the obvious named-iterator fix
   is bit-inert, §4.4), `GetCached` (995 vs 987 — one extra 4-byte frame
   slot, §4.5), `FindSoundByKey` (282 vs 281), `FUN_10061010` (726 vs 731).

## 10. The register-allocator model (wave 2)

Measured post-`16620ba9`. Tooling: `permcensus.py`, `erasegroups2.py`,
`colourreach.py`, `colourlaw.py`, `residuesets.py`, `defcensus.py`,
`period.py`, `staleness.py` in `scratchpad/stl/`.

### 10.0 Staleness check — my corpus survived the `vec.h` discharge

The coordinator warned that seed bodies moved at `3526a9ab`. **Measured: they
did not, for any TU in this lane.** Recompiled cells on the post-discharge
shadow and compared *every* `.text` COMDAT against the pre-discharge object:

| TU | cells compared | byte-identical | bodies moved |
|---|---|---|---|
| legoanimpresenter.cpp | 25 | 25 | 0 |
| viewlodlist.cpp | 12 | 12 | 0 |
| legoworld.cpp | 12 | 12 | 0 |
| legotexturepresenter.cpp | 12 | 12 | 0 |

So the 1,138-state legoanimpresenter corpus and the viewlodlist/legoworld
corpora are reusable, not stale. (`vec.h`'s `_DET3/_DET4` only reach TUs that
instantiate the determinant inlines; none of mine do.)

### 10.1 The controlled experiment: one body, twelve instantiations

`_Tree<...>::_Erase` compiles to an identical 57-byte, 23-instruction body for
twelve different instantiations. It is the perfect specimen: same IL, twelve
independent compilations, in nine different TUs.

**Retail colours that one body three different ways.** Grouping the twelve
retail bodies by their register sequence:

| colouring | instances | TUs |
|---|---|---|
| C0 | 6 | legoworld, legoextraactor, legopathctrledgeset, legomain, legocharactermanager, viewlodlist |
| C1 | 5 | legobewithmidpoint, legoanimpresenter (×3), mxmain |
| C2 | **1** | legopathboundary — **the only open row of the twelve** (0x10057180) |

Our build reproduces retail's colouring in **11 of 12**, and the one miss is
the singleton C2. Two facts follow immediately:

1. **The colouring is not a property of the instantiation.** C2's
   `set<LegoAnimPresenter*>` is the same set-of-pointers IL as C0's
   `set<MxCore*>` and C1's `set<MxAtom*>`. Node layout, key type and
   comparator do not separate the groups — C0 and C1 each contain both sets
   and maps.
2. **The colouring is a property of the emitting TU**, and three
   instantiations inside `legoanimpresenter.cpp` all land in C1, as that
   predicts.

Cross-check: both objects that define `_Erase<LegoCacheSoundEntry>`
(legosoundmanager.cpp and legocachesoundmanager.cpp) emit the *same* wrong
colouring `(ebx edi)`, so the link winner is not the lever either.

### 10.2 The reachability law (and its counterexample)

If the colouring is TU state, does the declaration carrier move it? I scored
**every oracled open row against every retained corpus state for its TU**,
keeping only states whose instruction *shape* equals retail's — so the only
possible difference is which register holds what (`colourlaw.py`).

| row | shape-equal states | distinct colourings | retail's colouring reached |
|---|---|---|---|
| 0x10006460 StopAction (closed) | 751 | 2 | **57** |
| 0x10020e50 `_Lrotate` (closed) | 29 | 1 | **29** |
| 0x100574a0 RemoveActor | 171 | 9 | **1** |
| 0x1002a1b0 `_Erase` CacheSound | 783 | 2 | 0 |
| 0x10057180 `_Erase` AnimPresenter | 375 | 2 | 0 |
| 0x100495b0 `insert` BEWithMidpoint | 353 | 6 | 0 |
| 0x10085500 `insert` LegoCharacter | 334 | 4 | 0 |
| 0x100a7960 `erase` ViewLODList | 96 | 5 | 0 |
| 0x1006dec0 `erase` HideAnim | 92 | 6 | 0 |
| 0x10068b20 `erase` AnimSubst | 44 | 6 | 0 |
| 0x1001d890 `erase` CoreSet | 16 | 2 | 0 |
| 0x100af7e0 `erase` MxAtom | 15 | **1** | 0 |
| 0x10069e90 `erase` AnimStruct | 7 | 1 | 0 |
| 0x10029d50 `erase` CacheSound | 5 | 2 | 0 |
| 0x10082ca0 `erase` LegoCharacter | 1 | 1 | 0 |
| 0x10045c20 PlaceActor | 17 | 1 | 0 |

> **SCOPE CORRECTION (see §10.5, §10.5a).** Every corpus in the table below
> is a *flat* axis or an older product. It does **not** cover the stacked
> `--pre X × shapefull` space, and on that space a `_Tree` regrole tie does
> move (`erase<MxAtom*>` +434 at `fwdE:88 × shape-8-45`). Read the table as
> **"the flat axis is near-inert on colouring"**, not as "colouring is
> unreachable"; a `distinct colourings = 1` entry means the flat axis is
> inert on that row, nothing more.

**The strong law is false and I am recording the counterexample:**
`LegoPathController::RemoveActor` reaches retail's colouring in 1 of 171
shape-equal states, so the carrier axis *can* move colouring. But the rate is
~0.6%, and for the `_Tree` family it is **0 in 1,891 shape-equal states across
12 rows and 9 TUs**. Several rows show `distinct colourings = 1`: the axis is
completely inert on their allocation.

**Operational consequence.** Sweeping a `_Tree` regrole row for colouring is
predicted waste. I acted on this immediately: I cancelled the planned
`legosoundmanager` sweep for 0x1002a1b0 (783 shape-equal states already prove
the axis reaches only 2 colourings, neither retail's) and moved the compute to
a row whose residue is not purely regrole.

### 10.3 The erase family reduces to two tie bytes, project-wide

`residuesets.py` over 133 length-correct states of `erase<MxAtom*>`
(0x100af7e0, `mxmain.cpp`, 3,391 states swept this wave):

```
nd=  2 x  47   [145, 434]      <-- the floor
nd= 37 x  15   [145, 434, 811, 814, 817, 819, 822, 832, 835, 838]
nd= 56+       [13, 14, 15, ...]  the block-swapped family
byte 145: correct in 19/133 length-correct states
byte 434: correct in  8/133
```

Those are the **same two bytes** this ledger identified for
`erase<LegoAnimSubst>` (+145 `if (_Y != _Z)` operand direction, +431/434
`cmp edx,edi` register-role tie), and the same +434 the wave-3 ledger recorded
for `erase<LegoPathActor*>`. **Three TUs, three instantiations, one pair of
tie bytes.** Each is individually reachable; in the flat grammar they are
never jointly correct, because every state that fixes 434 is inside the
structurally-wrong block-swapped region.

### 10.4 A forward prediction, stated before the result

Running now: `sw.py all2-mxmain --pre fwdE:88 --axes shapefull` (550 stacked
cells; `fwdE:88` is the suffix carrier that gives the nd=2 floor).

**Prediction.** The stacked product will reach **nd=1 with the residue at
offset 434 only, and will not reach nd=0.**
Reasoning: +145 is a `cmpdir` tie and the stacked product converted exactly
that byte for `erase<LegoAnimSubst>` (`fwdE:19 × shape-6-39` → residue at
+431 only); +434 is a `regrole` tie, and `colourlaw` measures the colouring
of this row as carrier-inert (15 shape-equal states, **1** distinct
colouring). A `cmpdir` is reachable; a `regrole` on this row is not.

### 10.5 Result of the prediction — the operative half was WRONG, and that is the finding

> **This section replaces an earlier version of itself that reported the
> opposite result. The earlier version was wrong because I sampled a running
> sweep and reported the sample as the outcome; the sweep then completed and
> contradicted it. Both the error and the correction are kept here.**

`sw.py all2-mxmain --pre fwdE:88 --axes shapefull`, **505 cells, 0 failed**
(the run completed; my kill landed after it had already exited).

| claim | outcome |
|---|---|
| will reach nd=1 | **held**, at `fwdE:88 × shape-8-45` |
| residue will be at **+434** (regrole), +145 fixed | **exactly backwards** |
| will **not** reach nd=0 | held |

The nd=1 cell has residue **`[145]` only** — the **`regrole` tie at +434 is
CORRECT** and the `cmpdir` at +145 is what remains.

```
# 0x100af7e0 retail=1107   21 length-correct states in the product
  nd=  0 x   0
  nd=  1 x   1   []=[145]     sw-all2-mxmain_pE88sf/shape-8-45
  nd= 13 x   9   [20, 30, 89, 102, 112, 213, 271, 476, ...]
```

**This refutes §10.2's conclusion, and the merge commit's title.** I claimed
the carrier axis does not move `regrole` ties on `_Tree` bodies. The stacked
product moves one. `colourlaw.py` had measured 15 shape-equal states and 1
colouring for this row, but it scanned the corpora that existed *at the
time* — flat axes and older products; `sw-all2-mxmain_pE88sf` did not exist
yet. **The stacked axis reaches colourings the flat axis does not.**

Two process errors of mine, recorded because they nearly cost the row and
did propagate into a merge:

1. **I sampled a running sweep and treated the sample as the result.** At 276
   of 505 cells the best was nd=13 and I wrote that down as the outcome.
   `shapefull` enumerates `(c, f)` with `c` ascending, so the high-`c` cells
   — including the winner `shape-8-45` — are all at the end. **A partial
   `shapefull` sweep is not a uniform sample of it.**
2. **I reported a floor that was never the floor**, and the coordinator
   merged it as a lane conclusion.

Corrected model: `regrole` is not immovable, it is *much harder to move than
`cmpdir`* — 0 hits in 1,891 flat shape-equal states versus 1 hit in 21
length-correct stacked cells — and the stacked axis is where it moves. Triage
rule in weakened form: score `cmpdir`-floored rows first, but do **not**
write off a `regrole`-floored row until it has seen a stacked pass.

**Consequence: 0x100af7e0 is at nd=1, one `cmpdir` byte from landing.**

### 10.5a A second refutation: colour moves in an AUTHORED function too

`LegoPathBoundary::RemoveActor` (0x100574a0) is authored source, not a
template instantiation. Over 1,350 retained legopathboundary states
(`colourreach.py`), 171 have retail's exact instruction shape, and across
them the function takes **9 distinct register colourings** — one of which is
**exactly retail's**, at `pad-10-12`. The function's text is identical in
every one of those cells; only the surrounding declarations differ.

So a `regrole` residue in an authored function is **not** evidence that our
text is wrong. Same text, nine colourings, retail's among them.

And that cell is not merely a colour match — it is a **complete donor**:

```
# 0x100574a0 retail=258   219 length-correct states
  nd=  0 x   1   []        sweep2-all2-legopathboundary/pad-10-12   <-- masked-EXACT
  nd=  1 x  13   [104]     fwdE-15
  nd=  1 x  11   [129]     pad-10-10
  nd=  1 x  10   [240]     fwdE-16
```

`pad_shape` became a renderable recipe kind only at `16620ba9`, which is why
this sat unclaimed in a corpus from an earlier wave. **legopathboundary.cpp
is not my TU — handed to its owner, not landed here.**

**Re-derivation on today's shadow: the donor is STALE.** I swept the full
144-cell `padgrid` on the current shadow (`sw-all2-legopathboundary_v3`):
`pad-10-12` no longer produces the retail body, and the floor is now
**nd=2 at `pad-12-11`, residue `[129, 240]`**. legopathboundary.cpp has had
landings since that corpus was built, and "landings re-dial their TU" applies.
So the handoff is *not* a ready donor — it is: the row is one carrier axis
away, the axis is now renderable, and the padgrid floor on today's shadow is
nd=2 with two named bytes. (The `HIT nd=0 0x10057260` in that same log is
`~LegoPathBoundary`, which is **already at matching 1.0** — the sweep oracle
includes closed rows, and I checked before reporting it as a find.)

### 10.5b The template/authored split — TESTED AND FALSIFIED

The proposed split: for a *template instantiation* colour is TU state (proved
in §10.1), but for an *authored function* the IL is not shared, so if our text
were retail's, C2 would rank the same candidates the same way — therefore a
`regrole` residue in an authored function is evidence that **our text is
wrong**.

**The split does not hold.** A carrier adds declarations around a function; it
does not change that function's source. So if an authored function's colour
moves under carrier states, its text is being held fixed while the colour
changes, and colour cannot be evidence about the text.

`colourlaw.py` over every oracled row, restricted to states whose instruction
shape equals retail's (so only the colouring can differ):

| row | kind | shape-equal states | distinct colourings | retail's reached |
|---|---|---|---|---|
| `LegoPathBoundary::RemoveActor` 0x100574a0 | **authored** | 209 | **14** | **1** |
| `MxControlPresenter::CheckButtonDown` 0x10044270 | **authored** | 3 | 3 | **1** |
| `Act3List::RemoveByObjectIdOrFirst` 0x100720d0 | **authored** | 568 | 10 | 0 |
| `LegoPathController::PlaceActor` 0x10045c20 | authored | 17 | 1 | 0 |
| every open `_Tree` row (12 of them) | template | 1–783 | 1–8 | **0** |

Two open authored functions reach **retail's exact colouring** under a pure
compile-state change, with their text untouched. `RemoveActor` takes
**fourteen** distinct colourings across 209 states. That is a direct
counterexample to "authored + regrole ⇒ text is wrong".

**What the data does show**, which is a weaker and more useful statement:
authored functions are *more* carrier-mobile in colour than template bodies
(14, 10, 3 distinct colourings versus 1–8, and 2 of 4 open authored rows
reach retail versus 0 of 12 template rows). That is the opposite of the
proposed split's direction, and it has a plausible mechanism: an authored
function has more live values and therefore more ties for the surrounding
declaration state to break, whereas a small template body like the 23-
instruction `_Erase` has almost no slack.

**So the reclassification the split was meant to produce cannot be made on
colour evidence.** `docs/open-set-triage.md` classifies the open set by
*residue class* instead, which is measurable and does not require knowing
whether the text is right.

Caveat recorded: `RemoveActor`'s retail-colour cell is in a pre-`3526a9ab`
corpus, and on today's shadow my 144-cell padgrid re-run does not reach it
(38 shape-equal cells — a much smaller sample, not a contradiction). The
mechanism claim does not depend on which shadow: the text was identical
across all 209 cells either way.

### 10.6 Two structural facts about the carrier axis itself

**(a) The fwd axis is partially periodic with period 32, and heavily
redundant on some rows.** Distinct body count over a 96-cell forward-run axis
(`period.py`):

| row / axis | distinct bodies out of 96 | strongest period |
|---|---|---|
| 0x1006e720 `_Insert` HideAnim / fwdE | **3** | p=32 (94% agreement) |
| 0x1006c200 `_Insert` AnimSubst / fwdE | **4** | p=32 (91%) |
| 0x1006a7a0 `_Insert` AnimStruct / fwdE | 6 | p=32 (86%) |
| 0x10068b20 erase AnimSubst / fwdE | 32 | p=32 (73%) |
| 0x100af7e0 erase MxAtom / fwdL | 61 | p=32 (53%) |
| 0x100a7960 erase ViewLODList / fwdL | 73 | p=32 (27%) |

p=32 is the strongest period for essentially every row and axis measured,
which points at a 32-entry table in the front end rather than a
count-proportional effect. The redundancy is row-specific: a 96-cell fwdE
sweep buys 3 distinct states for one row and 73 for another, so a flat
per-axis budget is the wrong shape. **Dedupe by body sha before scoring** and
the same information costs a fraction of the compiles.

**(b) `fwdL` and `fwdP` are the same state for most bodies.** Over all 96 k
on `legoanimpresenter.cpp`, comparing every `.text` COMDAT
(`fwdlp2.py`): only **19** bodies ever differ between "declarations at the
top of the file" and "declarations after the last `#include`" — 18 of them
header-defined inlines (`Vector2`/`Vector3`/`Matrix4`/`LegoROIList`) plus
`ParseExtra`. **None of the six `_Tree` rows, BuildROIMap or CopyTransform
ever differ**: for those, `fwdL-k` and `fwdP-k` are byte-identical for all
96 k. The equivalence is not universal — on `viewlodlist.cpp` the `_Tree`
erase and the destructor *do* differ — but where it holds it halves the fwd
search space, and it means a `fwdP` hit on those rows was always landable as
`placement: prefix`.

### 10.7 Wave-2 sweep results (new TUs and new axes)

New axes added to `sw.py` this wave: `fr:<prefix>:<width>:<placement>` (the
never-used free parameters of `forward_declaration_run` — everyone had only
ever used `MxUnkRecVA/VB/VC` at width 3), `f<A|B|C><P|S|I>` (all nine
prefix × placement combinations, including force-include of a forward run),
`externL`/`externG` (extern runs beyond the historical 8×17 box).

| row | TU | states swept | floor | residue class |
|---|---|---|---|---|
| 0x100af7e0 erase MxAtom | mxmain.cpp | **3,391** | nd=2 | `[145, 434]` — cmpdir + regrole |
| 0x10029d50 erase CacheSound | legosoundmanager.cpp | 1,620 (corpus) | nd=316 | structural |
| 0x1002a1b0 `_Erase` CacheSound | legosoundmanager.cpp | 1,620 (corpus) | nd=9 | **pure regrole — carrier-inert, 783 shape-equal states, 2 colourings, 0 retail** |

I cancelled the planned fresh `legosoundmanager` sweep on the strength of
that last line: 783 shape-equal states already prove the axis reaches only
two colourings for `_Erase`, neither of them retail's, so more cells on that
row are predicted waste. That is the model being used to *not* spend compute,
which is most of its value.

**No new landings this wave.** The two nd≤2 rows I was sent at
(0x100af7e0 nd=2, 0x10068b20 nd=1) are both blocked on a regrole tie, and
regrole is the class the carrier axis does not move.

### 10.8 Revised ranked next steps

1. **Triage every open row by residue class before spending a single compile.**
   `permcensus.py` + `residuesets.py` give the floor residue and its class in
   seconds from objects that already exist. Rows whose floor is `regrole` are
   carrier-dead (0 hits in 1,891 shape-equal states); rows whose floor is
   `cmpdir` or structural are carrier-live. The project's largest defect class
   (484 `regrole` sites) is therefore *not* addressable by the campaign's main
   instrument, and every hour spent sweeping such a row is an hour lost.
2. **Re-floor every stacked product** (§10.5). A product does not inherit its
   pre-carrier's floor; several of mine landed 11 bytes worse than the flat
   state they were built on.
3. **Dedupe carrier cells by body sha** (§10.6a). A 96-cell fwdE axis yields
   as few as 3 distinct bodies. Period 32 is the dominant structure across
   every row measured — worth one afternoon of RE against C1's name table,
   because it would let the whole campaign sample a 32-cell space instead of
   a 96- or 400-cell one.
4. **For the regrole class, the lever must change the function's own IL.**
   The evidence says the colouring is fixed by the emitting TU's state at the
   point the function is compiled, is identical across both definers of a
   symbol, and is untouched by ~2,000 declaration states. What remains
   upstream of the allocator is the **inliner**: what got inlined into the
   body determines its register pressure. That makes fresh-eyes-2 §C4's C2
   pool-dump instrument the critical path for 484 sites, not a nice-to-have.
5. **The one concrete open lead in this lane** is 0x10069b10 BuildROIMap: its
   floor residue splits into two *independent* groups — `{471, 481}` (a
   `_Nil` cmpdir pair) and `{304, 534, 540}` — each individually reachable
   (664/1,946 length-correct states fix the first; the nd=2 cells fix the
   second), never yet jointly. Both are carrier-live classes, so unlike the
   erase family this row is not predicted dead. Sweep pre-carriers other than
   `fwdE:19`, and re-floor each product per step 2.

## 11. Wave 4 — the carrier grammar is one integer, and it closed the row

### 11.1 LANDED: 0x100af7e0 `_Tree<MxAtom*>::erase` (.7273 → exact)

**Gated:** `ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE: LEGO1 4839/4933,
ISLE 172/172, CONFIG 111/111`; GAIN 0x100af7e0, zero LOST. Commit
`7808678e`; re-pinned 4838 → 4839. New translation unit for
`omni:LEGO1/omni/src/main/mxmain.cpp`.

* donor: `forward_run_with_shape` — `MxUnkRecVC` × **24** at suffix +
  `declaration_shape(8, 45)` force-included. Body 1107/1107 masked-exact.
* splice `same_slot_resize` 1103 → 1107.
* S72: donor relocation symbol sequence identical to a fresh pipeline seed
  (16/16).

**It was not found by more cells.** Three 505-cell shape grids over this row
had floored at nd=1. It was found by measuring the grammar first.

> ## ⚠ RETRACTION (wave 9): "the carrier grammar collapses to a count" is FALSE
>
> §11.2 below concluded that a carrier run is COUNT-ONLY and that the whole
> grammar therefore reduces to one integer. **The measurement is sound; the
> generalisation is wrong**, and I propagated it into a merge title.
>
> What I actually measured: on **`mxmain.cpp`**, 65 of 68 bodies are identical
> across every stem, width, declaration kind and seat **at equal count** —
> including different `(m,k)` splits of the same extern total. That still
> holds. What does not hold is that it is a property of the *grammar* rather
> than of that one TU.
>
> **My own corpus already contained the refutation.** Slicing
> `sw-all2-legoanimpresenter`'s extern cells by total and counting distinct
> bodies at a fixed total:
>
> | extern total | `(m,k)` pairs | distinct `erase<AnimSubst>` bodies | distinct `CopyTransform` |
> |---|---|---|---|
> | 7 | 8 | 6 | 5 |
> | 8 | 9 | **7** | 6 |
> | 9 | 9 | 6 | 5 |
> | 15 | 9 | 6 | 7 |
>
> Seven distinct bodies at a fixed count is not a count-only axis. Lane NM
> reached the same conclusion independently on the `m+k=33` diagonal
> (`HitActor` nine bodies, `AddPresenterIfInRange` eight with its retail-exact
> body at one of 34 states).
>
> **Corrected statement.** Inert: declaration kind, stem identity, identifier
> width, and the file-start/EOF seats (which collapse into each other). Live:
> the **after-includes seat**, so the `(m,k)` split of an extern pair is a real
> 2-D lattice. The search space is that lattice × the 2-D shape, and the right
> move is to sweep **rectangles, not lines**. §12's long-line strip and its
> yield curve remain valid as measurements of *one line* through that lattice;
> they simply are not a search of the space.
>
> The `mxmain` landing in §11.1 is unaffected — it was found in that TU, where
> the insensitivity does hold.

### 11.2 The carrier grammar collapses to a count

Two measurements, both on `mxmain.cpp`:

**(a) A forward/extern run is COUNT-ONLY.** For each count k, I compared every
carrier variant that declares k things — `fAS`/`fBS`/`fCS` (three different
stems at width 3), `fr:Q:1`/`fr:Q:2` (a one-character stem at widths 1 and 2),
`fr:MxUnkRecordLongStemAAAA:3` (a 24-character stem), and
`extern-0-k`/`extern-k-0`/`extern-a-b` with a+b=k (extern *object*
declarations rather than class declarations, at two different seats) — over
**every** `.text` COMDAT in the object:

```
bodies in the object: 68
  COUNT-ONLY (identical across every variant at every count): 65
  identity-sensitive:                                          3
     80/96 counts disagree  MxOmni::HandleEndAction
     24/96 counts disagree  MxOmni::CreatePresenter
     21/96 counts disagree  MxOmni::Create
```

So for 65 of 68 bodies — including `erase<MxAtom*>` — the stem text, the
identifier width, the declaration *kind* and the seat are all **inert**.
Only the count matters. That is a direct answer to "the free `prefix`/`width`
parameters were never swept": they were never swept because they do nothing,
and now that is measured rather than assumed.

**(b) `declaration_shape(c,f)` does NOT collapse.** Over the 505 shape cells
of one product, grouping by candidate scalars:

| scalar | groups | pure |
|---|---|---|
| c+f | 109 | 12% |
| f | 100 | 11% |
| c | 10 | 0% |
| c\*f | 348 | 69% (only because it is nearly injective) |

No scalar explains it; the shape carrier is genuinely 2-D. That asymmetry is
the whole method: **a stacked carrier is (2-D shape) × (1-D count)**.

### 11.3 The method that follows

Pin the shape at a cell that reached a good region, then sweep the run count.
Because the run half is one integer, sweeping it 1..300 is a **complete
search of that line**, not a sample — the first time in this campaign that a
sweep has been exhaustive over a dimension rather than a sample of it.

For 0x100af7e0: pin `shape(8,45)` (the cell that had fixed the `regrole` tie
at +434 and left only the `cmpdir` at +145), sweep the count. **nd=0 at
count 24**, in 156 cells.

Implemented as `sw.py --axes stack:<c>:<f>:<P|S>`; landed by `landin.py`,
which now parses the `stack_c_f_S-k` label straight into a
`forward_run_with_shape` recipe and creates the TU unit if one does not exist.

### 11.4 Not every row yields to it — BuildROIMap

`0x10069b10` with `shape(4,22)` pinned: **122 of 124** length-correct cells
give the identical nd=2 residue `[471, 481]`, and those two bytes are correct
in **0** of them. With that shape the count axis is inert. The shapes that do
fix `[471, 481]` are the ones that break the other group (`[304, 534, 540]`),
which is where the remaining sweeps are pointed. Recorded so nobody re-runs
the (4,22) line.

## 12. Wave 5 — the long-count line

### 12.1 The ceiling is 999, and the project has swept the first ~10%

`entropy.generate_forward_run` and `generate_extern_run` both accept
`1 <= count <= 999` (bounded by `count <= 10**width`, so width 3 reaches 999).
`generate_shape` is capped at `classes <= 10`, `functions <= 10*classes`, so
the shape grid really is 505 cells and I have swept it exhaustively — but the
count line is **999 long and the campaign has only ever compiled k <= 96**.
That is the first 9.6% of the line, not the first sixth.

### 12.2 The count-only law holds at long counts (re-verified)

The strip design rests on one axis standing in for all of them. Re-checked at
long counts on `viewlodlist.cpp`, k = 200..204, comparing `fAS` (stem
`MxUnkRecVA`), `fCS` (`MxUnkRecVC`), `fr:Q:3` (a one-character stem) and
`fr:MxUnkRecordLongStemAAAA:3` (a 24-character stem) over every `.text`
COMDAT:

```
counts with >=2 carrier variants: 5
bodies in the object: 20
  COUNT-ONLY: 20      identity-sensitive: 0
```

So identifier length does not start to matter as the run grows, and a single
`fCS` sweep covers the whole long line. (Recorded because the obvious worry —
longer runs mean longer identifiers mean more name-table pressure — is
measurably false.)

### 12.3 BuildROIMap: the count line is INERT, on two different shapes

`0x10069b10`'s two residue groups are `[471, 481]` (a `_Nil` cmpdir pair) and
`[304, 534, 540]`. The plan was to pin a shape that fixes one and sweep the
count for the other. Measured:

| pinned shape | length-correct cells | distinct residue sets | verdict |
|---|---|---|---|
| `shape(4,22)` (fixes `[304,534,540]`) | 124 | **1** — always `[471,481]` | count inert |
| `shape(6,60)` (fixes `[471,481]`) | 90 | **1** — always `[304,534,540]` | count inert |

214 length-correct cells across two shapes and **not one byte of variation**.
For this row the shape alone decides which group is correct and the count
does nothing, so the (shape × count) product cannot decouple the two groups.
Since the shape grid is exhaustively swept (505 cells) and the count adds
nothing, **the stacked carrier space is closed for BuildROIMap**. It needs a
different channel — the row's own text, or the inliner.

This is worth contrasting with `erase<MxAtom*>`, where the count line was the
whole answer (nd=0 at count 24). The count is not a universal lever; it is a
lever for some rows and a no-op for others, and which one you are in is
cheap to determine — pin a shape, sweep ~100 counts, count the distinct
residue sets. If it is 1, stop.

### 12.4 The yield curve — the answer is per-row, not global

`yieldcurve.py` answers "where does the long line stop paying" from a
*partially completed* sweep, which is the only kind I had. The information a
count line carries is not its cell count but how many **distinct bodies** it
produces; walking k in order and recording when a new body last appeared gives
the axis's real ceiling per row.

`legoanimpresenter.cpp`, `fCS` k = 97..160 (64 cells past the old ceiling):

| row | distinct bodies | last new at k | best nd (k) |
|---|---|---|---|
| 0x10068b20 erase AnimSubst | **36** | 160 | 1 (k=115) |
| 0x10069e90 erase AnimStruct | **31** | 156 | 348 |
| 0x1006dec0 erase HideAnim | 21 | 146 | 55 |
| 0x1006bac0 ParseExtra (closed) | 20 | 149 | 5 |
| 0x1006b140 CopyTransform | 15 | 156 | — (length never reached) |
| 0x1006a7a0 `_Insert` AnimStruct | 6 | **117** | 5 |
| 0x10069b10 BuildROIMap | 4 | **117** | 11 |
| 0x1006c200 `_Insert` AnimSubst | 4 | **103** | — |
| 0x1006e720 `_Insert` HideAnim | 3 | **102** | 47 |
| 0x1006dc10 AssignIndicies (closed) | 3 | 144 | 0 |

**The yield does not flatten globally — it flattens per row, and by residue
class.** The three `_Insert` rows saturate within 6 cells of the old ceiling
(3–6 distinct bodies, nothing new after k≈102–117), which is exactly the
family whose residue window is unreachable in 37,089 states (§4.2). The
`erase` rows are still producing new bodies at k=160 (31–36 distinct in 64
cells) — but their best nd does not improve, so new states are not
*better* states.

Operationally: **run ~20 cells past the ceiling and count distinct bodies. If
it is single digits, the line is done for that row.** That costs 20 compiles
instead of 900 and it is the measurement I would want handed to me.

### 12.5 Where I stopped, and why

Item 1's strip (`fCS`, k = 97..999, eight TUs) was launched after the
BuildROIMap lines were shown inert, and was still running when this wave
closed; per-TU results are in `scratchpad/stl/sw5-long-*.log`. I reordered
deliberately: BuildROIMap first (a concrete lead), then, once 214 cells had
shown its count line flat, I killed those sweeps and moved the compute to the
untested strip rather than finish a measured-dead line.

**Cost note for whoever continues.** A full long line is ~900 compiles per TU
and the machine is shared; eight TUs is ~7,200. I did not run that, and
§12.4 is why I did not need to: the yield curve answers the question from the
first ~20 cells past the ceiling. The remaining seven TUs' long lines are
still worth running, but they should be run *with* the yield curve, stopping
each row as soon as its distinct-body count stalls.

## 13. Wave 6 — the text channel, and a length defect that is not one

Tooling: `beta.py` (BETA10/ALPHA read-off — disassembly and an `[ebp-XX]`
frame-slot census; at /Od every named local has its own slot, so the frame
*is* the declaration set).

### 13.1 `0x1006b140 LegoAnimPresenter::CopyTransform` — NOT a text defect

The wave-6 brief lists this as "+7 bytes; never reaches 948 in 1,138 states,
so it is a real length defect". **Measured: it is a stack-slot colouring
tie, and the +7 is the encoding cost.**

**Step 1 — BETA10 confirms our declaration set is already right.**
`beta.py BETA10 frame 0x100507e0` gives the June frame: four 0x48-byte matrix
objects (slots −0x13c, −0xf4, −0xac, −0x64, exactly 0x48 apart) plus four
scalar slots (−0x60, −0x5c, −0x58, −0x54). Our source declares four matrices
— `inverse`, `originalTransform`, `newTransform`, and the `#ifdef BETA10
unused_matrix` — and four scalars (`mn`, `local2world`, `roiTransforms`,
`i`). The set matches. There is nothing to transcribe.

**Step 2 — the divergence is a slot assignment, not a statement.** Aimed diff
at the first difference (offset 96–120):

```
OURS    96 mov [edi], REL          RETAIL  96 mov [edi], REL
       105 mov [ebp-0x14], edi            105 mov [edi], REL
       108 mov [edi], REL                 111 mov [ebp-0x90], edi
       114 jmp +7                         117 jmp +10
       116 mov [ebp-0x14], 0              119 mov [ebp-0x90], 0
```

Both sides emit the same two vtable stores of the inlined
`MxMatrix::MxMatrix() : Matrix4(m_elements)`. The difference is that **`mn`
lives at `[ebp-0x14]` for us and `[ebp-0x90]` for retail** — disp8 versus
disp32, so every reference to it costs retail 3 bytes more
(`89 7d ec` vs `89 bd 70ffffff`; `c7 45 ec ...` vs `c7 85 70ffffff ...`).
Two or three references account for the whole +7.

**Step 3 — the frames are identical.** Both prologues are byte-for-byte
equal through offset 60, including `sub esp, 0x150`. Same frame size, same
layout, one variable placed differently inside it. So this is not "retail has
an extra object"; it is the allocator choosing a different spill slot for the
same value — the stack-slot analogue of the register-role ties in §1.3.

**Step 4 — declaration order is not the lever (measured).** Four variants,
all compiled:

| variant | body |
|---|---|
| base (`mn` declared first) | 941 |
| `mn` after `MxMatrix inverse` | 941 |
| `mn` last of the group | 941 |
| `Matrix4* mn;` early, assigned after the matrices | 941 |
| `MxMatrix*` static type instead of `Matrix4*` | 941 |

Not one byte moves. At /O2 the slot for this value is assigned by the
allocator, not by declaration position, so the text channel has no handle on
it.

**Verdict: reclassify.** `CopyTransform` is a COLOUR row, not a TEXT row. Its
length delta is an encoding consequence of a slot tie, exactly the confusion
`docs/open-set-triage.md` was extended to catch — and it slipped through
because the triage's encoding test compares *instruction multisets*
(ours 297 vs retail 295 here, so it failed the test) rather than asking
whether the length difference is carried by displacement widths. A sharper
test for the next pass: if the two bodies' prologues and frame sizes are
identical, a length delta cannot be a declaration-set defect.

### 13.2 `0x100998e0 LegoTextureContainer::GetCached` — a real text row, 995 → 991

Unlike CopyTransform, this row's **frame size genuinely differs**
(ours `sub esp,0xfc`, retail `sub esp,0xf8`), so retail really does reference
one fewer distinct 4-byte local. That is a declaration-set defect and the
text channel is the right one.

§4.5 had already localised it: retail keeps `p_textureInfo->m_surface` live in
`ESI` while we spill it, which pointed at the `cached` / `surface` pair inside
the match branch. Four variants, all compiled in the donor lane:

| variant | body | Δ to retail (987) |
|---|---|---|
| base | 995 | −8 |
| **g1 — drop `surface`, go through `cached->m_surface`** | **991** | **−4** |
| g2 — drop `cached`, keep `surface` | 992 | −5 |
| g3 — `BOOL und = <expr>` instead of the if/assign | 995 | −8 |
| g4 — drop both, use `(*it).first` throughout | 1000 | −13 |

**g1 removes exactly one slot and gains exactly the predicted 4 bytes.** The
prediction came from the frame census, not from guessing, and the two
neighbouring variants (g2, g4) confirm the direction is specific rather than
"fewer locals is better" — g4 drops two names and is 13 bytes *worse*.

Remaining after g1: 4 bytes. g1's own frame is `sub esp,0x100`, still above
retail's `0xf8`, and the next divergence is an instruction-scheduling one at
the first inlined `memset` (`rep stosd` for 0x1b dwords = `sizeof(DDSURFACEDESC)`
in both, but ours interleaves a `push 0` before it). So there is at least one
more named local to remove, in the second half of the function, and the
scheduling difference is likely downstream of it.

> **CORRECTION (wave 7).** The sentence above — "g1 removes exactly one slot
> and gains exactly the predicted 4 bytes" — is **wrong**, and the frame
> census I wrote in the same wave is what caught it. g1's frame is
> `sub esp,0x100`, i.e. it grew by 4 from base's `0xfc`, *away* from retail's
> `0xf8`. Dropping the `surface` **name** did not drop a **slot**: the value
> still has to live across the Lock/Unlock calls, so it just became an
> unnamed spill. The 4-byte body gain came from encoding, not from the
> declaration set. See §13.2a for the corrected picture.

### 13.2a GetCached, round 2: the slot is not any of the obvious names

Aimed by the frame this time rather than by body length. Every variant
compiled in the donor lane; retail is **987 / `sub esp,0xf8`**:

| variant | body | Δlen | `sub esp` | Δframe |
|---|---|---|---|---|
| base | 995 | +8 | 0xfc | +4 |
| g1 — drop `surface` | 991 | +4 | **0x100** | **+8** |
| g5 — drop `und` (Unlock first, test `newDesc` directly) | 982 | −5 | 0xfc | +4 |
| g7 — drop `height` | 989 | +2 | 0xfc | +4 |
| g8 — drop `width` and `height` | 983 | −4 | 0xfc | +4 |

**Not one variant moves the frame off `0xfc`**, and the three round-1
variants move it the wrong way. So the extra 4 bytes of frame are *not*
`surface`, `und`, `width` or `height`.

The reason is visible once the frame is decomposed: `0xfc` = 252 =
two `DDSURFACEDESC` (2 × 0x6c = 216) + a `RECT` (16) + **five** dword slots,
for seven named scalars (`it`, `cached`, `surface`, `und`, `width`,
`height`, `textureInfo`). The compiler is already overlapping them by
lifetime. **Slot count is decided by lifetime overlap, not by name count**,
which is why removing names moves the body length around freely (982 … 995)
while the frame stays pinned. Retail gets one more overlap than we do.

That is a real limit on the frame census as a *lever*: it is a reliable
**classifier** (a different `sub esp` proves a declaration-set difference)
but the budget it reports is not a shopping list of names to delete. To spend
it you have to change a **lifetime** — shorten the live range of one of those
seven values so it can share a slot — not merely rename or inline it.

**Not landed.** No variant closes the row and none matches retail's frame.
Best body lengths are g7 at 989 (+2) and g1 at 991 (+4), neither exact. The
row stays open with the table above as its map.

Harness rule that still applies whenever one of these is landed: victim
accounting has to run in the **seed** lane (absolute shadow path,
exact-replica command), and a text edit that closes one row while opening
another is not a gain — the gate enforces the exact accepted set.

### 13.3 Scope note: CoreSet `erase` is not a text row

`0x1001d890` is on the wave-6 list, but it is a `_Tree` vendor-template
instantiation: its text is MSVC's `<xtree>`, which the mandates forbid
editing and which is identical for the eleven instantiations we already match
byte-for-byte. `docs/beta10-foundry-ledger.md` classifies exactly this shape
as **OUT-OF-SCOPE** for the transcription channel, and §10.1 here shows its
colouring is a property of the emitting TU. There is no first-party text to
read off. It belongs in the colour channel with the rest of the family.

## 14. Wave 8 — FUN_10061010, the worst row

Baseline re-derived rather than compared: my merge base `251a6d56` builds
**4845/4933**. The 4934 denominator (the `LegoROI::Intersect` annotation fix)
is not in it, so nothing here is comparable to a 4934-based score.

**Correction to the wave-8 brief:** `0x100af7e0` is **already at 1.0** — this
lane landed it in wave 4 (`7808678e`). It is not an extern-grid target.

### 14.1 A real source defect, found by the aimed diff: `animRunning`

The first structural divergence is at offset 27 and it is a **type** defect,
not a layout one:

```
OURS   c745e800000000  mov dword ptr [ebp-0x18], 0    <- 4-byte store
RETAIL c645e700        mov byte  ptr [ebp-0x19], 0    <- 1-byte store
```

Our source declares `MxS32 animRunning = FALSE;`. Retail stores a **byte**,
and the member it is assigned to is `MxBool m_animRunning; // 0x39`
(`MxBool` = `MxU8`). So the local's type is wrong.

`MxBool animRunning = FALSE;` (line-neutral) produces
`mov byte ptr [ebp-0x15], 0` — retail's instruction form — and removes a
**3-byte skew** that had been misaligning everything downstream: with the
edit, offsets 32 / 44 / 52 / 58 coincide on both sides, where before they ran
35 / 47 / 55 / 61 against retail's 32 / 44 / 52 / 58.

**LANDED in the checked source, zero-loss** (4845 → 4845, no LOST, no GAIN;
`tools/repin_overlay.py` re-pinned). It does not close the row on its own —
body 726 → 717 against retail's 731 — but it is a correct source form backed
by two independent facts (the member's type, and retail's store width), and
the campaign's own history says text corrections compound rather than pay off
individually. Note the body got *shorter* while getting structurally closer:
**length is not the metric**, the same lesson as GetCached in §13.2a.

### 14.2 The `MxListEntry` half: hypothesis tested and REFUTED

Our object emits an out-of-line COMDAT
`??0?$MxListEntry@PAULegoTranInfo@@@@QAE@PAULegoTranInfo@@PAV0@1@Z` — the
**3-argument** ctor — and calls it. The retail report has no row for it. The
source carries a standing TODO on exactly this ("the embedded `MxListEntry`
constructor is not inlined; this may be the key"). Retail inlining it would
explain both the longer body (+5) and the bigger frame (+3 slots).

The ctor is already defined in-class, so MSVC's inliner simply declined it.
The obvious lever is the body's statement count: an initialiser list has zero
body statements where the assignment form has three, and MSVC 4.2's inline
heuristic is statement-count based.

**Measured, then reverted:**

```
MxListEntry(T p_obj, MxListEntry* p_prev, MxListEntry* p_next)
    : m_obj(p_obj), m_prev(p_prev), m_next(p_next) {}
```

→ **LOST `0x100cc3c0 MxListEntry<MxString>::MxListEntry`**, a currently-exact
row, and no gain anywhere: 4845 → 4844.

That is a **decisive negative with a positive corollary**: a
currently-byte-exact retail row is reproduced by the *assignment* form and
broken by the initialiser list, so **retail's `MxListEntry` ctor body uses
assignments** and our source is already right. The inline/out-of-line
difference for the `LegoTranInfo*` instantiation is therefore not a ctor
spelling at all — it is the C2 inliner declining at that one call site, i.e.
the inline-budget class (fresh-eyes-2 §C4), not the text channel.

`LEGO1/omni/include/mxlist.h` is outside this lane's TU list in any case; the
experiment was run only to settle the hypothesis and was reverted immediately
(`git checkout`, rebuild confirms 4845 restored).

### 14.3 Where FUN_10061010 stands

* frame budget **−3 slots** (ours `sub esp,0x2c`, retail `0x38`) — unspent,
  and §13.2a's lesson applies: three *lifetimes*, not three names.
* `animRunning` type corrected and landed; 3-byte skew removed.
* the `MxListEntry` route is closed as a text lever and reclassified to the
  inline-budget class.
* body 717 vs retail 731; instruction counts 208 vs 211.

The remaining +14 bytes and +3 slots are consistent with one inlined
construction we do not perform. That is the same conclusion the standing TODO
reached, now with the ctor-spelling explanation eliminated and the row's type
defect fixed underneath it.

## 15. Wave 9 — the rectangle, partially swept

`sw.py --axes externR --kmax 40` sweeps the full `m,k = 0..40` extern
rectangle (1,681 cells). Launched on `legoanimpresenter.cpp` — the TU that
refutes the count-only law and holds the erase family's `+145`/`+434` ties.

**Covered: `m = 0..6` complete (0..40 in k), plus `m = 7` partial — 288 of
1,681 cells.** The machine was shared with two other lanes and throughput fell
from ~2.4 cells/s to roughly one every four seconds, so I stopped it rather
than let a partial masquerade as a result (§10.5's lesson: a partial sweep of
an ordered axis is not a uniform sample of it; `externR` enumerates `m`
ascending, so what exists on disk is the sub-rectangle `m ≤ 6`, complete in
`k`).

Best in that sub-rectangle:

| row | best nd | state | residue |
|---|---|---|---|
| 0x10068b20 erase AnimSubst | **1** | `extern-0-19` | `[145]` |
| 0x10069b10 BuildROIMap | 10 | `extern-5-11` | `[345, 356, 368, …]` |

`erase<AnimSubst>` reaches its known nd=1 floor at a *new* state
(`extern-0-19`, where the previous floor was `fwdE-19`), and byte `+145` is
wrong in all 8 length-correct cells of the sub-rectangle. Nothing better than
the pre-existing floor was found in `m ≤ 6`; the region the wave-9 brief
points at (`m,k ≈ up to 40`, where the `ReadModelDbWorlds` transposition fell
at 72×72 and Lane NM's landings sit off the `m=0` line) is **mostly
unswept** — `m ≥ 7` is 1,393 of the 1,681 cells and none of it is compiled.

Handover: `stl/sw.py --axes externR --kmax 40 --tag=_R40` resumes exactly
where this left off (existing cells are skipped, `if not obj.exists()`), so
the remaining ~1,400 cells cost nothing already spent.

## 16. Wave 10 — the rectangle is a bounded negative for legoanimpresenter

Resumed `--axes externR --kmax 40` on `legoanimpresenter.cpp`.
**Covered: `m = 0..28` complete in `k = 0..40`, 1,184 of 1,681 cells** — which
contains the whole region the wave-10 brief cites (`StepState` at
`extern-18-12`, `PlaceActor` at `(11,12)`, `charmgr erase` at `(15,22)`, and
all of Lane NM's landings inside `m ≤ 18, k ≤ 28`).

**Not one open row in this TU improves on its pre-existing floor:**

| row | rectangle best | state | previous floor |
|---|---|---|---|
| 0x10068b20 erase AnimSubst | nd=1 | `extern-0-19` | nd=1 (`fwdE-19`) — same floor, new state |
| 0x10069b10 BuildROIMap | nd=10 | `extern-10-1` | **nd=2** (`fwdE:19 × shape-4-22`) |
| 0x1006a7a0 `_Insert` AnimStruct | nd=5 | `extern-0-37` | nd=5 |
| 0x1006e720 `_Insert` HideAnim | nd=9 | `extern-21-25` | nd=4 |
| 0x1006c200 `_Insert` AnimSubst | nd=10 | `extern-14-1` | nd=4 |
| 0x10069e90 erase AnimStruct | nd=18 | `extern-20-5` | nd=18 |
| 0x1006dec0 erase HideAnim | nd=56 | `extern-0-10` | nd=55 |
| 0x1006b140 CopyTransform | — | length never reached | — |

The only nd=0 cells are rows that are already closed (`AssignIndiciesWithMap`,
`ParseExtra`). **Calling it: the extern rectangle is a bounded negative for
`legoanimpresenter.cpp` over `m ≤ 28`.** The register ties that fell for other
lanes in this region do not fall here, and the two rows with a *better* floor
elsewhere (BuildROIMap at nd=2, `_Insert` at nd=4) both found it in the
**shape** product, not the extern lattice — consistent with §12.3, where
BuildROIMap's count line was inert on two different pinned shapes.

`erase<AnimSubst>` reaching nd=1 at `extern-0-19` as well as `fwdE-19` is
worth one line: two structurally different carriers land the same body, and
byte `+145` is wrong in all 8 length-correct cells of the rectangle. That byte
has now resisted the flat grammar, the stacked product, the long line and the
2-D lattice.

### 16.1 `extern_pair_with_shape` — set up, not concluded

`landin.py` now emits the `extern_pair_with_shape` recipe (pre `extern:m,k` +
`shape-c-f`), so a hit in that space is landable. The canonical run for the
`+145` tie — `--pre extern:0,19 --axes shapefull`, the seat holding the
structure while the shape flips the byte — reached **85 of 505 cells** before
the machine saturated again. `shapefull` orders by `c` ascending, so that is
the `c ≤ 1` sub-grid and **not** a uniform sample; I am not reporting a floor
from it. Resume with the same tag (`_E019sf`); existing cells are skipped.

## 17. Wave 11 — FUN_10061010: the lifetime analysis

Reading only, no sweeping. Two hard facts, both from the built object against
the corrected retail body.

### 17.1 We call the `MxListEntry` ctor; retail inlines it

Call census of the two bodies: **ours makes 17 calls, retail 16**, and the
extra one is ours at offset 509,
`??0?$MxListEntry@PAULegoTranInfo@@@@QAE@PAULegoTranInfo@@PAV0@1@`. Every
other call pairs up in order. So the standing TODO's guess is confirmed as a
*fact* about the two objects (wave 8 only refuted the ctor-*spelling*
explanation for it): retail inlines that construction and we emit a call.

Retail's call offsets run **+11 bytes** ahead of ours from the third call
onward and **+14** from the thirteenth (the region containing our
`MxListEntry` call). So the 14-byte deficit is two separate regions: 11 bytes
early, and 3 more at the construction.

### 17.2 The early 11 bytes: retail materialises `&m_flags` before the branch

The bodies are instruction-for-instruction identical through offset 129 (the
cursor's four vtable stores at EH states 0..3). The first real divergence is
at **offset 196**:

```
OURS    193 mov esi,[ebp-0x14]   196 add esi, 0x14      199 cmp byte ptr [esi], 0
RETAIL  193 mov esi,[ebp-0x14]   196 mov edx,[ebp-0x14] 199 add esi, 0x74
```

`LegoTranInfo` layout: `m_location` 0x12, **`m_unk0x14` 0x14**, **`m_flags`
0x74**. So at the top of the loop body:

* we compute `&tranInfo->m_unk0x14` and test it — our source's condition
  order, `if (tranInfo->m_unk0x14 && tranInfo->m_location != -1 && p_und)`;
* retail computes **`&tranInfo->m_flags`** and *additionally* keeps a
  **second copy of `tranInfo` in `edx`**.

Two live pointers derived from `tranInfo`, materialised before the branch,
is exactly the shape of a **+3 slot** budget — this is the lifetime the frame
census has been pointing at since wave 7.

**Why `m_flags` before the branch is the interesting part.** In our source the
block

```cpp
if (tranInfo->m_flags & LegoTranInfo::c_bit2) {
    BackgroundAudioManager()->RaiseVolume();
    tranInfo->m_flags &= ~LegoTranInfo::c_bit2;
}
```

appears **twice** — once inside the then-arm's inner `if (…GetCamAnim())` and
once in the else-arm. Retail hoisting `&m_flags` above the branch is what you
would expect if the 1997 source evaluated that test **once, common to both
paths**, rather than duplicating it into the two arms.

**Not attempted, and deliberately so.** A naive hoist is *not* semantics-
preserving: in our text the then-arm's flags block sits inside the inner
`GetCamAnim()` test, so the `MxTrace`/`FUN_1004b8c0` path does **not** run it,
while the else-arm's copy is unconditional. Any reconstruction has to
reproduce that asymmetry while still making `&m_flags` live across the branch.
That is a real restructuring of the conditional, not a one-token edit, and it
should be done with the BETA10 body for this function in hand rather than
guessed — the function has no BETA10 annotation, so locating it is the first
step (the foundry ledger's bracketing method).

### 17.3 Handover

The row is now characterised end to end:

| fact | status |
|---|---|
| `animRunning` type (`MxS32` → `MxBool`) | fixed, landed zero-loss (wave 8) |
| `MxListEntry` ctor spelling | refuted with evidence (wave 8) |
| we call the ctor, retail inlines it | **confirmed by call census (17 vs 16)** |
| −3 slot budget | **located**: retail keeps `&m_flags` + a second `tranInfo` live across the branch |
| deficit split | 11 bytes early (the `&m_flags` hoist) + 3 at the construction |
| remaining work | restructure the duplicated `m_flags & c_bit2` test so it is common to both paths while preserving the then-arm asymmetry; needs the BETA10 body, which is unannotated for this function |

### 17.4 `extern_pair_with_shape` on `+145`: COMPLETE, and a bounded negative

`--pre extern:0,19 --axes shapefull` — the canonical case the wave-10 brief
named: one extern seat holds the structure, the shape flips the byte.
**505 of 505 cells, complete**, 72 of them length-correct, 20 distinct
residue sets. Floor for `erase<AnimSubst>`:

| residue | cells | example |
|---|---|---|
| `[145]` — byte 432 correct | 6 | `shape-5-20` |
| `[432]` — **byte 145 correct** | 2 | `shape-6-39` |
| `[145, 432]` — both wrong | 3 | `shape-4-33` |

**nd=1 both ways, nd=0 never.** Each tie byte is individually reachable in
this product and they are never jointly correct — the same anti-correlation
first recorded in §4.3 for the flat grammar, now reproduced over a *complete*
extern-seat × shape grid with the newest recipe kind.

So `+145`/`+432` have now resisted, each with a bounded search: the flat
grammar (§4.3), the `forward_run_with_shape` product (§10.5, 505 cells), the
long count line (§12), the 2-D extern rectangle (§16, 1,184 cells), and the
`extern_pair_with_shape` product (here, 505 cells). Five bounded negatives on
one pair of bytes is, at this point, evidence about the *mechanism* rather
than about the search: the two ties are not independently steerable by
declaration state, which is what a shared allocator decision would look like.

## 18. Wave 12 — FUN_10061010: BETA10 is empty here, and the slots are a symptom

### 18.1 BETA10 has nothing usable for this function — definitively

Not "I could not locate it": the body **is** annotated and **already
transcribed**. `legoanimationmanager.cpp` carries two source forms —
`#ifdef BETA10` (`// FUNCTION: BETA10 0x100422cc`) and `#else` (the retail
form). The June body is a much earlier function:

* no `m_flags` anywhere — so no `c_bit2` test, no `RaiseVolume` block;
* no `p_und` in the condition;
* no `m_tranInfoList2`, no `Append`, hence no `MxListEntry` construction;
* no `GetCamAnim()` chain, no `animRunning` accumulator;
* `m_presenter != NULL` tested *inside* each arm rather than as the outer test.

The construct I need to reconstruct did not exist in June. **BETA10 cannot
confirm or refute the `m_flags` hoist**, and no amount of bracketing will
change that. Recorded so nobody re-opens it.

### 18.2 Retail's structure, read from the binary instead

```
193 esi = tranInfo            196 edx = tranInfo
199 esi = tranInfo + 0x74     -> &m_flags,   live across the branch
202 edx = tranInfo + 0x14     -> &m_unk0x14
205 [ebp-0x44] = edx          -> SPILLED to a stack slot
208 ebx = [esi]               -> m_flags loaded once
212 al  = ebx & 2             -> the c_bit2 test computed BEFORE any branch
...
257 test bl, 2                -> re-tested inside the arm
274 and dword [esi], ~2       -> m_flags &= ~c_bit2 through the held address
284 edx = [ebp-0x44]          -> &m_unk0x14 reloaded
287 mov byte [edx], 0         -> m_unk0x14 = FALSE
```

So retail computes `m_flags & c_bit2` **once above the branch** and keeps two
derived addresses live — one of them spilled, which is one of the three extra
slots.

### 18.3 Two source forms tested; neither moves the frame

| variant | body | `sub esp` |
|---|---|---|
| base | 717 | 0x2c |
| h1 — `MxU32 flags = tranInfo->m_flags;` hoisted above the branch, both arms gate on it | 713 | 0x2c |
| h2 — `MxU32& flags` **and** `MxBool& unk14` reference locals | 711 | 0x2c |
| retail | 731 | **0x38** |

Both are semantics-preserving (each arm keeps its own gate, so the
`MxTrace`/`FUN_1004b8c0` path still does not run the raise block). Both move
the body and **neither moves the frame by a single byte**. This is §13.2a's
law again, now confirmed on a second row: **naming a value — even taking its
address — does not create a lifetime.** The allocator folds it.

### 18.4 The synthesis: the slot budget is a symptom, not a target

Retail *spills* `&m_unk0x14`. A spill happens because the allocator ran out
of registers — i.e. retail has **more register pressure** than we do. The one
structural difference we have already proven between the two objects is that
**retail inlines `MxListEntry<LegoTranInfo*>::MxListEntry` and we call it**
(17 calls vs 16, §17.1). An inlined construction adds live values, which adds
pressure, which produces exactly the spills that show up as +3 slots.

That unifies every measurement on this row into one cause:

| observation | explained by |
|---|---|
| 17 calls vs 16 | retail inlines the ctor |
| +3 bytes at the construction region | the inline itself |
| +3 stack slots | spills forced by the added pressure |
| +11 bytes early (addresses materialised and spilled) | the same pressure, upstream |

**So the frame budget is downstream of the inline decision, not an
independent lever** — which is why two reasonable source forms move the body
and leave `sub esp` at 0x2c. Wave 8 already showed the ctor *spelling* is not
the lever (the initialiser-list form breaks a currently-exact row and so is
refuted as retail's source). What remains is the C2 inline decision itself:
the inline-budget class, fresh-eyes-2 §C4.

**Recommendation: stop spending source variants on this row.** It is now
fully characterised and its remaining lever is the inliner instrument, which
is the same instrument the 484-site regrole class needs. No checked-source
edit was made this wave; all variants were out-of-tree.

## 19. Wave 13 — the C2 inliner instrument: observability, and a controlled dataset

Tooling: `inlinecensus.py` (whole-build), `inlinecensus2.py` (per-callee,
per-site).

### 19.1 The observable, and the flaw in my first version of it

Sound direction: **a call relocation to a COMDAT-defined callee is a
DECLINE** — the inliner saw an inline-eligible body at that site and did not
take it. The converse is not sound, and my first pass got it wrong: I scored
"defined but never called" as INLINED, which is false for **virtual**
members. They are reached through the vtable (a *data* relocation), so
nothing calls them directly. That put `Matrix4::ToQuaternion` (444 bytes,
`@@UAE` = virtual) at the top of an "always inlined" list, and produced a
decline-vs-size curve that was non-monotonic nonsense (P = 0.075, 0.018,
0.086, 0.035, 0.088, 0.277, **0.754**, 0.154 …). The 0.754 spike was an
artefact of what fell in that bucket, not a cost threshold.

Corrected: "no call" is ambiguous (inlined, unused, or vtable-only), so it is
only usable where the callee is **known** to be used at a **known** site.
That means the useful dataset is a template member with one known caller,
instantiated across many TUs — exactly the controlled shape the wave asked
for.

Whole-build numbers from the sound direction alone (226 objects, 1,776
inline-eligible callees, 517 defined in ≥2 objects): **159 are called in
every object that defines them**, and only **8 vary between objects**. The
decline is overwhelmingly stable per callee — but see §19.3, because retail
shows that stability is not the whole story.

### 19.2 The controlled case: `MxListEntry<T>::MxListEntry(T, prev, next)`

`MxList<T>::Append` → `InsertEntry` → `new MxListEntry<T>(obj, prev, next)`,
so every instantiation has exactly one caller and it is known. **Our build
declines it at 5 of 5 sites:**

| instantiation | size | TU | declining caller |
|---|---|---|---|
| `LegoTranInfo*` | 25B | legoanimationmanager | `FUN_10061010` |
| `LegoPhoneme*` | 25B | legophonemepresenter | `StartingTickle` |
| `LegoROI*` | 25B | legoanimpresenter | `AppendROIToScene` |
| `MxSpan*` | 25B | mxregion | `AddRect` |
| `MxString` | 130B | mxdsselectaction | `InsertEntry` |

### 19.3 What retail did — and it is a PER-SITE decision, not a per-callee one

Retail's row set contains out-of-line `MxListEntry` ctors, **all at 1.0**, for
`LegoPhoneme*` (0x1004eb20), `LegoROI*` (0x1006ea00), `MxSpan*` (0x100c5a20)
and `MxString` (0x100cc3c0). **The only instantiation retail has no row for is
`LegoTranInfo*`.**

So retail **declines this ctor at four sites and inlines it at exactly one** —
and that one site is `FUN_10061010`. We decline at all five. We therefore
agree with retail at 4 of 5 sites and differ at precisely the row that has
been open for six waves.

This corrects the natural reading of §18.4. The inline is **not** a property
of the callee (retail proves it by deciding both ways on the same template
body), and it is not a property of the callee's size (25 bytes, identical in
four of the five). It is a genuine per-call-site decision — which is what a
budget/pressure model predicts and what a pure cost model cannot.

It also disposes of the obvious source hypotheses. Retail *has* the
out-of-line ctor, so retail's `MxListEntry` really does have this 3-argument
constructor and really does construct through it — the decomp's source shape
is right (wave 8 had already shown the initialiser-list form breaks
`MxListEntry<MxString>`, an exact row; now we know that row is exact in
retail *because retail also declined to inline it there*).

### 19.4 Status of the instrument

Built: a sound one-directional observable and a controlled five-site dataset
in which retail and our build are known to differ at exactly one site.

Not built: the fitted budget rule. What §19.3 establishes is that the rule
must be **site-local** — the same 25-byte body, the same one-line caller
shape, decided both ways by retail. Fitting it needs the two counters at
`[esp+0x38]`/`[esp+0x40]` observed at the decision point, i.e. the sandboxed
C2 stub that fresh-eyes-2 §C4 specifies and that still does not exist. The
census cannot substitute for it: with one differing site the dataset has
exactly one bit of signal.

**The honest bound**: I can now say *which* site differs and that the decision
is site-local, but not *why*. Anyone continuing should build the C2 stub
first and use §19.2's five sites as its validation set — a model that does not
reproduce "decline at four, inline at `FUN_10061010`" is wrong, and that is a
sharper test than any single row.

## 20. Reproducing this lane

Everything lives in `scratchpad/stl/` (a private copy of `sweep-bench/` +
`fresh2/` repointed at `isle-build-tr03`). Nothing in the shared corpus was
mutated.

| tool | what it does |
|---|---|
| `famextract.py` | retail body + span for every `_Tree` row, straight from `legobin/LEGO1.DLL` |
| `laneoracle.py` | the same for an arbitrary row list (independent check on `oracles-v2.json`) |
| `symmap.py` | every `_Tree` COMDAT in the build with its link-winning object |
| `ourdiff.py` / `gdiff.py` | ours-vs-retail structural diff, relocation-masked, branch targets normalised (`gdiff` works for any oracles-v2 row) |
| `treedis.py` | retail-vs-retail diff of two instantiations |
| `summary.py` | the §1.2 family-map table |
| `lendelta.py` | instruction counts + `[ebp]` ModRM census (the §1.4 argument) |
| `nm2.py` | corpus near-miss against the corrected oracle, with the **length histogram** (answers "does any state reach retail's length at all?") |
| `pertarget.py` / `statereport.py` | top-N states per target / per-state view across targets |
| `bytecensus.py` / `wincensus.py` | census of one byte / one byte-window across a state space or the whole corpus |
| `zoom.py` | side-by-side disassembly of a donor and retail over an offset window |
| `sw.py` | the corrected sweeper (oracle v2, best-nd logging, `--pre` products, `--src` text variants, `inc`/`externL`/`externG`/`f<A|B|C><P|S|I>` axes) |
| `permcensus.py` / `permdbg.py` | which open rows are pure register permutations of retail, and what the permutation is |
| `erasegroups2.py` | the twelve-instantiation controlled experiment (retail colouring vs ours) |
| `colourreach.py` / `colourlaw.py` | does any state reach retail's colouring — per row, and project-wide |
| `residuesets.py` | distinct residue-offset sets: are the residual bytes individually or jointly locked |
| `defcensus.py` | same symbol, every defining TU: does the colouring differ between definers |
| `period.py` / `fwdlp2.py` | carrier-axis redundancy (period 32) and the fwdL/fwdP equivalence |
| `staleness.py` | did an upstream change move this TU's bodies (used for the `vec.h` discharge) |
| `landin.py` | `land_into.py` for this worktree, with the S72 relocation-symbol guard and the stacked-recipe writer |
| `repin_tr03.py` | accepted-row re-pin against `isle-build-tr03` |

Build command used for every gate in this ledger:

```sh
python3 tools/isle_build.py --build-dir /Users/foxtacles/Projects/isle-build-tr03 \
  --compiler /Users/foxtacles/Projects/MSVC420/wine/x86/cl --jobs 4 \
  --baseline-report /tmp/lego1-tr03-base.json
```
