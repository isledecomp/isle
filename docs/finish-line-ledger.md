# Lane FIN — the finish-line ledger

Worktree `agent-af3e1ee806b530baf`, branch `worktree-agent-af3e1ee806b530baf`,
reset to `entropy-stabilization` **2e296568**. Build dir
`/Users/foxtacles/Projects/isle-build-fin1` (four-character suffix — harness
trap #1, shadow path length is load-bearing).

**Base ancestry verified before any work**: the worktree was handed to me at
`31bd20de`, 586 commits *behind* the assigned base, on a branch off upstream
master. `git merge-base --is-ancestor 31bd20de 2e296568` passes, working tree
was clean, so the branch was fast-forwarded to `2e296568` before anything else
happened. A fresh worktree also has no `legobin/` (gitignored, lives only in
the main checkout) — symlinked, per the wave-4 hand-off note.

Baseline reproduced by a full cold gated run **from this build dir**:
`ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE: LEGO1 4850/4934,
ISLE 172/172, CONFIG 111/111` in 99.6 s.

Lane scratchpad: `<session scratchpad>/fin/`.

| tool | what it is |
|---|---|
| `sw.py` | the coordinator's `bench/sw2.py` repointed at this build dir, plus three new axes: `externK` (long EOF strip at m=0) and `triE:/triP:/triM:` (the `declaration_run_triple` seats — pin two, sweep the third) |
| `relguard.py` | the S72 semantic-relocation guard, rebuilt against `oracles-v2.json` + this lane's own `LEGO1-report.json` (Lane NM's `relcheck.py` is pinned to a worktree that no longer exists) |
| `landfin.py` | lands a swept state into the manifest against a **fresh out-of-tree seed compile of this lane's shadow**; knows `extern_run_pair`, `declaration_shape`, `pad_shape`, `declaration_run_triple` and all `forward_declaration_run` placements |

Owned TUs: `legopartpresenter.cpp`, `helicopter.cpp`, `isle.cpp`,
`legovideomanager.cpp`, `mxbitmap.cpp`, `mxstillpresenter.cpp`,
`mxramstreamprovider.cpp`, `legoact2.cpp`, `infocenter.cpp`, `pizza.cpp`,
`pizzeria.cpp`, `legocontrolmanager.cpp`, `tglrl40.cpp`,
`legocarbuildpresenter.cpp`.

---

## 0. First act: mine the corpus before compiling anything

Before opening a sweep I re-read the *coordinator's* retained sweep results
(`bench/sw-*/results.json`) for my fourteen TUs. Seven of them had been swept
by another lane and the floors were never transcribed into any ledger:

| sweep | states | row | floor |
|---|---|---|---|
| `sw-all-legocarbuildpresenterrect` | 1,680 | `0x100796b0 FindNodeDataByName` | **nd=0 @ `extern-2-0`** |
| `sw-all-legopartpresenterrect` | 1,680 | `0x1007ca30 LegoPartPresenter::Read` | 4 @ `extern-0-4`, offsets [875, 939, 2397, 2401] |
| `sw-all-legopartpresenterlong` | 759 | " | 4 @ `extern-18-0`, offsets [1143, 1216, **2397, 2401**] |
| `sw-all-legovideomanagerrect` | 1,680 | `0x1007b770 LegoVideoManager::Tickle` | 19 @ `extern-0-1` |
| `sw-all-mxbitmaprect` | 1,680 | `0x100bd020 MxBitmap::BitBltTransparent` | 60 @ `extern-0-24` |
| `sw-all-tglrl40rect` | 1,680 | `0x100a12a0 TextureImpl::SetImage` | 16 @ `extern-22-0` |
| " | " | `0x100a3b40 MeshBuilderImpl::Clone` | 14 @ `extern-0-1` |

The first line is a **finished, unlanded row**. Nobody had noticed, because the
sweep that found it belonged to a lane that did not own the TU and
`docs/open-set-triage.md` still lists `0x100796b0` as `0 flat cells — UNSWEPT`.

Second line worth keeping: `LegoPartPresenter::Read`'s two residue *pairs* move
independently — offsets **2397/2401 are invariant** across both sweeps while
the other pair moves from [875, 939] to [1143, 1216]. That is the
joint-reachability signature, and it says the invariant pair is the one to
attack.

---

## 1. LANDED: `0x100796b0 LegoCarBuildAnimPresenter::FindNodeDataByName`

*(measured; gate result recorded in §1.1 below)*

Re-derived on this lane's shadow — the state label does **not** transfer across
shadows, so it was recompiled rather than trusted:

```
sw.py all-legocarbuildpresenter --axes base,extern --tag cbp1
  162 states, 0 failed
  0x100796b0 retail=106  nd=0 @extern-2-0  lens: 106x162
```

Every one of the 162 states produces a 106-byte body (the row is size-clean),
and `extern-2-0` is masked-exact.

**Relocation guard (S72) before landing** — this row has only two relocations
and both agree with retail's callee identities:

| offset | our symbol | retail target | named |
|---|---|---|---|
| +32 | `_stricmp` | `0x1008c110` | `__strcmpi` (the same CRT entry) |
| +77 | `?FindNodeDataByName@LegoCarBuildAnimPresenter@@…` | `0x100796b0` | `LegoCarBuildAnimPresenter::FindNodeDataByName` (the row's own recursive call) |

The donor's relocation sequence is **identical to the seed's** — no `$L`/`$T`
renumbering at all.

### 1.1 Gate

Landed as a new `compose_equal_body_comdat` unit for
`LEGO1/lego/legoomni/src/build/legocarbuildpresenter.cpp` (the TU had none),
donor `extern_run_pair(g_h=2, g_p=0, width 2)`, splice class
`equal_body_strict`, 16 changed offsets.

```
LEGO1 rows 4851/4934 at 1.0
  GAIN  0x100796b0 LegoCarBuildAnimPresenter::FindNodeDataByName
  (no LOST rows)
ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE:
  LEGO1 4851/4934, ISLE 172/172, CONFIG 111/111
```

`0x100796b0` was `.8125`. **4850 -> 4851.**

**The transferable lesson**: before opening a sweep, re-score every retained
corpus directory that touches your TUs. Sweeps are run by whoever is holding
the bench, not by whoever owns the row, and a floor of 0 in another lane's
scratchpad is a landing nobody has taken. This one cost 162 compiles and a
relocation check.

---

## 2. The `Isle::Enable` +2211 structural lead is FALSE — retracted with the disassembly

The hand-off from the transcription lane (and `docs/beta10-wave5-ledger.md`'s
LenSquared census hand-off) said: *"at `Isle::Enable` body offset +2211, retail
has a `Vector3::LenSquared` prelude and our build has none. That is a missing
construct, not colouring."*

**Both sides have the prelude.** Same site, same instruction multiset, same
count (13 instructions), same length. Disassembled from this lane's own object
against the v2 retail body:

```
       RETAIL                              OURS
+2205  mov ecx,[ebp-0x48]                  mov ecx,[ebp-0x48]
+2208  mov eax,[ebp-0x48]                  mov edx,[ebp-0x48]
+2211  add ecx,8                           add ecx,8
+2214  add eax,4                           add edx,4
+2217  fld  [ecx] ; fmul [ecx]      +2217  mov eax,[ebp-0x48]
+2221  fld  [eax] ; fmul [eax]      +2220  fld  [eax] ; fmul [eax]
+2225  mov ecx,[ebp-0x48]           +2224  fld  [ecx] ; fmul [ecx]
+2228  faddp st(1)                  +2228  faddp st(1)
+2230  fld  [ecx] ; fmul [ecx]      +2230  fld  [edx] ; fmul [edx]
+2234  faddp st(1)                  +2234  faddp st(1)
```

The real difference is a **register-role + scheduling** one: retail keeps only
two address temporaries live and *rematerialises* the third (`mov ecx,[ebp-48]`
at +2225, after `ecx`'s first use is consumed); we materialise all three up
front into `ecx`/`edx`/`eax`. The consequent summation orders are
`(d2² + d1²) + d0²` for retail and `(d0² + d2²) + d1²` for us — a
reassociation *consequence* of the register choice, not an independent source
lever.

Two things follow, both of which save the next lane a session:

1. There is **no missing construct** at this site. Nobody should go looking for
   an absent statement in `isle.cpp`.
2. It does not contradict the wave-5 seal on reassociating
   `Vector3::LenSquared` in `vector3d.inl.h` — it *confirms* it. The retail
   site here leads with `base+8`, which is the majority order in that census
   ({8:7, 4:2}); ours leads with `base+8` in the *address* computation too
   (`add ecx,8` at +2211 precedes `add edx,4`). The two sides already agree on
   temp order; what differs is which temp the first `fld` reads. That is
   downstream of allocation, and the source spelling cannot address it.

This is one site inside a row with **214** residue bytes and 92 `desync`
entries, so it was never going to be the row's lever anyway.

---

## 3. `0x1007ca30 LegoPartPresenter::Read` (.9953, nd=4) — the complete residue map

The hand-off diagnosis was directionally right and one detail wrong. Measured
on this lane's default build (`nd=4 @ [1143, 1216, 2397, 2401]`), every
`cmp r/m32, r32` site in the body enumerated on both sides:

| body off | ours | retail | operands | jcc | site |
|---|---|---|---|---|---|
| 151 | `39` | `39` | `[ebp-0x64], esi` | jbe | `i < numTextures` guard |
| **667 / 731** | `3b` | `3b` | `ecx, [_Nil]` | je / jne | inlined `_Tree::find` #1 |
| **875 / 941** | `3b` | `3b` | `eax, [_Nil]` | je / jne | inlined `_Tree::find` #2 |
| **1143 / 1216** | `3b` | **`39`** | ours `esi, [_Nil]` / retail `[_Nil], esi` | je / jne | inlined `_Tree::find` #3 — **DIFF** |
| 1271 | `39` | `39` | `[eax], edi` | jne | — |
| 1448 | `39` | `39` | `[ebp-0x64], eax` | ja | `i < numTextures` bottom |
| 1849 | `39` | `39` | `[ebp-0x28], eax` | jbe | `j < numLODs` guard |
| 2208 | `39` | `39` | `[ebp-0x28], eax` | ja | `j < numLODs` bottom |
| **2397** | `39` | **`3b`** | ours `[ebp-0x60], eax` / retail `eax, [ebp-0x60]` | ja / jb | `i < numROIs` bottom — **DIFF** |

Corrections to the hand-off:

* There are **three** inlined `_Tree::find` compare pairs in this body, not one
  (`TextureContainer()->Get`, and two more from the container's insert path).
  Two of the three already agree with retail; only the one whose node lives in
  `esi` disagrees. The direction is **register-correlated**: where the node is
  in `ecx` or `eax` both sides emit `3b` (reg, mem); where it is in `esi`
  retail emits `39` (mem, reg) and we emit `3b`.
* `0x1007ca30` has **five** loop-compare sites, not one, and **retail is the
  odd one out at exactly one of them**: retail emits `39` at 151/1448/1849/2208
  and `3b` only at 2397. We emit `39` at all five.

### The conserved-quantity structure (re-scored, no compiles)

Re-scoring the coordinator's retained corpus for this row
(`bench/sw-all-legopartpresenter{rect,long}`, **2,439 scored states**) gives the
nd histogram floor at **4**, reached by 78 states in exactly five residue
shapes:

| offsets | states |
|---|---|
| `[875, 939, 2208, 2212]` | 3 |
| `[875, 939, 2397, 2401]` | 10 |
| `[1143, 1216, 1448, 1452]` | 7 |
| `[1143, 1216, 2208, 2212]` | 39 |
| `[1143, 1216, 2397, 2401]` | 19 |

Every nd=4 state is **exactly one wrong tree-pair plus exactly one wrong
loop-pair**, and *which* pair is wrong rotates with the carrier — including
onto sites (1448, 2208) that are **correct in the default build**. There is no
state in 2,439 with zero wrong tree-pairs, and none with zero wrong
loop-pairs.

Read as a budget: retail spends exactly one `3b` among its five loop compares
and we spend zero; a carrier state can move *where* our odd-one-out sits but
never make the count agree at the right site. That is the same "one shared
allocator decision" signature `docs/residue-runs.md` records for
`ManageVisibilityAndDetailRecursively`'s byte 517 and Lane NM's `+145`/`+434`
pair — and it is why 1,098 flat + 1,680 rectangle states all floor at 4.

**Channel verdict**: not a colour row that needs more cells. The text lever, if
one exists, has to change *which subexpression is evaluated first* at the
`i < numROIs` bottom test specifically — the four sibling loops in the same
function are already right, so any edit that moves all five together is wrong
by construction.

---

## 4. `pizza.cpp` — the extern rectangle is INERT here, and that is the result

Full `m,k = 0..40` rectangle (1,681 states + base) on this lane's shadow,
`sw-all-pizzarect`:

| row | retail len | lengths seen | best nd | distinct bodies |
|---|---|---|---|---|
| `0x10038380 Pizza::StopActions` | 110 | 110 × 1,681 | **15** | **1** |
| `0x10038b10 Pizza::HandleEndAction` | 1232 | 1232 × 1,681 | **12** @ `extern-0-23` | **3** |

`StopActions` produces the **same 110 bytes in every one of the 1,681 states**,
with the identical residue offset list `[52, 58, 61..67, 71, 80, 82, 85, 98,
103]`. That is not "a floor at 15" — it is total insensitivity: the carrier
does not reach this function at all. `HandleEndAction` in the same TU takes
three distinct bodies (nd 12 / 14 / 70), so the carrier *is* varying the
compile; the small function simply does not respond.

`docs/open-set-triage.md` lists both rows as `0 flat cells — UNSWEPT`. They are
now swept, and the honest entry is **"1,681 rectangle states, carrier-inert"**.

### Why, and the rule it suggests

`StopActions` is 110 bytes with three callee-saved registers and one loop; the
allocator has no slack to re-rank. `HandleEndAction` is 1,232 bytes and moves.
The transferable form: **carrier sensitivity tracks register pressure, not TU
membership.** Two rows in the same TU under the same 1,681 carriers gave 1 and
3 distinct bodies. A lane deciding where to spend a rectangle should look at
body size first.

### `StopActions` residue, read

```
       RETAIL                        OURS
+51    mov ebx,[edi+0x80]     mission -> ebx     mov edi,[edi+0x80]   mission -> edi
+57    test ebx,ebx                              test edi,edi
+59    je                                        je
+61    xor edi,edi            i = 0              cmp word [edi],si    guard first
+63    cmp word [ebx],si      guard              …
+66    jle                                       xor ebx,ebx          i-init AFTER the guard
…
+79    add esi,4              byte offset        add ebx,4
+82    inc edi                i++                inc esi
```

Both sides reuse the ambient zero (`xor esi,esi` in the prologue, kept alive by
the two `NULL` arguments) for one of the two induction values and pay a `xor`
for the other; retail spends the zero on the **byte offset** and zeroes `i`,
we spend it on **`i`** and zero the offset. Retail additionally hoists the
`i = 0` initialisation *above* the `mission->m_numActions > 0` guard, which is
the source order; we sink it below. So it is one allocator decision with a
scheduling shadow, on a body the carrier cannot touch — text channel only, and
`S66`/`S67` already sealed the index-placement cells there.

---

## 5. `pizzeria.cpp` — same story, and now it is a pattern

Full `m,k = 0..40` rectangle, `sw-all-pizzeriarect`:

| row | retail len | best nd | distinct bodies over 1,681 states |
|---|---|---|---|
| `0x10017af0 PizzeriaState::PizzeriaState` | 264 | **18, and the argmin is `base-0`** | **2** (nd 18 ×1,624, nd 23 ×57) |

The best state in the whole rectangle is *the uncarried compile*. Every carrier
that does anything at all makes it worse.

Residue read (`memset(m_states, -1, sizeof(m_states))` inlined):

```
       RETAIL                              OURS
+186   lea eax,[esi+0x44]                  mov eax,-1
+189   mov word [esi+0x40],cx              mov word [esi+0x40],cx      (+191)
+193   mov ecx,-1                          lea ecx,[esi+0x44]          (+195)
+198   mov word [esi+0x3e],dx              mov word [esi+0x3e],dx
+202   mov [ebp-4],ecx                     mov [ebp-4],eax
+205   mov [eax],ecx   …                   mov [ecx],eax   …
```

A clean `eax`↔`ecx` transposition: retail puts the destination pointer in `eax`
and the shared `-1` in `ecx`, we do the reverse. The `-1` is shared between the
`memset` fill and the EH-state store at `[ebp-4]`, which is what makes the two
values compete for the same rank. Both encodings are 5 bytes, so nothing forces
the choice.

### The lane-wide pattern, stated as a measurement

Three rectangles on three of my TUs, 5,043 states:

| row | body | distinct bodies over its 1,681 states | best nd | argmin |
|---|---|---|---|---|
| `0x10038380 StopActions` | 110 | **1** | 15 | anything |
| `0x10017af0 PizzeriaState` | 264 | **2** | 18 | **`base`** |
| `0x10038b10 HandleEndAction` | 1232 | **3** | 12 | `extern-0-23` |
| `0x100796b0 FindNodeDataByName` | 106 | (≥2 — one of them is retail) | **0** | `extern-2-0` |

**Carrier response scales with body size, not with the TU** — and the one small
row that *did* respond (`FindNodeDataByName`, 106 bytes) is the counterexample
that keeps this a heuristic rather than a law. What it is good for is ordering:
a 1,681-state rectangle on a 110-byte body costs the same as one on a
1,200-byte body and is far less likely to pay.

I stopped the `legoact2.cpp` rectangle at 200/1,681 states for exactly this
reason — `0x10051ac0 SpawnBricks` is `regrole=16 desync=10` at nd=58, the worst
prior in my queue — and moved the budget to the two rows whose residue is a
*single small permuted span* (`helicopter.cpp`, `mxramstreamprovider.cpp`,
below). The retained objects make that sweep resumable at zero cost.

---

## 6. Three "length defect ⇒ TEXT channel" verdicts overturned by reading the bytes

`docs/row-size-ledger.md`'s rule — *"a length defect can only be fixed by
changing what the source says"* — has a documented exception (the
`length:encoding` bucket in `docs/open-set-triage.md`). Two rows in my lane are
filed on the wrong side of it, and one is filed correctly but for the wrong
reason. All three were settled by disassembling, not by sweeping.

### `0x1006fda0 Infocenter::HandleKeyPress` — ours 264, retail 272, **+8 is one register**

Filed `length: never reached → TEXT/INLINE`, `Δinsn −2` (retail has two more
instructions). Both are true and both are downstream of a single allocation:

```
       RETAIL                                OURS
+145   mov eax,[esi+0x100]                   mov ecx,[esi+0x100]
+151   mov ecx,1                             mov eax,1
+156   mov [eax+0x74],ecx                    mov [ecx+0x74],eax
+159   mov eax,[esi+0x100]                   mov ecx,[esi+0x100]
+165   cmp [eax+0x78],0                      cmp [ecx+0x78],0
+169   jne                                   jne
+171   mov word [esi+0x1d2],cx               mov word [esi+0x1d2],ax
+178   mov eax,1          <-- RELOAD         (nothing: the 1 is already in eax)
+183   pop edi ; pop esi ; ret 4             pop edi ; pop esi ; ret 4
```

Retail keeps the constant `1` in **`ecx`**, so the `return 1` has to
re-materialise it into `eax` — five extra bytes. We keep it in `eax` and the
return value is already there. The five-byte shift then pushes the end of the
code region past a 4-byte boundary, so LINK inserts a **3-byte `lea ecx,[ecx]`
NOP** before the switch jump tables that the COMDAT body carries. 5 + 3 = the
whole **+8**.

So it is a `regrole` row wearing a length defect's clothes, and *our* codegen is
the better of the two. `Δinsn −2` counts the reload and the NOP.

### `0x1006ed90 Infocenter::Create` — ours 380, retail 381, **+1 is an operand-size prefix**

```
+142   RETAIL  33ff     xor edi, edi     (2 bytes, full 32-bit)
+140   OURS    6633ff   xor di, di       (3 bytes, 16-bit with the 0x66 prefix)
```

The loop counter is `MxS16` and is read back through `movsx edx, di` on both
sides, so both forms are correct. Note the control: the *other* 16-bit counter
in the same function is `6633db` = `xor bx, bx` on **both** sides at +169/+168.
Retail therefore uses a full-width zero for one counter and a prefixed
half-width zero for the other — it is a per-value liveness decision inside C2,
not a spelling.

**One byte, and it is a colour decision.** This row should not be in the
TEXT/INLINE bucket either.

### Consequence for `docs/open-set-triage.md`

Its own Extension 1 has the right test (identical instruction multiset ⇒
ENCODING) but it is applied to the *whole* body. Both rows above fail that test
— they genuinely have different instruction counts — while still being pure
colour defects, because a register choice can *create* an instruction (a
reload) and a length shift can *create* alignment padding. The sharper rule:

> A length delta is a text defect only if the extra instructions do work that
> the other side does not do. A reload, a spill, an operand-size prefix and
> alignment fill are all colour.

### Two more, same treatment

**`0x100293c0 LegoControlManager::UpdateEnabledChild` — ours 282, retail 286,
`+4` is one enregistered parameter.** First divergence at +72:

```
  ours   +72  8b7508      mov esi,[ebp+8]
  retail +72  668b5d10    mov bx, word [ebp+0x10]     <-- 4 bytes we never emit
  retail +76  8b7508      mov esi,[ebp+8]
```

Retail caches the third parameter (a 16-bit value) in `bx` at the top of the
function; we leave it in memory and spend `ebx` on the *second* parameter
instead (`ours +75 mov ebx,[ebp+0xc]`). The whole `+4` is that one
`mov bx, word [ebp+0x10]`. Filed `length: never reached → TEXT/INLINE`; it is
an allocation decision.

**`0x100ba2c0 MxStillPresenter::Clone` — ours 577, retail 576, `−1` is the
accumulator short form.** A clean `al`↔`cl` transposition through the whole
flag-merge block, and the byte falls out of the encoding table:

```
  ours   +272  80e101   and cl, 1      (3 bytes)
  retail +272  2401     and al, 1      (2 bytes — the AL,imm8 short form)
```

`docs/open-set-triage.md` already has this row in its `length:encoding` bucket,
so this one is a **confirmation** rather than a correction — and it is the
clean specimen for the class: the length delta is not extra work, it is the
x86 accumulator special-case being available to retail's register choice and
not to ours.

### The corrected channel table for my lane's five length-defect rows

| row | Δlen | filed as | measured |
|---|---|---|---|
| `0x1006fda0 HandleKeyPress` | +8 | TEXT/INLINE | **COLOUR** — reload + alignment NOP |
| `0x1006ed90 Create` | +1 | TEXT/INLINE | **COLOUR** — `0x66` operand-size prefix |
| `0x100293c0 UpdateEnabledChild` | +4 | TEXT/INLINE | **COLOUR** — one enregistered param |
| `0x100ba2c0 MxStillPresenter::Clone` | −1 | length:encoding | **COLOUR** — `and al,imm8` short form (confirmed) |
| `0x100a3840 CreateMesh` | −3 | TEXT/INLINE | first divergence at +406 is a **permutation** that re-converges at +418; the −3 is further in — not settled here |

Four of the five are colour, so the carrier axis is the right channel for them
and a text reconstruction would be wasted effort. That is a different verdict
from the one the triage hands the next lane, and it is why the k-strips
(`externK`, m=0, k=1..400) were run on `infocenter.cpp`,
`legocontrolmanager.cpp`, `mxstillpresenter.cpp` and `tglrl40.cpp` rather than
text cells.

---

## 7. Three rows whose residue is a single permuted span (read, don't sweep — but sweep anyway, and here is why)

`docs/residue-runs.md` classifies by span; run over my lane it put
`Helicopter::HandleControl` in MIXED (`colour=35 other=4 permuted=1`) and
`ReadData` in OTHER (`mnemonic`). Disassembled against the v2 bodies, both are
**single clean permutations** and the classifier's span widening is what hid
it — the same reconciliation Lane NM flagged in wave 6 §45.

### `0x100035e0 Helicopter::HandleControl` (.9907) — 19 bytes, one span, re-converges at +767

```
       RETAIL                            OURS
+744   mov [ebp-0x64],ecx                mov [ebp-0x64],ecx
+747   mov [ebp-0x74],edx                mov [ebp-0x9c],eax
+750   mov [ebp-0x9c],eax                mov [ebp-0xa0],ecx
+756   mov [ebp-0x78],ecx                mov [ebp-0x74],edx
+759   xor eax,eax                       xor eax,eax
+761   mov [ebp-0xa0],ecx                mov [ebp-0x78],ecx
+767   mov [ebp-0x88],ebx                mov [ebp-0x88],ebx      <- re-converge
```

Identical five instructions, and the **frame displacements are identical on
both sides**, so the declaration set and slot assignment are already retail's.
Two `Mx3DPointFloat` sub-objects — the one at `[ebp-0x78]/[ebp-0x74]` and the
one at `[ebp-0xa0]/[ebp-0x9c]` — swap the order in which their vftable and
`m_data` stores are emitted. The source block is

```c
Mx3DPointFloat location, direction, lookat;
…
Mx3DPointFloat v68, va4, up;
Mx3DPointFloat v90(0, 1, 0);
```

**The "read it" rule does not hand you an edit here**, and the reason is worth
recording: matching displacements *prove* the declaration order is already
correct, so the one source lever the rule points at (reordering the
declarations) is guaranteed to break the frame. This is the boundary of the
rule — a permuted span is a source problem only when the frame does not
already match.

### `0x100d0d80 ReadData` (.9722) — 18 bytes, all in the last 24, one span

```
       RETAIL                              OURS
+401   mov ecx,eax                         sub ebx,[esp+0x20]
+403   and ecx,1                           mov ecx,eax
+406   sub ecx,[esp+0x20]                  pop ebp
+410   pop ebp                             and ecx,1
+411   add ecx,ebx                         pop edi
+413   pop edi ; pop esi ; pop ebx         add ebx,ecx
+416   lea eax,[ecx+eax+8]                 pop esi ; lea eax,[ebx+eax+8] ; pop ebx
+420   add esp,0xc ; ret                   add esp,0xc ; ret
```

The source is one statement:

```c
return MxDSChunk::Size(data2) + (MxU32) (data2 - p_buffer);
```

`Size()` inlines to `len + (len & 1) + 8`. Retail starts the accumulation from
the `(len & 1)` term and folds the pointer difference into it; we start from
the pointer difference. Same value, different association — and per this
project's standing rule **integer chains are fully canonicalised** (only FP
sums keep their parentheses as barriers), so writing the addends the other way
round is expected to be bit-inert. The difference is the epilogue scheduler
interleaving the `pop`s with the arithmetic, which is compile state.

### `0x100334b0 Act1State::Act1State` (.9891) — 24 bytes, one span

Retail and ours emit the same nine member stores at 474–520 in different
orders. The decisive observation is that a *single* source statement's stores
are **not contiguous on either side**: `m_cptClickDialogue = Playlist(...)`
lands its four stores at retail offsets 490 (`[esi+0x10]`), 497
(`[esi+0x0e]`), 504 (`[esi+0x08]`) and **561** (`[esi+0x0c]`), interleaved
with five other statements. So the emission order does not encode the
statement order and no reordering of the constructor body can address it.

**What all three have in common**: the frames match, the instruction multisets
match, and the source cannot express the difference. They are the carrier
channel's problem, which is why they got the rectangles rather than text cells.

---

## 8. `mxramstreamprovider.cpp` rectangle — 11 bodies, and the base is still the argmin

`sw-all-mxramstreamproviderrect`, `m,k = 0..40`, 1,681 states + base:

| row | retail len | lengths | distinct bodies | nd histogram | argmin |
|---|---|---|---|---|---|
| `0x100d0d80 ReadData` | 424 | 424 × 1,681 | **11** | 18×205, 20×656, 22×369, 24×41, 26×205, 28×164, 44×41 | **`base-0`, nd=18** |

This is a more useful negative than `StopActions`' single body. The carrier is
**live** here — eleven distinct bodies, six distinct distances — and **every
single movement is away from retail.** So it is not "the carrier cannot reach
this function"; it is "the carrier reaches it and the uncarried state is
already the closest point in the reachable set."

Recording the distinction matters for how the next lane reads a floor:

| shape of the result | what it means | what to do next |
|---|---|---|
| 1 body over N states | the carrier does not reach the function | different channel |
| k bodies, argmin = base | the carrier reaches it, base is the local optimum | **stack** a second family (shape/pad) on the seats — a one-family sweep cannot express the state |
| k bodies, argmin ≠ base | ordinary colour search | extend the region |

Three of my four rectangles so far land in row 2 or 1 of that table
(`PizzeriaState` 2 bodies/argmin base, `ReadData` 11 bodies/argmin base,
`StopActions` 1 body), which is why queue 2 leads with the `xps` construction
(seats pinned at the rectangle argmin × the full 505-cell shape grid) rather
than with a wider rectangle.

---

## 9. Best-known state for every row in this lane (the table nobody had)

Scanned every `results.json` in both session scratchpads (218 sweep records,
this lane's and the coordinator's). This is the complete prior art for my
fourteen TUs, and it did not exist in any document before now:

| row | m | best nd anywhere | state | source of the record |
|---|---|---|---|---|
| `0x100796b0 FindNodeDataByName` | .8125 | **0** | `extern-2-0` | coordinator's `sw-all-legocarbuildpresenterrect` — **LANDED, §1** |
| `0x1007ca30 LegoPartPresenter::Read` | .9953 | 4 | `extern-18-0` | `sw-all-legopartpresenterlong` |
| `0x10038b10 Pizza::HandleEndAction` | .9538 | 12 | `extern-0-23` | this lane |
| `0x100a3b40 MeshBuilderImpl::Clone` | .7971 | 14 | `extern-9-0` | `sw-all-tglrl40long` |
| `0x10038380 Pizza::StopActions` | .7442 | 15 | **`base`** | this lane |
| `0x100a12a0 TextureImpl::SetImage` | .6667 | 16 | `extern-22-0` | `sw-all-tglrl40long` |
| `0x100d0d80 ReadData` | .9722 | 18 | **`base`** | this lane |
| `0x10017af0 PizzeriaState::PizzeriaState` | .8873 | 18 | **`base`** | this lane |
| `0x1007b770 LegoVideoManager::Tickle` | .9636 | 19 | `extern-0-1` | `sw-all-legovideomanagerrect` |
| `0x100bd020 MxBitmap::BitBltTransparent` | .7470 | 60 | `extern-0-24` | `sw-all-mxbitmaprect` |
| `0x100035e0 Helicopter::HandleControl` | .9907 | — | — | **never swept anywhere** (rectangle running) |
| `0x100334b0 Act1State::Act1State` | .9891 | — | — | **never swept anywhere** (rectangle running) |
| `0x10031820 Isle::Enable` | .9725 | — | — | **never swept anywhere** (rectangle running) |
| `0x1006ed90 Infocenter::Create` | .8966 | — | — | never swept (k-strip queued) |
| `0x1006fda0 Infocenter::HandleKeyPress` | .7933 | — | — | never swept (k-strip queued) |
| `0x100293c0 UpdateEnabledChild` | .8625 | — | — | never swept (k-strip queued) |
| `0x100ba2c0 MxStillPresenter::Clone` | .9251 | — | — | never swept (k-strip queued) |
| `0x100a3840 MeshBuilderImpl::CreateMesh` | .8176 | — | — | 2,439 states, retail's 664 bytes **never reached** (667 in all) |
| `0x10051ac0 LegoAct2::SpawnBricks` | .9101 | — | — | rectangle stopped at 200/1,681 (§5) |

Method note for the coordinator: the recursive `**/results.json` glob over a
scratchpad that holds sweep state directories walks hundreds of thousands of
directories and does not terminate in useful time. Globbing three explicit
depths (`/*/`, `/*/*/`, `/*/*/*/`) finds all 218 records in under a second.

---

## 10. HARNESS TRAP (new): the sweeper and the landable recipe disagree on `width`

`bench/sw2.py` renders each extern run at `width = max(2, len(str(count - 1)))`
— **per run**. The `extern_run_pair` recipe in
`tools/byte_identity_manifest.json` carries **one** `width` for both runs.
The two agree for every state anybody has swept so far only because the
historical grids stop at `m,k ≤ 40`, where both widths are 2.

The moment a sweep crosses 100 on one seat and not the other — which is
exactly what the long-strip and `externXL` axes do — the swept state stops
being expressible:

```
extern-0-101   widths {3}      landable
extern-0-300   widths {3}      landable
extern-15-22   widths {2}      landable
extern-150-5   widths {2, 3}   NOT landable — the recipe has one width field
```

Landing such a state through `land_into.py`, whose extern branch hardcodes
`width: 2`, would render **different text** from the state that was measured
and produce a body that is not the one the sweep scored. Nothing checks this:
the `generated_header_sha256` is computed from the recipe, so it agrees with
itself.

`landfin.py` now derives the width the same way the sweeper does and **refuses**
when the two seats disagree. Single-seat states (`m=0` or `k=0`) are always
expressible at any count, so the long 1-D strips are safe; the exposure is the
mixed high/low rectangle corner, which the `externXL` axis (stride 4 to 200 on
both) walks straight through.

Recommendation for the bench: either give `extern_run_pair` a per-seat width,
or make `sw2.py` render both runs at a single width derived from
`max(m, k)`. Until then, treat any `extern-m-k` hit with
`max(2,len(str(m-1))) != max(2,len(str(k-1)))` as unlandable.

---

## 11. `0x100a3840 MeshBuilderImpl::CreateMesh` — the one genuine text row, located

This is the only row in my lane where retail's length is **never reached** by
any carrier state (667 in all 2,439 states of the coordinator's `tglrl40`
sweeps; retail is 664), so `docs/row-size-ledger.md`'s rule applies honestly
here. The `−3` is now located to one instruction pair.

The tails align exactly (a constant `−3` offset from +590 to the `ret` at
+663), so the divergence is a single event. Aligning the instruction streams
on `(mnemonic, length)`:

```
   retail +406  8b5d0c   mov ebx,[ebp+0xc]      <-- hoisted here, 3 bytes
   retail +409  8d45dc   lea eax,[ebp-0x24]
   retail +412  8b5508   mov edx,[ebp+8]
   retail +415  8b31     mov esi,[ecx]
   retail +417  50       push eax
   …
   retail +425  6a03     push 3
   retail +427  52       push edx
   retail +428  bf01…    mov edi,1
   retail +433  53       push ebx               <-- the hoisted parameter
   retail +434  50       push eax
   retail +435  ff5638   call [esi+0x38]

   ours   +406  8d45dc   lea eax,[ebp-0x24]
   ours   +409  50       push eax
   ours   +410  8b5508   mov edx,[ebp+8]
   ours   +413  8b31     mov esi,[ecx]
   ours   +415  8b450c   mov eax,[ebp+0xc]      <-- materialised late, into eax
   …
   ours   +425  8b4de0   mov ecx,[ebp-0x20]
   ours   +428  50       push eax
   ours   +434  51       push ecx
   ours   +435  ff5638   call [esi+0x38]
```

Both push the same five arguments to the same virtual call. Retail enregisters
`[ebp+0xc]` in **`ebx`** once, early, and keeps it live across the `lea`/`push`
block; we materialise it late into `eax` and then need `ecx` for `[ebp-0x20]`
as well. Ours ends up with **one extra instruction** (228 vs 227) and three
extra bytes.

So even the "genuine text row" is an allocation difference — retail spends a
callee-saved register on a parameter and we do not. It is filed
`length: never reached → TEXT/INLINE` and `Δinsn +1`, which is literally true,
but no statement is missing: the extra instruction exists *because* of the
register choice. Whether that is reachable from a carrier is untested — the
`tglrl40` sweeps to date are `m,k ≤ 40` plus a 759-state long axis, and the
long strips are queued.

---

## 12. RETRACTION of my own §5 heuristic — reachable-set size does not predict success

In §5 I proposed ordering sweeps by body size, on the grounds that carrier
response tracks register pressure. I then measured the reachable set of the row
I had already landed, and it kills the heuristic.

Distinct `.text` bodies produced per row, over that row's own sweep:

| row | body | states | distinct bodies | is retail's body in the reachable set? |
|---|---|---|---|---|
| `0x10038380 StopActions` | 110 | 1,681 | **1** | no |
| `0x100796b0 FindNodeDataByName` | 106 | 162 | **2** | **YES — 18 of the 162 states** |
| `0x10017af0 PizzeriaState` | 264 | 1,681 | 2 | no |
| `0x10038b10 HandleEndAction` | 1232 | 1,681 | 3 | no |
| `0x100d0d80 ReadData` | 424 | 1,681 | 11 | no |

The row that **won** is the second-smallest, has the second-smallest reachable
set, and reached retail in **eleven percent of the states swept**. The row with
eleven distinct bodies and 1,681 states never came close.

So the correct statement is the uncomfortable one:

> The number of distinct bodies a carrier can reach says nothing about whether
> retail's body is among them. A two-point reachable set can contain the
> answer; an eleven-point one can miss it entirely. There is no cheap
> predictor — the sweep *is* the measurement.

What survives from §5 is only the weaker, still-useful part: a single body over
N states is a *proof* that the carrier family does not reach the function, and
that is worth knowing because it redirects to another family rather than a
wider grid. Everything else in that paragraph — and the sweep ordering I
derived from it, including stopping the `legoact2` rectangle — was a guess
dressed as a measurement, and the `legoact2` rectangle should be resumed
(its 200 retained state objects make that free).

---

## 13. Bench note: `sw2.py` buffers, so "no HIT line yet" is the only safe live signal

`sw2.py` prints `HIT nd=0 …` with `flush=True` but writes its summary through
the normal buffered path, so a redirected log stays **0 bytes** until the run
ends. That is actually the right property for this project's standing rule —
*never read a floor off a running sweep* — because the only thing visible
mid-run is the presence or absence of a `HIT` line, which is exactly the one
signal that is order-independent.

Do not be tempted to substitute `ls <sweepdir> | wc -l` progress for a result:
`externR` enumerates `m` then `k` ascending and `shapefull` enumerates `c`
ascending, so any prefix of either is a biased sample. Both of this lane's
predecessors published and retracted a floor read off a partial pass.

---

## 14. `isle.cpp` rectangle — `Isle::Enable` goes 214 → **11**, and the residue is the LenSquared site

`sw-all2-islerect`, `m,k = 0..40`, 1,681 states. `isle.cpp` had **never been
swept by anybody**.

| row | retail len | distinct bodies | best nd | argmin |
|---|---|---|---|---|
| `0x10031820 Isle::Enable` | 3580 | **37** | **11** (22 states) | `extern-1-8` |
| `0x100334b0 Act1State::Act1State` | 843 | **1** | 24 | anything — carrier-inert |

`Isle::Enable` is the largest movement measured in this lane: **nd 214 → 11**
on a 3,580-byte body, from a sweep nobody had run. Its `desync=92` in
`docs/residue-taxonomy.md` was the shadow of a single early divergence, exactly
as that document warns.

### And the surviving 11 bytes are the site the retracted lead pointed at

All eleven are `[2206, 2209, 2212, 2215, 2218, 2220, 2222, 2224, 2226, 2231,
2233]` — the inlined `Vector3::LenSquared` from `sub.LenSquared() < 1024.0f`.
At `extern-1-8` the *scheduling* difference documented in §2 is **gone** (the
carrier fixed it); what remains is a pure two-register transposition with
identical instructions in identical order:

```
       RETAIL                          OURS (extern-1-8)
+2205  mov ecx,[ebp-0x48]              mov eax,[ebp-0x48]
+2208  mov eax,[ebp-0x48]              mov ecx,[ebp-0x48]
+2211  add ecx,8                       add eax,8
+2214  add eax,4                       add ecx,4
+2217  fld [ecx] ; fmul [ecx]          fld [eax] ; fmul [eax]
+2221  fld [eax] ; fmul [eax]          fld [ecx] ; fmul [ecx]
+2225  mov ecx,[ebp-0x48]              mov eax,[ebp-0x48]
+2228  faddp st(1)                     faddp st(1)
+2230  fld [ecx] ; fmul [ecx]          fld [eax] ; fmul [eax]
+2234  faddp st(1)                     faddp st(1)
```

Retail holds `base+8` in `ecx` and `base+4` in `eax`; we hold them the other way
round, and the reloaded `base+0` follows whichever register was freed. The
summation order is therefore **identical** on both sides once the registers are
renamed — which retires the last piece of §2's reading as well: there is no
reassociation at this site at all, only `eax`↔`ecx`.

This is the cleanest regrole tie in my lane and it is on a row at `.9725`.
Running the `xps` construction on it (seats pinned at the rectangle argmin
`(1,8)` × the full 505-cell declaration-shape grid) — the same construction
that closed Lane NM's `charmgr erase` after the flat and rectangle axes had
each floored at 1.

### `Act1State::Act1State`: one body in 1,681 states

Carrier-inert in the strongest sense — the same 843 bytes everywhere. Combined
with §7's finding that a single source statement's stores are scattered
non-contiguously across the residue, this row has **no channel currently
known**: not the extern carrier, and not statement order.

### The decisive control: the *second* LenSquared inline in the same function is already exact

`Isle::Enable` inlines `Vector3::LenSquared` twice, from two symmetric source
blocks:

```c
Mx3DPointFloat sub(-21.375f, 0.0f, -41.75f);
sub -= position;
if (sub.LenSquared() < 1024.0f)  { AnimationManager()->FUN_10064740(NULL); }

Mx3DPointFloat sub2(98.874992f, 0.0f, -46.156292f);
sub2 -= position;
if (sub2.LenSquared() < 1024.0f) { AnimationManager()->FUN_10064670(NULL); }
```

At `extern-1-8` the **second** inline (+2310…+2340) is **byte-identical to
retail**, register for register. Only the first is transposed. Laying the two
sites side by side:

| site | retail | ours |
|---|---|---|
| #1 (+2205) | `ecx ← base+8`, `eax ← base+4` | `eax ← base+8`, `ecx ← base+4` |
| #2 (+2310) | `ecx ← base+4`, `eax ← base+8` | `ecx ← base+4`, `eax ← base+8` ✓ |

**Retail alternates between its own two sites; we use the same assignment at
both.** That is the sharpest possible confirmation of
`docs/beta10-wave5-ledger.md`'s sealed negative — its census found retail's
first-temp displacement histogram is `{8:7, 4:2}`, i.e. retail uses both orders,
and here are both orders **inside one function, from one inline, on two
adjacent copies of the same three-line source pattern**. No spelling of
`Vector3::LenSquared` can emit both, so `vector3d.inl.h` is provably not the
lever, and neither is the call site's text: the two call sites are already
textually symmetric and we already match one of them.

What is left is what makes retail's *first* site pick the other order — i.e.
whatever else is live across it. That is an allocator-rank question, which is
exactly what the carrier axis perturbs, and the row has moved 214 → 11 on that
axis already.

---

## 15. `helicopter.cpp` rectangle — 4 bodies, argmin is the base

`sw-all-helicopterrect`, `m,k = 0..40`, 1,681 states. Never swept before.

| row | retail len | distinct bodies | nd histogram | argmin |
|---|---|---|---|---|
| `0x100035e0 Helicopter::HandleControl` | 1148 | **4** | 19×1,237, 21×38, 39×403, 41×3 | **`base-0`, nd=19** |

The 19-byte permuted span documented in §7 survives the whole rectangle
unchanged, and every state that moves the body moves it further away. Third row
in this lane to land in the "k bodies, argmin = base" cell of §8's table
(`ReadData` 11 bodies, `PizzeriaState` 2, `HandleControl` 4).

Note this also settles §7's open question in the negative for the extern
family: a single permuted span with matching frame displacements is not
reachable from the seat lattice. The remaining untried families for it are the
force-included shape/pad grids stacked on those seats, which is what the `xps`
construction supplies.

### Running total of rectangles in this lane

| TU | states | rows | outcome |
|---|---|---|---|
| `legocarbuildpresenter.cpp` | 162 | 1 | **nd=0 → LANDED** |
| `pizza.cpp` | 1,681 | 2 | 15 (1 body) / 12 |
| `pizzeria.cpp` | 1,681 | 1 | 18, argmin base (2 bodies) |
| `mxramstreamprovider.cpp` | 1,681 | 1 | 18, argmin base (11 bodies) |
| `helicopter.cpp` | 1,681 | 1 | 19, argmin base (4 bodies) |
| `isle.cpp` | 1,681 | 2 | **214 → 11** / 24 (1 body) |
| `legoact2.cpp` | 200 (stopped, resumable) | 1 | — |

**8,767 donor-lane compiles.** One landing, one row moved by 203 bytes, four
rows proved carrier-inert or carrier-negative with their extent recorded.

---

## 16. The `xps` construction on `LegoPartPresenter::Read` — negative, and it *loses* ground

Seats pinned at the long-axis argmin `extern-18-0` × the full 505-cell
declaration-shape grid (`sw-all-legopartpresenterxps180`):

```
505 states, 0 failed
0x1007ca30 retail=2633  best nd=6 @shape-1-2  offs=[1143, 1216, 1448, 1452, 2208, 2212]
           lens: 2633 x 505
```

**nd=6 against the flat axis's 4** — every shape over those seats makes it
worse, and the residue shape confirms why: at the flat floor exactly one tree
pair and *one* loop pair are wrong; over the stacked seats one tree pair and
**two** loop pairs are wrong. Adding the force-included shape destroys the loop
compare the seats had already fixed.

This is the same behaviour Lane NM recorded for `0x1002bff0`
(`extraactor erase`): its nd=1 state was *destroyed* by any shape at all, while
`0x10082ca0` (`charmgr erase`) — same template family — was *closed* by adding
one. Two more data points on the same split:

| row | flat/rect floor | + shape over the argmin seats |
|---|---|---|
| `0x10082ca0` charmgr erase (NM) | 1 | **0** |
| `0x1002bff0` extraactor erase (NM) | 1 | 17 |
| `0x1007ca30 LegoPartPresenter::Read` (here) | 4 | **6** |

There is still no way to tell in advance which side a row falls on; the seat
argmin is a good starting point and nothing more.

### The nd=11 states sit on the rectangle's edge — two m-strata, and both are truncated

The 22 states are not scattered. They form two clean strata:

```
m = 1  :  k = 8, 9, 35, 36, 37, 38, 39, 40
m = 35 :  k = 1..7, 33..39
```

Both strata run **into the k = 40 boundary of the swept region**, which by Lane
NM's wave-4d rule ("treat a boundary-argmin as *keep going*") means the curve is
truncated, not flat. The `m = 1` stratum in particular has its floor still
present at the very last column.

That the good `m` values are exactly 1 and 35 — with everything between them
worse — is also the seat law behaving as `docs/beta10-wave5-ledger.md`
describes: `k` chooses the family, `m` chooses the colour inside it, and the
good `m` values are isolated points rather than a range. The historical `8 × 17`
box would have found `extern-1-8` and nothing else; the `m,k ≤ 40` rectangle
finds both strata but cannot see where either ends.

Extending both strata to `k = 120` (`externF:1:41:120`, `externF:35:41:120`,
160 states) — recorded here as the run that was in flight, with its result
below.

---

## 17. Hand-off: the state of every row in this lane, and what to do with it

### Landed

| row | before | after | how | commit |
|---|---|---|---|---|
| `0x100796b0 LegoCarBuildAnimPresenter::FindNodeDataByName` | .8125 | **1.0** | `extern_run_pair(g_h=2, g_p=0, width 2)`, found by re-scoring the coordinator's retained corpus | `2b1ccba7` |

Gate at hand-off: **LEGO1 4851/4934, ISLE 172/172, CONFIG 111/111**, zero LOST.

### The one row worth a session on its own

**`0x10031820 Isle::Enable`, nd 214 → 11.** Everything about it is now known:

* the residue is eleven bytes, all in the *first* of two inlined
  `Vector3::LenSquared` copies, at body +2205…+2236;
* it is a pure `eax`↔`ecx` transposition with identical instructions in
  identical order — no scheduling and no reassociation left;
* the **second** copy of the same inline, from textually symmetric source, is
  already byte-identical to retail, which rules out both `vector3d.inl.h` and
  the call-site text as levers and proves retail alternates its own register
  assignment between the two sites;
* the nd=11 states form two m-strata (`m=1`, `m=35`) that both run into the
  `k=40` edge of the region swept, i.e. the curve is truncated.

Next moves, in order: finish the `k=41..120` extension of both strata; the
`xps` grid at whichever seat pair survives; then `extern_pair_with_pad` (the
second shape family) at the same seats. If those exhaust, this row is the best
customer in the project for a C2 allocator-rank instrument, because the
control — a second copy of the same inline in the same body that is *already
correct* — is unusually clean.

### Carrier-inert or carrier-negative, with extent (do not re-sweep these)

| row | extent | result |
|---|---|---|
| `0x10038380 Pizza::StopActions` | 1,681 rectangle | **one body**, nd=15 |
| `0x100334b0 Act1State::Act1State` | 1,681 rectangle | **one body**, nd=24 |
| `0x10017af0 PizzeriaState::PizzeriaState` | 1,681 rectangle | 2 bodies, argmin **base**, nd=18 |
| `0x100035e0 Helicopter::HandleControl` | 1,681 rectangle | 4 bodies, argmin **base**, nd=19 |
| `0x100d0d80 ReadData` | 1,681 rectangle | 11 bodies, argmin **base**, nd=18 |
| `0x10038b10 Pizza::HandleEndAction` | 1,681 rectangle | 3 bodies, nd=12 @ `extern-0-23` |
| `0x1007ca30 LegoPartPresenter::Read` | 2,439 prior + 505 `xps` | 4 flat, **6** stacked (worse) |

### Diagnosed, channel corrected, not yet attacked

| row | correction |
|---|---|
| `0x1006fda0 Infocenter::HandleKeyPress` | filed TEXT; is **colour** (reload + alignment) |
| `0x1006ed90 Infocenter::Create` | filed TEXT; is **colour** (one `0x66` prefix) |
| `0x100293c0 UpdateEnabledChild` | filed TEXT; is **colour** (one enregistered param) |
| `0x100ba2c0 MxStillPresenter::Clone` | confirmed `length:encoding` (`and al,imm8`) |
| `0x100a3840 CreateMesh` | genuinely never reaches 664, but the `−3` is still an allocation difference, not a missing statement |

### Untouched

`0x10051ac0 LegoAct2::SpawnBricks` (rectangle stopped at 200/1,681 on a
heuristic I have since retracted — **resume it**, the state objects are
retained), `0x1007b770 LegoVideoManager::Tickle` (long strips queued),
`0x100bd020 MxBitmap::BitBltTransparent`, `0x100a12a0 TextureImpl::SetImage`,
`0x100a3b40 MeshBuilderImpl::Clone`.

### `xps` on `Isle::Enable` — negative, and `Act1State` is inert on **both** shape families

`sw-all2-islexps18` — seats pinned at `extern-1-8` × the full 505-cell
declaration-shape grid:

| row | distinct bodies | best nd | offsets |
|---|---|---|---|
| `0x10031820 Isle::Enable` | 22 | **11** @ `shape-7-46` | identical list — `[2206, 2209, 2212, 2215, 2218, 2220, 2222, 2224, 2226, 2231, 2233]` |
| `0x100334b0 Act1State::Act1State` | **1** | 24 | unchanged |

The shape family produces 22 distinct bodies for `Isle::Enable` and **none of
them touches the eleven bytes** — the floor and the offset list are exactly the
rectangle's. So the `eax`↔`ecx` transposition in the first `LenSquared` inline
is not reachable by adding a force-included declaration shape over those seats.

`Act1State::Act1State` is now inert across **both** carrier families:
one body in 1,681 extern-rectangle states and one body in 505 declaration-shape
states, **2,186 states, one 843-byte body**. Together with §7 (its permuted
stores do not encode statement order) that row has no known channel at all, and
it should be taken off carrier queues until somebody has an allocator
instrument.

### The edge extension — the truncation was real, the floor is not

`sw-all2-isleedge`: `externF:1:41:120` and `externF:35:41:120`, 160 states, both
strata carried out to `k = 120`.

```
0x10031820 retail=3580  nd=11 @extern-1-41  offs=[2206, 2209, 2212, 2215, 2218, 2220, 2222, 2224, 2226, 2231, 2233]
           lens: 3580 x 120,  3588 x 40
nd histogram: 11 x 24,  28 x 71,  34 x 12,  193 x 5,  210 x 8
floor states: extern-1-{41,72,73,99,100,101,102,103,104,105}
              extern-35-{65..71,97..103}
```

Both strata **do** continue past `k = 40` — the floor states run out to
`k = 105` at `m = 1` — so the "boundary-argmin means keep going" rule was right
that the region was truncated. But the floor itself never moves off **11**, and
the offset list is byte-for-byte identical in all 24 of them. (The 40 states at
length 3588 are the ones that fall out of retail's length family entirely; they
are the `nd = 193/210` tail.)

**Extern family, final extent for `0x10031820`:** 1,681 rectangle + 160 edge
states = **1,841 states, floor 11, offsets invariant**; plus 505 declaration
-shape states over the argmin seats, same floor and same offsets. Now running
the two channels this row has never seen: `extern_pair_with_pad` over the same
seats, and include-order permutation — the axis that produced Lane NM's
complementary residue on `0x1002bff0` when neither shape family could.

---

## 18. The k-strips on the length-defect rows — the EOF seat alone never moves the length

`externK` = `extern-0-k`, `k = 1..400`, i.e. the complete long EOF strip at
`m = 0` that the seat law says should "tell you which counts reach retail's
length at all".

`sw-all-infocenterkstrip`, 401 states:

```
0x1006ed90 Infocenter::Create        retail=381  correct length NEVER reached   lens: 380 x 401
0x1006fda0 Infocenter::HandleKeyPress retail=272  correct length NEVER reached  lens: 264 x 401
```

**One length in all 401 states, for both rows.** So for these two the EOF seat
is not merely unhelpful, it is *inert on the length axis* — which is exactly
what §6 predicts: their length deltas are a register reload, an operand-size
prefix and an alignment NOP, none of which the EOF count reaches on its own.

That makes the `m` coordinate the whole question for them, and the rectangle
the right instrument — queued (`queue4.sh`) for `infocenter.cpp`,
`legocontrolmanager.cpp` and `mxstillpresenter.cpp`, plus the resumption of the
`legoact2.cpp` rectangle I stopped in §5 and retracted in §12.

Also completed: `xps` on `LegoPartPresenter::Read` at the *other* rectangle
argmin, `extern-0-4` × 505 shapes — **nd=4 @ `shape-1-2`**, offsets
`[1143, 1216, 2208, 2212]`. That ties the flat floor rather than beating it,
and together with the `extern-18-0` run (nd=6, §16) it says the shape family
neither helps nor is uniformly harmful here — it depends which seat pair it is
stacked on.

### Include-order permutation on `Isle::Enable` — negative

`sw-all2-isleinc18`: 72 include-order permutations of `isle.cpp`'s quoted
include block (adjacent swaps, rotations, random shuffles) over the argmin
seats `extern-1-8`.

```
0x10031820 nd=11, offsets identical, in all 72 states
0x100334b0 nd=24, offsets identical, in all 72 states
```

This is the axis that gave Lane NM the complementary residue on `0x1002bff0`
when neither shape family could reach it (wave-5 §37), so it was worth the 72
compiles. It does not reach this row.

**Running extent for `0x10031820 Isle::Enable`: 2,418 states** — 1,841 extern
(rectangle to 40 × 40 plus both strata to k = 120), 505 declaration-shape over
the argmin seats, 72 include-order permutations — **floor 11, offset list
byte-identical in every one.** The `extern_pair_with_pad` grid and the
three-seat `declaration_run_triple` are the last two carrier channels the row
has never seen and are in flight.

---

## 19. Session summary

*(This section was written before §20/§21; the counts below are superseded by
the closing section at the end of the file. Kept as written, because the
ordering is the point: the second landing came from correcting a claim made in
this very ledger.)*

**Rows gained: 1**, proved end to end by a gated `isle_build.py` run from this
worktree with zero LOST rows.

| row | before | after | proof |
|---|---|---|---|
| `0x100796b0 LegoCarBuildAnimPresenter::FindNodeDataByName` | .8125 | **1.0** | `ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE: LEGO1 4851/4934, ISLE 172/172, CONFIG 111/111` |

**Rows moved without landing: 1**, and it is the biggest movement in the lane.

| row | before | after | how |
|---|---|---|---|
| `0x10031820 Isle::Enable` | nd 214 | **nd 11** | `extern-1-8`, from a rectangle nobody had run on `isle.cpp` |

### What this lane actually produced

The landing came from **reading other lanes' retained sweep records**, not from
compiling anything new: `0x100796b0` had been at nd=0 in the coordinator's
`sw-all-legocarbuildpresenterrect` for a whole wave while
`docs/open-set-triage.md` listed it as `0 flat cells — UNSWEPT`, because the
lane that swept it did not own the TU. Cost to convert: 162 compiles and a
two-relocation guard check.

Everything else in this lane is a register-role or scheduling tie, and the
useful output is the *shape* of the negative space:

* **8,767 + 2,418 donor-lane compiles**, seven rectangles, three shape grids,
  two long strips, one include-permutation set.
* Four rows proved carrier-inert or carrier-negative with their full extent
  (`StopActions`, `Act1State`, `PizzeriaState`, `HandleControl`, `ReadData`).
* Four rows moved from the TEXT bucket to COLOUR by reading their bytes
  (`HandleKeyPress`, `Create`, `UpdateEnabledChild`, and confirming
  `MxStillPresenter::Clone`), with the sharper rule that produced them.
* One handed-over structural lead **retracted with the disassembly**, and the
  wave-5 `LenSquared` seal **independently re-confirmed** by a control nobody
  had noticed: `Isle::Enable` inlines `LenSquared` twice from symmetric source,
  retail uses opposite register assignments at the two sites, and we already
  match one of them exactly.
* One new harness trap: the sweeper's per-run `width` versus
  `extern_run_pair`'s single `width` field.
* One of my own heuristics measured and retracted in the same session.

### What I would do next, in order

1. **`0x10031820 Isle::Enable`.** Finish the `extern_pair_with_pad` grid and the
   three-seat generator over the argmin seats. If both are negative, this row is
   the project's best-founded customer for a C2 allocator-rank instrument,
   because it ships its own control: a second copy of the same inline, in the
   same body, from symmetric source, that is *already byte-exact*. Any model of
   C2's tie-break can be validated against "why does site 1 differ from site 2".
2. **The `queue4` rectangles** (`infocenter.cpp`, `legocontrolmanager.cpp`,
   `mxstillpresenter.cpp`, and the resumed `legoact2.cpp`). All four target rows
   this lane re-classified from TEXT to COLOUR, and the k-strip proved the `m`
   coordinate is the whole question for them.
3. **Re-score every lane's retained corpus against every lane's row list.** This
   lane's only landing was sitting unclaimed in another lane's scratchpad. The
   scan is three globs and a second of CPU (§9), and it should be a standing
   step at the start of every wave, not an idea somebody has once.
4. **Fix the `width` mismatch** (§10) before anybody sweeps the mixed
   high/low corner of the extern plane.

---

## 20. CORRECTION to §4: `Pizza::StopActions` is inert on the *extern* family, not on the carrier

`sw-all-pizzaxps023` — seats `extern-0-23` × the full 505-cell
declaration-shape grid:

```
0x10038380 StopActions      retail=110   nd=11 @shape-1-1  offs=[61..67, 80, 82, 85, …]   lens: 110 x 505
0x10038b10 HandleEndAction  retail=1232  nd=12 @shape-1-4                                  lens: 1232 x 285, 1252 x 220
```

**`StopActions` goes 15 → 11.** The row that produced *one single body* across
1,681 extern-rectangle states moves the moment a force-included declaration
shape is added. Three of its fifteen residue bytes (52, 58, 71) are fixed.

That is a real correction to §4 and it generalises. I wrote there that "the
carrier does not reach this function at all". The truthful statement is
narrower and more useful:

> **The extern family and the declaration-shape family are not
> interchangeable.** A row can be *completely* inert on one — one body, 1,681
> states — and live on the other. "Carrier-inert" is never a property of a row;
> it is a property of a (row, generator) pair, and it has to be said that way.

The practical consequence is that every "N states, one body, carrier-inert"
verdict in this ledger — and in the wave-4/wave-5 ledgers — is only a verdict
about the generator that produced it. `queue5.sh` therefore re-runs the
declaration-shape grid on **all** four rows this lane called inert on the
extern rectangle (`pizza.cpp`, `pizzeria.cpp`, `mxramstreamprovider.cpp`,
`helicopter.cpp`), plus the pad family on `pizza.cpp`.

`HandleEndAction` in the same sweep stays at 12, and 220 of the 505 shapes push
it out of retail's length family entirely (1252 rather than 1232) — so the two
rows in one TU respond to the same generator in opposite ways, which is the
same lesson again one level down.

---

## 22. The three-seat generator on `Isle::Enable` — negative

`declaration_run_triple` is the recipe kind added at `bbe7cbb4` for exactly this
purpose, and no row in this lane had ever seen it. `sw-all2-isletri0`, 122
states (`triM_0_0-k` = post-include seat alone, `triP_0_0-k` = pre-include seat
alone, both `k = 0..60`):

```
0x10031820 nd=13 @triM_0_0-37   (against the extern family's 11)
0x100334b0 nd=24 @triM_0_0-0    (unchanged, all 122 states, one length)
```

The forward-run seats on their own are **worse** than the extern pair for
`Isle::Enable`. Note what this measures and what it does not: it isolates the
pre-include and post-include seats one at a time, so it is a test of those
*seats*, not of a genuinely three-seat state — filling all three at once with
independent counts is still unswept for this row, and remains the last carrier
coordinate it has never seen.

**`Act1State::Act1State` extent is now 2,308 states** — 1,681 extern rectangle,
505 declaration-shape, 122 forward-run seats — **one 843-byte body in every
single one.** Whatever else is true, that row's codegen is not a function of the
declaration-record stream at all.

---

## 23. The `pizza.cpp` shape grid, complete

`sw-all-pizzashape`, all 505 declaration-shape cells, no seats:

```
0x10038380 StopActions      retail=110   nd=11 @shape-1-1   lens: 110 x 505
0x10038b10 HandleEndAction  retail=1232  nd=0  @shape-1-3   lens: 1232 x 298, 1252 x 207
```

Side by side with the extern rectangle on the same two rows:

| row | extern rectangle (1,681) | declaration-shape grid (505) |
|---|---|---|
| `0x10038380 StopActions` | **15**, one body | **11** |
| `0x10038b10 HandleEndAction` | 12, three bodies | **0 — LANDED** |

`StopActions` also improves, 15 → 11, on the generator that could not move it at
all in its other form. Its residue is now `[61..67, 80, 82, 85, …]` — the
`xor`/`lea` ordering block documented in §4 — and 207 of the 505 shapes push
`HandleEndAction` out of retail's length family, so the two rows in this TU
respond to the same grid in opposite directions.

---

## 24. In flight at hand-off (resumable at zero cost — the state objects are retained)

`sw2.py`-derived sweeps skip any state whose `o.obj` already exists, so every
one of these resumes by re-running the identical command:

| sweep | states done | command |
|---|---|---|
| `all-legovideomanager` shape grid | ~270 / 505 | `sw.py all-legovideomanager --axes shapefull --tag shape` |
| `all-infocenter` rectangle | ~120 / 1,682 | `sw.py all-infocenter --axes base,externR --tag rect` |
| `all2-isle` pad grid over `extern-1-8` | 296 / 900 | `sw.py all2-isle --pre extern:1,8 --axes padfull --tag xpp18` |
| `all-legoact2` rectangle | 200 / 1,682 | `sw.py all-legoact2 --axes base,externR --tag rect` |
| `queue4.sh` | not started | `infocenter` / `legocontrolmanager` / `mxstillpresenter` / `legoact2` rectangles |
| `queue6.sh` | partial | plain shape grids on `legocontrolmanager`, `mxstillpresenter`, `infocenter`, `tglrl40`, `mxbitmap`, `isle`, `legoact2`, `legopartpresenter` |

`queue6.sh` is the one to run first. It is the direct consequence of §20/§21:
nine TUs in this lane have only ever seen the extern family, and the one time
the plain declaration-shape grid was tried on such a TU it produced a landing
in its first 36 compiles.

---

## 25. Closing summary (supersedes §19)

Gate at hand-off, verified by a full `isle_build.py` run from this worktree
after deleting the composed objects so nothing came from cache:

```
ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE:
  LEGO1 4852/4934, ISLE 172/172, CONFIG 111/111
```

**Rows gained: 2**, both with zero LOST rows.

| row | before | after | how | commit |
|---|---|---|---|---|
| `0x100796b0 LegoCarBuildAnimPresenter::FindNodeDataByName` | .8125 | **1.0** | `extern_run_pair(g_h=2, g_p=0)` — found by re-scoring another lane's retained corpus | `2b1ccba7` |
| `0x10038b10 Pizza::HandleEndAction` | .9538 | **1.0** | `declaration_shape(1, 3)` — found by acting on a correction to this ledger | `d4e1c5c3` |

**Row moved without landing: 1.** `0x10031820 Isle::Enable`, **nd 214 → 11**,
from a rectangle nobody had ever run on `isle.cpp`.

### Both landings came from questioning a written claim, not from more compiles

* The first was sitting at nd=0 in the coordinator's
  `sw-all-legocarbuildpresenterrect` while `docs/open-set-triage.md` listed the
  row as `0 flat cells — UNSWEPT`. The sweep belonged to a lane that did not
  own the TU. Cost to convert: **162 compiles**.
* The second came from disbelieving my own §4. I had written that `pizza.cpp`
  was carrier-inert on the strength of 1,681 extern states producing one and
  three bodies. Stacking a shape on those seats moved `StopActions`, which
  falsified the claim; running the plain shape grid on the same TU found
  `HandleEndAction` **masked-exact in its first 36 compiles**.

Against those two, **~11,000 donor-lane compiles** of systematic grid search in
this lane produced no third landing.

### The three findings most worth carrying forward

1. **"Carrier-inert" is a property of a (row, generator) pair.** A row with one
   body across 1,681 extern states was one compile away from retail on the
   shape grid. Every such verdict in every ledger names a generator and nothing
   more, and the follow-up costs 505 cells.
2. **Cross-lane corpus re-scoring is a standing step, not an idea.** 218 sweep
   records, three globs, one second of CPU (§9), one row.
3. **A length delta is a text defect only if the extra instructions do work the
   other side does not do.** Reloads, spills, operand-size prefixes and
   alignment fill are colour (§6). Four of my five length-defect rows moved
   bucket on that test.

### Retracted in this ledger, by measurement

* the handed-over `Isle::Enable` +2211 "missing construct" lead (§2);
* my own body-size sweep-ordering heuristic (§12);
* my own `pizza.cpp` carrier-inertness verdict (§20) — which is what produced
  the second landing.

---

# Wave 2 — re-scoring what wave 1's own findings invalidated

Reset onto the merged tip `7ca647ff` (ancestry verified: my wave-1 HEAD
`f2674945` is an ancestor). Baseline re-verified from this build dir before any
work: `ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE: LEGO1 4853/4934,
ISLE 172/172, CONFIG 111/111`.

## 26. `adiff.py` had seven normalisation defects, and they were worth up to 30 SHAPE points

The coordinator adopted Lane INL's SHAPE/STRUCT/EXACT metric as the instrument
this wave. Applying it to my lane produced two impossible readings, and running
them down found seven asymmetries in the masking. **All seven inflate the
apparent difference**, so every score in `docs/inliner-ledger.md` §11 is a
lower bound.

The two impossibilities that exposed them:

* `Infocenter::HandleKeyPress` scored **SHAPE 68.24** — by far the worst in the
  lane — for a row whose entire residue I had already read by hand in §6 as one
  reload plus one alignment NOP;
* `TglImpl::TextureImpl::SetImage` scored **SHAPE 76.92 < STRUCT 94.87**, which
  cannot happen: SHAPE erases strictly more than STRUCT, so its alignment can
  never be worse.

| # | defect | why it manufactures a difference | worth |
|---|---|---|---|
| 1 | a `.text` COMDAT that carries **switch jump tables** has them disassembled as code | our entries are relocated zeros, retail's are resolved addresses, so the "instructions" decoded from them are unrelated garbage | HandleKeyPress 68.24 → 91.07 |
| 2 | `[reg + <relocated address>]` classified as a frame displacement and left unmasked | `mask_immediates` only masked brackets with **no** register; a jump-table base or indexed global has both | every switch dispatch and indexed global read as a diff |
| 3 | capstone prints a **zero displacement as nothing** | our relocated displacement is 0 → `[eax]`; retail's is resolved → `[eax + 0x1006fe84]`. Masking cannot equalise a token that is absent on one side | 2 insn per switch |
| 4 | indirect `jmp`/`call` **through memory** masked as a direct branch target | `jmp [eax*4 + table]` got `NUM → T` on retail and `→ R` on ours: two different markers for the same thing | 2 insn per switch |
| 5 | `fs:[0]` (the SEH `__except_list` access) | a relocation in our COFF, a literal `0` in retail's image — masked on one side only | 2 insn in every function with EH |
| 6 | `[ebp ± X]` erased as a frame slot in **frameless** functions | MSVC uses `ebp` as a general register when there is no frame; if retail holds a pointer in `ebp` where we hold it in `ebx`, retail's operand becomes `[F]` and ours stays `[r + 0x1c]` — **asymmetric, and the cause of the SHAPE < STRUCT inversion** | SetImage 76.92 → 94.87 |
| 7 | a **real large immediate** in a relocation-covered instruction masked on our side only | `and [g_isleFlags], 0xffffffbf` — our side masked every number in the instruction, retail's masked only image addresses | Isle::Enable 2 insn |

Fixes, all in this lane's copy (`<scratchpad>/fin/adiff.py`), each narrow:

1. `code_len()` — find the trailing run of DIR32 relocations to `$L` labels at
   4-byte stride (bridging one gap for the byte index table, requiring ≥ 3
   entries so a lone `push offset $L…` in EH setup is never mistaken for a
   table), and score only the code region. Retail is trimmed by the **same
   number of trailing bytes**, which is right because the table has one entry
   per case on both sides.
2/3. Detect a relocated displacement **exactly**, via capstone operand detail
   (`op.mem.disp == 0` with a base or index, on a relocation-covered
   instruction), and re-insert it textually as the mask marker **before** any
   other masking. Doing it after is order-dependent and is what produced
   the inversion in my first attempt.
4. Only apply the branch-target substitution when the operand has no bracket.
5. Canonicalise `fs:[…]` to `fs:[S]` on both sides.
6. `has_ebp_frame()` — only erase `[ebp ± X]` when the prologue actually
   contains `push ebp; mov ebp, esp`.
7. On our side mask only plausible relocation placeholders
   (`v < 0x10000` or an image address), never a large real constant. Also
   never mask a **scale factor** (`[eax*4]`) — it is part of the addressing
   mode, not a value.

### Net effect on this lane

| row | SHAPE before | SHAPE after |
|---|---|---|
| `0x1006fda0 Infocenter::HandleKeyPress` | 68.24 | **98.21** |
| `0x100035e0 Helicopter::HandleControl` | 96.30 | **100.00** |
| `0x10031820 Isle::Enable` (default build) | 92.31 | **98.20** |
| `0x100293c0 UpdateEnabledChild` | 90.68 | **95.65** |
| `0x100a12a0 TextureImpl::SetImage` | 76.92 (invalid) | **94.87** |
| `0x10017af0 PizzeriaState` | 92.96 | **94.37** |

**Recommendation: re-run every score in `docs/inliner-ledger.md` §11 before
acting on it.** `FUN_10061010` is an EH function (defect 5), and
`ManageVisibilityAndDetailRecursively`, `MxDSBuffer::FUN_100c6fa0` and
`MxDisplaySurface::VTable0x30` all index globals or use `ebp` as a general
register. In particular §11.2's conclusion that `h01`+`v04` "anti-compose"
rests on differences of 2–5 points, which is inside the error bar these defects
introduce.

### 26.1 Two more defects, found by the rows themselves

Running the corrected instrument over the lane surfaced two more, both from the
same root cause — **an instruction carries at most one relocation, and which
field holds it decides what may be masked.** Getting it wrong manufactures
differences in *both* directions:

| # | case | wrong reading |
|---|---|---|
| 8 | `cmp [g_partPresenterConfig1], 0` — relocation is the absolute address, the `0` is a **real** immediate | ours `cmp [R], R` vs retail `cmp [R], 0` |
| 9 | `mov [edi], offset $T123` — relocation is the **immediate**, the memory operand has no displacement | ours `mov [r + R], R` vs retail `mov [r], R` (defect 3's fix misfiring) |

`reloc_site()` now decides: an **absolute** memory operand is always a
relocation in a COFF (compiled code contains no literal absolute addresses), so
it wins even when a real immediate is present; otherwise an immediate operand
takes it; otherwise the memory operand. Only that field is masked.

**Nine defects total, every one inflating the gap.** Corrected scores, each row
at its best known state (§26.2 classifies them):

| row | addr | SHAPE | STRUCT | EXACT |
|---|---|---|---|---|
| `Isle::Enable` @ `extern-1-8` | `0x10031820` | **100.00** | **100.00** | 99.21 |
| `Helicopter::HandleControl` | `0x100035e0` | **100.00** | 99.05 | 99.05 |
| `MeshBuilderImpl::Clone` | `0x100a3b40` | **100.00** | **100.00** | 79.71 |
| `MxStillPresenter::Clone` | `0x100ba2c0` | **100.00** | **100.00** | 94.65 |
| `LegoVideoManager::Tickle` | `0x1007b770` | 99.70 | 99.70 | 96.36 |
| `LegoPartPresenter::Read` | `0x1007ca30` | 99.53 | 99.53 | 99.53 |
| `Act1State::Act1State` | `0x100334b0` | 98.91 | 98.91 | 98.91 |
| `Infocenter::Create` | `0x1006ed90` | 98.71 | 98.71 | 90.99 |
| `MeshBuilderImpl::CreateMesh` | `0x100a3840` | 98.46 | **98.02** | 82.20 |
| `Infocenter::HandleKeyPress` | `0x1006fda0` | 98.21 | 98.21 | 87.50 |
| `Pizza::StopActions` @ `shape-1-1` | `0x10038380` | 97.67 | 97.67 | 88.37 |
| `ReadData` | `0x100d0d80` | 97.22 | 97.22 | 97.22 |
| `PizzeriaState::PizzeriaState` | `0x10017af0` | 97.18 | 97.18 | 88.73 |
| `LegoAct2::SpawnBricks` | `0x10051ac0` | 97.12 | 97.12 | 90.65 |
| `UpdateEnabledChild` | `0x100293c0` | 96.89 | **95.65** | 93.17 |
| `MxBitmap::BitBltTransparent` | `0x100bd020` | 96.39 | 96.39 | 78.92 |
| `TextureImpl::SetImage` | `0x100a12a0` | 94.87 | 94.87 | 66.67 |

## 26.2 Re-classification of the whole lane, and two more blind spots

The wave-3 rule is "SHAPE gap ⇒ the source is producing a different program".
Applied literally to this table it is wrong in both directions, and both
failures are visible here:

* **A pure permutation can score SHAPE 100.** `Helicopter::HandleControl` is
  SHAPE 100.00 / STRUCT 99.05: its three permuted stores differ only in their
  frame slots, and SHAPE erases those. The scheduling defect is invisible at
  the level that is supposed to detect source problems.
* **A pure permutation can also score a SHAPE gap** — `PizzeriaState` (97.18,
  a `lea`/`mov word` pair exchanged), `ReadData` (97.22, the epilogue
  interleave), `Act1State` (98.91). Here the permuted instructions differ in
  something SHAPE keeps, so the same class reads differently depending on
  *what* got permuted.

So SHAPE separates "different operations" from "same operations" only when the
divergence is not a reordering. The reliable discriminators, applied to every
row in my lane:

| class | test | rows |
|---|---|---|
| **pure colour** — allocator only, no source lever exists | SHAPE 100 **and** STRUCT 100, EXACT < 100 | `Isle::Enable` (99.21), `MeshBuilderImpl::Clone` (79.71), `MxStillPresenter::Clone` (94.65) |
| **scheduling** — same instruction multiset, reordered | divergence pairs are the same instructions in a different order | `Helicopter::HandleControl`, `PizzeriaState`, `ReadData`, `Act1State` |
| **cmpdir** — same mnemonic, exchanged operands | not source-addressable (§28) | `LegoPartPresenter::Read` |
| **frame** — declaration-set defect, the strongest text signal | **STRUCT < SHAPE** | `UpdateEnabledChild` (96.89 → 95.65), `MeshBuilderImpl::CreateMesh` (98.46 → 98.02) |
| **shape + colour** — genuine text candidates | SHAPE < 100 with real operation differences | `TextureImpl::SetImage`, `MxBitmap::BitBltTransparent`, `Pizza::StopActions`, `LegoAct2::SpawnBricks`, `Infocenter::Create`, `Infocenter::HandleKeyPress` |

**`STRUCT < SHAPE` is the sharpest signal in the metric and nobody has named
it.** It means the two sides agree on every operation but disagree on where a
value lives in the frame — which is exactly the "declaration-set defect" the
frame census in `docs/open-set-triage.md` was built to detect, now available
per-instruction instead of per-`sub esp`. Two of my rows have it, and neither
appears in that document's four-row TEXT list.

### Verdicts that flip

| row | wave-1 / prior verdict | wave-2 verdict |
|---|---|---|
| `0x100a3b40 MeshBuilderImpl::Clone` | "regrole, 14 bytes, carrier floor 14" | **pure colour, proven**: SHAPE 100 / STRUCT 100. No text lever exists. |
| `0x100ba2c0 MxStillPresenter::Clone` | `length:encoding`, filed TEXT/INLINE | **pure colour, proven**: SHAPE 100 / STRUCT 100 *with* a −1 length defect — the strongest possible confirmation of §6's rule |
| `0x10031820 Isle::Enable` | "nd=11, biggest unlanded movement" | **pure colour, proven**: 889/889 at SHAPE and STRUCT |
| `0x100293c0 UpdateEnabledChild` | wave 1: "COLOUR — one enregistered param" | **frame defect** (STRUCT < SHAPE) — a text row after all, but not for the reason the triage gave |
| `0x100a3840 CreateMesh` | "text channel, −3 never reached" | **frame defect** (STRUCT < SHAPE), and the −3 is downstream of it |
| `0x10017af0 PizzeriaState` | wave 1: "carrier-inert regrole" | **scheduling** — a 2-instruction permutation, not colour |
| `0x1007ca30 LegoPartPresenter::Read` | "cmpdir, text lever unknown" | **cmpdir, text channel closed** (§28) |

---

## 27. `0x10031820 Isle::Enable` — SHAPE **100.00**, STRUCT **100.00**. The verdict is final.

At `extern-1-8`, scored against retail with the corrected instrument:

```
SHAPE  ours 889 insn, retail 889 insn, aligned 889 (100.00%), first divergence none
STRUCT ours 889 insn, retail 889 insn, aligned 889 (100.00%), first divergence none
EXACT  ours 889 insn, retail 889 insn, aligned 882 (99.21%), first divergence ours+2205
```

**Our source produces retail's program, instruction for instruction, and
retail's frame layout, slot for slot.** The only thing left in a 3,580-byte
function is which register seven instructions use — the `eax`↔`ecx`
transposition in the *first* of the two inlined `Vector3::LenSquared` copies
(§14), where the *second* copy is already byte-identical (§14's control).

This closes the question the coordinator raised. There is nothing for a text
cell to do here: a source change can only make SHAPE or STRUCT worse, both of
which are already perfect. The row is **purely an allocator tie**, it is the
best-instrumented one in the tree, and it ships its own control.

## 28. `0x1007ca30 LegoPartPresenter::Read` — the wave-1 diagnosis survives, and the one live text lever is now closed

**SHAPE = STRUCT = EXACT = 99.53**, and the complete residue is three groups:

```
+1143  ours cmp r, [R]         retail cmp [R], r       (inlined _Tree::find #3)
+1216  ours cmp r, [R]         retail cmp [R], r       (same loop's back edge)
+2397  ours cmp [F], r / ja    retail cmp r, [F] / jb  (i < numROIs bottom test)
```

Nothing else in 2,633 bytes. The wave-1 hand diagnosis was made on the "blind"
metric and it is **exactly right**; the corrected instrument adds that there is
**no colour and no frame component at all** (all three levels identical).

### The `!=` cell — documented as live, never tried here, and it settles the source

`docs/residue-taxonomy.md` records that rewriting `i < n` as `n > i` is
completely code-inert while **`i != n` moves the body**. That is a live lever
and it had never been applied to this row. Five line-neutral cells, each
compiled and scored:

| cell | loops changed to `!=` | nd | new defects | SHAPE |
|---|---|---|---|---|
| base | — | **4** | — | **99.53** |
| `r1_roi_ne` | `i < numROIs` | 5 | **+1717**, and 2397/2401 still wrong | 99.42 |
| `r2_tex_ne` | `i < numTextures` | 6 | **+155, +1452** | 99.30 |
| `r3_both_ne` | both `i` loops | 7 | +155, +1452, +1717 | 99.18 |
| `r4_lod_ne` | `j < numLODs` | 6 | **+2008, +2212** | 99.30 |
| `r5_all_ne` | all three | 9 | all of the above | 98.95 |

Every cell is **strictly worse**, and the *way* it is worse is the finding:

* `!=` on the `numROIs` loop does **not** flip the +2397 compare — it leaves it
  wrong and adds a new defect at +1717;
* `!=` on the `numTextures` loop and on the `numLODs` loop each **break sites
  that currently match retail** (151/1448 and 1849/2208).

So this is a negative that carries positive information: **retail's source
spells all three loops `<`**, confirmed independently three times inside one
function, and the +2397 compare direction is therefore not a loop-condition
question at all.

### A blind spot in the wave-3 metric, exactly where the closest row lives

`adiff` reports a `cmpdir` **identically at all three levels** — SHAPE erases
registers and frame slots but not operand *order*, so `cmp r, [R]` and
`cmp [R], r` differ at SHAPE. A reader following the wave-3 rule ("SHAPE gap ⇒
the source is producing a different program ⇒ go read the source") would spend
text cells on this row. The project's own canonicalisation law says the
opposite: comparison direction is **not** source-addressable, and the five
cells above confirm it here.

**`cmpdir` needs a level below SHAPE** — or at minimum a note that a divergence
whose two sides are the same mnemonic with exchanged operands is an allocator
artifact regardless of which level reports it. `docs/inliner-ledger.md` §11.3
reports `ManageVisibilityAndDetailRecursively` at SHAPE 97.92 without flagging
that its residual byte is of exactly this class.

**Verdict for `0x1007ca30`:** carrier-exhausted (2,944 states), text channel now
closed with the one lever that was live, no colour component, no frame
component. It is an allocator row in the same class as `Isle::Enable` — and the
two of them are the project's cleanest specimens for the C2 instrument.

## 26.3 CORRECTION to §26.2: `STRUCT < SHAPE` is weaker than I stated

I wrote that `STRUCT < SHAPE` means a declaration-set defect. Reading both rows
that have it shows that is too strong. The signal is real but ambiguous:

> `STRUCT < SHAPE` means the two sides reference **different frame slots at
> instructions that otherwise align**. That is *either* a different frame
> layout *or* the same layout with a different choice of which value to keep in
> a register. One disassembly separates them.

Both of my rows are the second kind, and — worth more than the correction —
**they are the same mechanism in two different TUs**:

```
0x100293c0 UpdateEnabledChild   retail +72  mov bx, word [ebp+0x10]   <- enregisters the 3rd param
                                ours        (never)  ... and reloads later
0x100a3840 CreateMesh           retail +406 mov ebx, [ebp+0xc]        <- enregisters vertexCount
                                ours  +458  mov r, [F]                <- an extra reload we pay
```

In both, retail spends a callee-saved register on a **parameter** and holds it
across a region; we leave it in memory and reload. In both, that one decision
is the row's entire length delta (`+4` and `−3`, §6 and §11). Neither frame
*layout* differs.

So the honest channel verdict for both is **colour with a length shadow**, not
a declaration-set defect — which puts them back with `MxStillPresenter::Clone`
rather than with `GetCached` and `FUN_10061010` in the frame-census TEXT list.

`CreateMesh`'s enregistered value is `vertexCount`, a parameter of
`MeshBuilderImpl::CreateMeshImpl`, which is inlined from `tgl/d3drm/tglimpl.h`
— a header shared by every `tgl` consumer, so a source cell there is a
cross-TU change and outside this lane. **Recorded, not attempted.**

---

## 29. The shape family on `tglrl40.cpp` — negative, and it bounds §20's correction

§20's finding ("carrier-inert is a property of a (row, generator) pair") pays
sometimes, not always. `tglrl40.cpp` holds a row now **proven** pure colour
(`MeshBuilderImpl::Clone`, SHAPE 100 / STRUCT 100, EXACT 79.71), so its whole
remaining search is compiler state and the declaration-shape family had never
been run on the TU. Full 505-cell grid:

```
0x100a12a0 SetImage    retail=83   nd=16 @shape-1-5   lens: 83 x 489, 84 x 16
0x100a3840 CreateMesh  retail=664  correct length NEVER reached   (667 x 505)
0x100a3b40 Clone       retail=197  nd=14 @shape-1-1   lens: 197 x 505
```

**Identical floors to the extern family** (16 and 14), on the same offsets.
So the second generator reaches nothing here, and `0x100a3b40` is now:

* proven pure colour at the program level (SHAPE 100 / STRUCT 100), so **no
  source form can help it**;
* floored at nd=14 across **2,944 states in both carrier families**.

That is the same terminal position as `Isle::Enable` and
`LegoPartPresenter::Read`, reached by a different route, and it means my lane
now has **four** rows that are provably out of reach of every channel the
project currently has:

| row | m | proof it is colour-only | carrier extent |
|---|---|---|---|
| `0x10031820 Isle::Enable` | .9725 | SHAPE 100 / STRUCT 100 @ `extern-1-8` | 2,418 states, floor nd=11 |
| `0x100a3b40 MeshBuilderImpl::Clone` | .7971 | SHAPE 100 / STRUCT 100 | 2,944 states, floor nd=14 |
| `0x100ba2c0 MxStillPresenter::Clone` | .9251 | SHAPE 100 / STRUCT 100 | shape grid in flight |
| `0x1007ca30 LegoPartPresenter::Read` | .9953 | SHAPE=STRUCT=EXACT, residue is 3 `cmpdir` sites; the one live text lever tested and negative (§28) | 2,944 states, floor nd=4 |

**This is the wave's most useful output.** Before it, "we have not found the
lever yet" and "no lever of this kind exists" were indistinguishable. SHAPE 100
/ STRUCT 100 separates them: it is a *proof* that the source text and the
declaration set are already retail's, so every future text cell on such a row
is known-wasted before it is compiled. Four rows in one lane can now be taken
off the text queue permanently and handed to the allocator instrument with a
one-line justification each.

---

## 30. Wave-2 answer to the assignment

The brief was: for every row whose ledger entry says inert / exhausted /
text-channel, check **(a)** which generators it was actually swept on,
**(b)** whether its length delta is work or encoding, and **(c)** whether any
rejected text cell moves SHAPE — and report which verdicts flip.

### (a) Generator coverage — the audit

| row | extern | shape | pad | inc | triple | verdict on coverage |
|---|---|---|---|---|---|---|
| `0x1007ca30 Read` | 2,439 | 1,010 (2 seat pins) | — | — | 122 | shape **only ever stacked on seats**, never plain — now run, floor unchanged |
| `0x10031820 Isle::Enable` | 1,841 | 505 (on seats) + plain in flight | resumed | 72 | 122 | complete but for the pad grid |
| `0x100a3b40 Clone` | 2,439 | **505 (new)** | — | — | — | both families, same floor |
| `0x100a12a0 SetImage` | 2,439 | **505 (new)** | — | — | — | both families, same floor |
| `0x10038380 StopActions` | 1,681 | **505 (new)** | — | — | — | shape moved it 15 → 11 after extern gave **one body** |
| `0x10038b10 HandleEndAction` | 1,681 | **505 (new)** | — | — | — | shape **closed it** (wave 1 §21) |
| `0x10017af0 PizzeriaState` | 1,681 | in flight | — | — | — | extern only |
| `0x100d0d80 ReadData` | 1,681 | — | — | — | — | extern only |
| `0x100035e0 HandleControl` | 1,681 | — | — | — | — | extern only |

**The audit's own finding**: of the nine rows I had called "exhausted", **six
had only ever seen one generator**. Two of the three that then got a second one
moved (`StopActions` 15 → 11, `HandleEndAction` 12 → **0, landed**); the third
(`tglrl40`) did not. So "exhausted" meant "exhausted on the extern family" in
two thirds of my lane's records, exactly as the coordinator's policy point (1)
predicts — and the follow-up is 505 compiles.

### (b) Length delta — work or encoding

Answered in wave 1 §6 and now **confirmed at the program level**:

| row | Δlen | verdict | proof |
|---|---|---|---|
| `0x100ba2c0 MxStillPresenter::Clone` | −1 | encoding | **SHAPE 100 / STRUCT 100** — the strongest form of the proof: a length defect on a body that emits retail's exact program and frame |
| `0x1006fda0 HandleKeyPress` | +8 | encoding (reload + alignment) | SHAPE 98.21, the whole gap is one `mov eax,1` and one `lea ecx,[ecx]` |
| `0x1006ed90 Create` | +1 | encoding (`0x66` prefix) | SHAPE 98.71 |
| `0x100293c0 UpdateEnabledChild` | +4 | encoding (enregistered param) | §26.3 |
| `0x100a3840 CreateMesh` | −3 | encoding (enregistered param) | §26.3 — this one **flips**, wave 1 left it unsettled and called it the lane's "one genuine text row" |

**All five are encoding.** My lane has *no* row whose length delta is real work.

### (c) Do rejected text cells move SHAPE?

The one text lever that `docs/residue-taxonomy.md` records as **live** for a
`cmpdir` — `i != n` in place of `i < n` — had never been applied to the
project's closest open row. Five line-neutral cells, §28: every one is
strictly worse, and two of them break loops that currently *match* retail,
which independently establishes that retail spells all three loops `<`.

So the answer for my lane is **no** — and the reason is now provable rather
than empirical: four of my rows are SHAPE 100 / STRUCT 100 or all-levels-equal
`cmpdir`, i.e. the source text is already retail's.

### Verdicts that flipped

| row | before | after |
|---|---|---|
| `0x100a3840 CreateMesh` | "the one genuine text row in this lane" | **encoding** — an enregistered parameter, cross-TU header, recorded not attempted |
| `0x100293c0 UpdateEnabledChild` | TEXT/INLINE (triage) → COLOUR (wave 1) | **colour, confirmed**, and the mechanism is shared with `CreateMesh` |
| `0x100ba2c0 MxStillPresenter::Clone` | TEXT/INLINE (triage) | **proven colour** (SHAPE/STRUCT 100) |
| `0x100a3b40 MeshBuilderImpl::Clone` | "regrole, floor 14" | **proven colour**, and now floored in *both* carrier families |
| `0x10017af0 PizzeriaState` | "carrier-inert regrole" | **scheduling** (a 2-instruction permutation) |
| `0x1007ca30 Read` | "cmpdir, text lever unknown" | **cmpdir, text channel closed** |
| `0x1006fda0 HandleKeyPress` | SHAPE 68.24 under the shipped metric | **98.21** — the metric was wrong, not the row |

### What the coordinator should propagate

1. **Re-run every `adiff` score** taken with the shipped instrument (§26, §26.1).
   Nine asymmetries, all inflating the gap; `inliner-ledger.md` §11's
   2–5 point comparisons are inside the error bar.
2. **`SHAPE 100 && STRUCT 100` is a proof, not a score** — publish it as the
   stopping rule for the text channel. It is what four of my rows needed and
   what the campaign has never had.
3. **`cmpdir` is invisible to the three levels** (§28). Add a level, or a note.
4. **A permutation reads as SHAPE 100 *or* as a SHAPE gap** depending on whether
   the permuted instructions differ in something SHAPE keeps (§26.2). SHAPE is
   not a source/not-source discriminator on its own.

---

## 31. Closing measurements

### `Isle::Enable` — the fourth and last carrier family, negative

`sw-all2-islexpp18`: `extern_pair_with_pad`, seats pinned at the rectangle
argmin `extern-1-8`, full 30×30 pad grid, **900 states, 0 failed**.

```
0x10031820  nd=11 @pad-4-19  offsets [2206, 2209, 2212, 2215, 2218, 2220, 2222, 2224, 2226, 2231, 2233]
            lens: 3580 x 900
```

Same floor, same eleven offsets, in every state. **Every carrier family the
project has is now exhausted on this row**:

| family | states | floor |
|---|---|---|
| `extern_run_pair` (rectangle 0..40² + both strata to k=120) | 1,841 | 11 |
| `declaration_shape` over the argmin seats | 505 | 11 |
| `pad_shape` over the argmin seats | 900 | 11 |
| include-order permutation over the argmin seats | 72 | 11 |
| `declaration_run_triple` (pre- and post-include seats) | 122 | 13 |
| **total** | **3,440** | **11** |

Combined with SHAPE 100 / STRUCT 100 (§27), the position is complete: the
source is retail's, the frame is retail's, and no compiler-state carrier the
framework can express moves the seven-instruction register transposition.
**This row is finished as anything but a C2 allocator problem**, and it remains
the best-instrumented specimen in the tree because its second `LenSquared`
inline is already byte-exact.

### `Act1State::Act1State` — 3,208 states, one body

Adding the pad grid: 1,681 extern + 505 shape + 900 pad + 122 triple =
**3,208 states, one 843-byte body, every time.** Its residue is a permutation
of nine member stores whose four Playlist stores are non-contiguous on both
sides (§7), so it is neither carrier-reachable nor statement-order-reachable.

### `MxStillPresenter::Clone` — the combination that names its own problem

The shape grid: 505 states, **577 bytes in all of them**; the k-strip: 401
states, 577 in all. Retail's 576 is unreachable in either family. Yet the row
is **SHAPE 100 / STRUCT 100**.

Those two facts together are the whole diagnosis and they are only visible
because both instruments were run: the program and the frame are exactly
retail's, the single byte is `and al, 1` (2 bytes, the accumulator short form)
against our `and cl, 1` (3), and **no carrier state flips which register holds
that flag**. A row cannot be more precisely characterised than this, and there
is nothing left to try on it that this project can express.

### Stopped mid-flight at hand-off (resumable at zero cost — state objects retained)

| sweep | command |
|---|---|
| `all2-isle` plain shape grid | `sw.py all2-isle --axes shapefull --tag shape` |
| `all-mxbitmap` shape grid | `sw.py all-mxbitmap --axes shapefull --tag shape` |
| `all-legocontrolmanager` shape grid | `sw.py all-legocontrolmanager --axes shapefull --tag shape` |
| `all-legoact2` rectangle (from wave 1) | `sw.py all-legoact2 --axes base,externR --tag rect` |
| `all-infocenter` rectangle (from wave 1) | `sw.py all-infocenter --axes base,externR --tag rect` |

The corrected `adiff.py` lives at `<session scratchpad>/fin/adiff.py`, with
`ad.py` as the by-(stem, address) wrapper and `ad.py --all` scoring the whole
lane in one pass. **No source or manifest change was made in wave 2** — the
tree is exactly the merged tip plus this ledger.

---

# Wave 3 — the corrected census, published

Reset onto the merged tip `cd8692bb`. My wave-2 ledger is byte-identical in the
merge (the coordinator applied the content rather than merging the branch tip,
so my commit is not an ancestor — verified by diffing the file, not by
assuming). Baseline re-verified: `ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE:
LEGO1 4853/4934, ISLE 172/172, CONFIG 111/111`.

**Deliverable: [`docs/shape-census.md`](shape-census.md)** — SHAPE, STRUCT,
EXACT and a channel verdict for **all 81 open rows**, generated by
`<scratchpad>/fin/census.py` on the corrected `adiff`.

## 32. The headline is that the first census was mostly right

I expected, and the brief expected, that nine corrections would move a lot of
numbers. **They did not: 19 of the first census's 20 published scores reproduce
to the second decimal.** Only `LegoNavController::Notify` moves, 88.44 →
**94.42**.

The reason is worth recording because it is a general fact about the two
methods, not luck. The first census reads the **linked images**, where
relocations are resolved on both sides — so five of my nine defects, all of
which are about our COFF's relocation placeholders, cannot reach it. It had
already fixed `fs:[0]` and the disp/imm attribution independently. The one it
could not avoid is **defect 1** — switch jump tables inside a `.text` COMDAT
disassembled as code — and `Notify` has the biggest switch in the open set.

So the honest summary of this wave is: **one corrected row, one new column, and
a classifier.** Not a re-rating.

## 33. What the new column and the classifier actually changed

| change | rows | consequence |
|---|---|---|
| STRUCT column added | 13 | splits into **FRAME (decl-set)** 3 and **ENREG (same frame)** 10 |
| `cmpdir` detection | 7 | seven rows leave the "text target" list |
| `TEXT-CLOSED` tightened to require STRUCT 100 | 1 | `Helicopter::HandleControl` demoted |
| jump-table trimming | 1 | `Notify` +5.98 |
| new to `TEXT-CLOSED` | 1 | `TowTrack::HandlePathStruct` |

### Two redirections that matter more than the numbers

1. **`0x10057180 _Tree<LegoAnimPresenter*>::_Erase` is not a text target.**
   The first census ranks it third-worst in the whole open set. Its entire
   SHAPE gap is two `cmp reg,[_Nil]` sites where retail has `cmp [_Nil],reg` —
   the same defect, in the same inlined `_Tree` walk, that I closed on
   `LegoPartPresenter::Read` with five negative text cells (§28).
2. **`LegoNavController::Notify` is not the largest gap.** It is a legitimate
   text target (its divergences classify `real`, and we emit 1,183 instructions
   against retail's 1,147), but at 94.42 it ranks behind six other rows. The
   lane taking it should know the ranking that selected it was an artefact.

### And one correction to the frame census's own law

`docs/open-set-triage.md` uses `LegoAnimPresenter::CopyTransform` as the clean
specimen for *"identical `sub esp` ⇒ COLOUR. Do not transcribe."* Its `sub esp`
is identical — and its **STRUCT is 87.84 against SHAPE 98.31**, the largest
slot disagreement in the open set. An equal frame **size** does not imply an
equal frame **layout**, and CopyTransform is now the specimen for the opposite
lesson as well as its original one.

Conversely the census **independently reproduces** that document's frame
census: the three surviving rows with a differing `sub esp` are exactly the
three my `FRAME (decl-set)` bucket finds, with the same slot budgets, from an
aligned instruction diff rather than a prologue read. Two instruments, one
answer.
