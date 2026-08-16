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
