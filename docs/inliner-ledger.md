# Lane INL — can a C2 inline decision be flipped at all?

Successor to Lane STL (`docs/stl-family-ledger.md` §19). Worktree
`agent-a76c38a47569ceb59`, base `7467fc53` (ancestry verified before any
work — the worktree was found stale at `31bd20de` and was reset).
Build dir `/Users/foxtacles/Projects/isle-build-inl1`.

Baseline verified in this worktree before any change:
`ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE: LEGO1 4850/4934,
ISLE 172/172, CONFIG 111/111 in 111.7s`.

Tooling (session scratchpad `.../3233884b-.../scratchpad/inl/`):
`census.py` (whole-build inline-decision census), `inlprobe.py` (the
one-bit probe under carrier / include / text states; carrier rendering
copied verbatim from `stl/sw.py` so state labels mean the same thing and
any hit is landable through the same recipe kinds).

---

## 1. The premise, re-verified independently and more strongly

Lane STL read "retail has no row for `MxListEntry<LegoTranInfo*>`" out of
the reccmp report. A missing *row* could be a missing annotation, so I
checked the image instead.

The 3-argument ctor for any pointer instantiation compiles to the same
25 bytes:

```
8b 44 24 04   mov eax,[esp+4]        ; p_obj
8b 54 24 08   mov edx,[esp+8]        ; p_prev
89 01         mov [ecx],eax
89 51 04      mov [ecx+4],edx
8b 44 24 0c   mov eax,[esp+0xc]      ; p_next
89 41 08      mov [ecx+8],eax
8b c1         mov eax,ecx
c2 0c 00      ret 0xc
```

A literal search of `legobin/LEGO1.DLL` finds **exactly three** copies of
that byte string in the whole image:

| RVA | instantiation |
|---|---|
| 0x1004eb20 | `LegoPhoneme*` |
| 0x1006ea00 | `LegoROI*` |
| 0x100c5a20 | `MxSpan*` |

There is **no fourth copy anywhere in retail**. So the premise is stronger
than "no row": retail's image genuinely contains no out-of-line
`MxListEntry<LegoTranInfo*>` ctor. (`MxListEntry<MxString>` at 0x100cc3c0
is a different, 130-byte body — MxString has a real copy ctor and EH.)

## 2. The dataset is NINE sites, not five — and our build already inlines four

`census.py` walks every object in the build, pairs each `MxListEntry<T>`
3-arg ctor COMDAT with the `.text` sections that emit a CALL relocation to
it, and claims the INLINED direction only where the object proves a
construction site exists (it defines `MxList<T>::InsertEntry` out of line).

| object | T | verdict | ctorB | out-of-line `InsertEntry` | declining caller |
|---|---|---|---|---|---|
| legoanimationmanager.cpp | `LegoTranInfo*` | DECLINED | 25 | — | `FUN_10061010` |
| legophonemepresenter.cpp | `LegoPhoneme*` | DECLINED | 25 | — | `StartingTickle` |
| legoanimpresenter.cpp | `LegoROI*` | DECLINED | 25 | — | `AppendROIToScene` |
| mxregion.cpp | `MxSpan*` | DECLINED ×3 | 25 | 161B | `AddRect` |
| mxdsselectaction.cpp | `MxString` | DECLINED | 130 | 230B | `InsertEntry` |
| legoworld.cpp | `LegoCacheSound*` | **INLINED** | — | 161B | — |
| legoworld.cpp | `LegoEntity*` | **INLINED** | — | 161B | — |
| legoworld.cpp | `MxPresenter*` | **INLINED** | — | 161B | — |
| mxregion.cpp | `MxSegment*` | **INLINED** | — | 161B | — |

**Lane STL's §19.2 table ("declines at 5 of 5 sites") is incomplete**: it
enumerated only the five instantiations that emit a ctor COMDAT, so the
four instantiations where our own build *takes* the inline were invisible
to it. Our C2 does inline this body — routinely.

Correction of record: §19.2 lists the `LegoPhoneme*` ctor as `PAU…`; it is
`PAV` (`LegoPhoneme` is a class). My first probe run inherited that typo
and reported a spurious INLINED for legophonemepresenter; fixed before any
sweep was launched.

### 2.1 `mxregion.cpp` decides BOTH WAYS inside a single compile

This is the sharpest specimen in the dataset. One object, one compile
state, one 25-byte callee:

* `?InsertEntry@?$MxList@PAVMxSpan@@…` (161 B) emits **no** ctor
  relocation → it **inlined** the ctor;
* `?AddRect@MxRegion@@…` (1157 B) emits **three** ctor relocations → it
  **declined** the ctor three times, and additionally left two
  `InsertEntry` calls out of line.

So the decision is neither per-callee, nor per-TU, nor per-compile-state.
It is per-expansion-site, and it varies *within one function*.

### 2.2 The law that fits all nine sites

The ctor is inlined **iff the expansion that encloses it is the
out-of-line `MxList<T>::InsertEntry` body**, and declined whenever
`InsertEntry` itself was inlined into a larger caller first:

* the four INLINED sites are all inside a 161-byte out-of-line
  `InsertEntry` (ctor at nesting depth 1);
* legoanimationmanager / legophonemepresenter / legoanimpresenter emit
  **no** out-of-line `InsertEntry` at all — `Append` → `InsertEntry` were
  both expanded into the caller, so the ctor sat at depth ≥ 2 and was
  refused;
* `AddRect` shows both regimes side by side, exactly as the law predicts.

Depth alone is not sufficient, and the dataset says so: the
`mxdsselectaction` site is at depth 1 (inside the out-of-line
`MxList<MxString>::InsertEntry`) and is still declined — but there the
callee is 130 bytes, not 25. So the rule is a *budget* consumed both by
callee size and by the enclosing expansion, which is the classic shape.

## 3. Retail agrees with us at eight of the nine sites

Masked search of retail for our 161-byte out-of-line `InsertEntry` body
(relocation operands masked) finds **four** copies —
`0x10022380`, `0x10022430`, `0x100224e0` (legoworld) and `0x100c5970`
(mxregion) — the same four our build emits, and the reccmp report scores
all four at 1.0.

So retail did **not** reach its `FUN_10061010` inline by keeping
`InsertEntry` out of line there: retail, like us, expanded
`Append` → `InsertEntry` into `FUN_10061010` and *then* took the 25-byte
ctor at that depth as well. This closes off the one structural
explanation that would have made the row easy.

Cross-check that the model is not overfitted: `MxRegion::AddRect`
(`0x100c3750`) is an open row at **0.9739**, and its residue is classified
as pure register colour (`docs/residue-taxonomy.md`: regrole=10, same
length 1157, same frame). A pure-colour residue means retail's `AddRect`
made *exactly* our inline decisions — three declines plus two out-of-line
`InsertEntry` calls. Retail and our build therefore agree at eight of nine
sites and differ only at `FUN_10061010`, which is precisely Lane STL's
one bit of signal, now resting on a nine-site dataset instead of five.

## 4. The observable used from here

Per compiled object, per state, one bit:

* a CALL relocation to the ctor COMDAT ⇒ **DECLINED** (sound direction);
* no ctor COMDAT while the caller section is present ⇒ **INLINED**.

No body distance, no `nd`, no oracle — so a state costs one compile and
one COFF parse.

## 4.1 The site region is instruction-identical to retail

Ours (`ip-anmgr/base-0/o.obj`) against retail `0x10061010`, from the inner
cursor's construction to the `operator new`, every instruction pairs up
with a uniform +11 byte / −4 frame-offset shift. The *only* divergence in
the whole region is the construction itself:

```
OURS   500 push 0            502 mov eax,[ebp-0x10]  505 push esi
       506 mov ecx,edi       508 push eax            509 call ??0MxListEntry…   (14 B)
RETAIL 511 mov eax,[ebp-0x14] 514 mov [edi],eax      516 mov eax,edi
       518 mov [edi+4],esi   521 mov [edi+8],0                                   (17 B)
```

Retail's inlined Find loop (`+429..+466`) is instruction-for-instruction
ours (`+418..+455`), including the virtual `call [esi+0x14]`. So our
source text at this site is right, retail expands exactly the same set of
inlines except this one, and the entire remaining +14 bytes / +3 slots of
the row is downstream of that single decision.

---

# THE ANSWER

**YES — the decision at `FUN_10061010` can be flipped, and I flipped it
four times.** It is not a fixed property of the callee, the TU, or the
compile state. What I could NOT do is flip it with any *legitimate*
change: every semantics-preserving form and every compiler-state carrier
leaves it declined. Both halves are measured, and both are below.

## 5. The flip is real — four caller-side forms take the inline

Same TU, same instantiation, same build; only the text of the enclosing
`else` arm differs. Verdict read off the ctor COMDAT + call relocations.

| variant | what changed | verdict | caller B |
|---|---|---|---|
| `v00_base` | — | DECLINED | 717 |
| `v09_PROBE_nocursor` | inner cursor + `Find` deleted | **INLINED** | 556 |
| `v10_PROBE_bare` | site reduced to a bare `Append` | **INLINED** | 552 |
| `t_orig__e_cursor_nofind` | cursor **constructed and EH-live**, `Find` not called | **INLINED** | 662 |
| `p05_hasmatch` | `if (!cursor.HasMatch())` in place of `Find` | **INLINED** | 668 |

All four change behaviour and none is landable. Their value is that they
prove the capability and localise the mechanism.

### 5.1 The margin is one live pointer — measured to the byte

The sharpest pair in the whole lane. Both are one-line inline accessors on
the same cursor object, neither has a loop, neither makes a call:

```cpp
MxBool HasMatch() { return m_match != NULL; }                 -> INLINED (668 B)
MxBool Head() { m_match = m_list->m_first; return m_match != NULL; }
                                                              -> DECLINED (672 B)
```

The only difference is that `Head()` dereferences `m_list`. One extra live
pointer at the site is the entire margin between taking and refusing the
25-byte inline. That is why `Find` — which loads `m_list`, loads its
vtable and calls through it — refuses so decisively.

## 6. Four models refuted, each by measurement

**(a) "An EH-tracked object in scope forbids the inline."** Refuted:
`e_cursor_nofind` keeps `LegoTranInfoListCursor cursor(m_tranInfoList2)`
constructed, in scope and EH-registered at the site, and the ctor is
INLINED.

**(b) "Budget consumed in source order before the site."** Refuted twice:

| probe | site position | verdict |
|---|---|---|
| `p02_find_after` | `Append` written **before** `Find` | DECLINED |
| `p07_append_before_cursor` | `Append` written before the cursor is even **constructed** | DECLINED |

The decision is made with knowledge of the whole enclosing region, not of
what precedes the site.

**(c) "Upstream expansion in the same function consumes the budget."**
Refuted: gutting the accessor chain (`t_PROBE_shortchain`, −21 B) and
deleting both `BackgroundAudioManager()->RaiseVolume()` blocks
(`t_PROBE_noraise`, −75 B) both leave it DECLINED.

**(d) "It is TU-global — the two sites that DO inline (lines 1019, 1086)
precede the declining one."** Refuted, and cleanly: the whole
`#ifdef BETA10 … #endif` block for `FUN_10061010` was moved to four
positions in the TU — first definition, before `FUN_100609f0`, base, and
last — and the emitted body is **byte-identical at 717 in all four**. The
decision is strictly function-local; function position is inert.

## 7. Bounded negatives — the legitimate channels are closed

Every state below was compiled; none is an inference. Each sweep ran to
completion (`0 failed`), so these are uniform samples, not partial passes
of an ordered axis.

### 7.1 Carrier lattice — 1,284 states, zero flips

| TU | axes | states | result |
|---|---|---|---|
| `legoanimationmanager.cpp` | shape 60, padgrid 144, extern 161, fwdL 96, fwdP 96, fwdE 96, **inc 60** | **713** | 713 DECLINED |
| `mxregion.cpp` | same | **654** | 654 DECLINED |

Include-order permutation is inside the `inc` axis, so the brief's second
channel is covered here and is negative on both TUs.

Two by-products worth recording:

* the carrier is not inert on `legoanimationmanager` — it moves
  `FUN_10061010`'s body (717 in 684 states, 725 in 29) — it just never
  moves the bit;
* the carrier **is** inert on `MxRegion::AddRect`: 1157 bytes in all 654
  states. `AddRect` (`0x100c3750`, .9739) is listed in
  `docs/open-set-triage.md` as `0 — UNSWEPT`; it is now swept on 654
  states with zero body movement, which retires the carrier channel for
  that row.

### 7.2 Semantics-preserving caller-side forms — 19 forms, zero flips

All at `sub esp = 0x2c` (retail 0x38), bodies 709–774.

| batch | forms | result |
|---|---|---|
| 1 | `findbool`, `cursor2` (rename, no shadowing), `localptr`, `flagfirst`, `eqfalse`, `guard` (early-continue), `objlocal`, `appendafter` | 8 DECLINED |
| 2 | `scopedfind` (cursor destroyed before the site, `found` bool carried out) | 1 DECLINED |
| 4 | `flagsvalue` (§18.3 h1), `refs` (§18.3 h2), `testonce`, `flagsptr`, `presenterlocal`, `testonce_presenter` | 6 DECLINED |
| 6 | `declswap`, `forloop`, `outerdecl`, `earlyout` | 4 DECLINED |

Batch 4 re-reads Lane STL §18.3's hoist forms against the *inline* bit
rather than `sub esp`, and adds four closer reconstructions of retail's
§18.2 shape (the `c_bit2` test evaluated once above the branch, `&m_flags`
and `&m_unk0x14` held). **None of them moves either the frame or the bit.**
§18.3's "naming a value does not create a lifetime" now has a second,
independent confirmation: it does not create an inline decision either.

### 7.3 Text × carrier product — the last untested region

The carrier sweep ran on base text; the text forms ran on the base
carrier. The product is a genuinely different region because each text
form is a different compile state (bodies 709–717).

| base text | axes | states | result |
|---|---|---|---|
| `h02_refs` (711 B) | shape 60, extern 161, fwdE 96 | **317** | 317 DECLINED |
| `h06_testonce_presenter` (709 B) | shape 60, extern 161, fwdE 96 | **317** | 317 DECLINED |

**634 product states, zero flips.** Both products moved the body in three
states each (711→719, 709→717) and the bit in none.

### 7.4 The `mxlist.h` channel is closed by construction

§5.1 says the live-value set at the site is what decides, and the only
remaining source location that could change it is
`MxListCursor<T>::Find` itself. It cannot be touched:

* `MxListCursor<LegoCacheSound*>::Find` (`0x10022590`) is an **out-of-line
  row at 1.0** — retail's `Find` body is pinned exactly;
* `LegoAnimationManager::FUN_10061530` (`0x10061530`) is at **1.0** and
  uses `Find` *inlined*, on `m_tranInfoList2`, in the same TU — retail's
  inlined expansion of `Find` is pinned exactly too.

Any respelling of `Find` that changed its expansion would break one or
both. So the last source location with leverage over the site's live-value
set is unavailable, and that closes the argument rather than leaving it
open.

### 7.5 The model checks out against every enclosing function's score

| enclosing function | site verdict (ours) | row |
|---|---|---|
| `MxList<MxPresenter*>::InsertEntry` 0x10022380 | INLINED | **1.0** |
| `MxList<LegoEntity*>::InsertEntry` 0x10022430 | INLINED | **1.0** |
| `MxList<LegoCacheSound*>::InsertEntry` 0x100224e0 | INLINED | **1.0** |
| `MxList<MxSegment*>::InsertEntry` 0x100c58c0 | INLINED | **1.0** |
| `MxList<MxSpan*>::InsertEntry` 0x100c5970 | INLINED | **1.0** |
| `MxList<MxString>::InsertEntry` 0x100cc2d0 | DECLINED | **1.0** |
| `LegoPhonemePresenter::StartingTickle` 0x1004e3d0 | DECLINED | **1.0** |
| `LegoAnimPresenter::AppendROIToScene` 0x100698b0 | DECLINED | **1.0** |
| `LegoAnimationManager::FUN_100609f0` 0x100609f0 | INLINED | **1.0** |
| `MxRegion::AddRect` 0x100c3750 | DECLINED ×3 | 0.9739, pure regrole, same length + frame |
| `LegoAnimationManager::FUN_10061010` 0x10061010 | DECLINED | **0.5411** |

Every function that contains a site is byte-exact except `AddRect` (whose
residue is register colour, so its inline decisions match retail) and
`FUN_10061010`. The dataset really is one differing bit, and it is this
row.

## 8. What this means for the project

1. **`FUN_10061010` (0x10061010, .5481) is not reachable from any channel
   this project currently has.** Carrier (713 states), include order (in
   the 60 `inc` states), caller-side source form (19 semantics-preserving
   forms), function position (4), and the text × carrier product (634)
   are all negative, and the row's entire residue is downstream of the one
   decision. Lane STL §18.4's "stop spending source variants on this row"
   is confirmed with a much larger bound, and §19.4's "build the C2 stub
   first" is the right next step — but §5.1 now gives that stub a much
   sharper validation target than five sites: it must reproduce
   `HasMatch` → inline and `Head` → decline, a one-pointer margin.

2. **The register/stack colouring class does not inherit a lever from
   here.** The inline decision responds only to changes in the live-value
   set at the site — i.e. to the same register pressure that the colouring
   class is made of. It is a symptom of the allocator state, not an
   independent dial on it.

3. **`MxRegion::AddRect` should be moved out of the `0 — UNSWEPT` column**
   of `docs/open-set-triage.md`: 654 carrier states, body invariant.

4. **Do not re-derive the census.** Nine sites, four already inlined by us,
   eight of nine agreeing with retail; `census.py` reproduces it from any
   build directory in one pass.

---

# 9. `0x100c1290 MxStreamController::~MxStreamController`

The wave's second target. The same instrument applies, and it turns the
"566-byte call-first/inline-last form" that has been sought for several
sessions from a description into a **measured signature**.

## 9.1 What the row actually is

`MxUtilityList<T>::PopFront` calls `pop_front()` → `erase(begin())`, and
MSVC 4.2's `erase(iterator _P)` opens with `(_P++)._Mynode()` — so every
`PopFront` loop carries a *nested* pair of inline candidates:
`list<T>::erase`, and `iterator::operator++(int)` inside it.

The destructor has three such loops:

| loop | member | size field | our build | retail |
|---|---|---|---|---|
| 1 | `m_subscribers` (`list<MxDSSubscriber*>`) | `+0x38` | erase inlined, `++` inlined | same |
| 2 | `m_unk0x3c` (`list<MxDSObject*>`) | `+0x44` | erase **inlined**, `++` **CALLED** | erase **CALLED** |
| 3 | `m_unk0x54` (`list<MxDSObject*>`) | `+0x5c` | erase **CALLED** | erase inlined, `++` inlined |

Read off the objects: our destructor's relocation signature is
`op++@173, erase@371`; retail calls `list<MxDSObject*>::erase`
(`0x100c14d0`) once, at `+172`, and inlines the unlink + `operator delete`
+ `dec [ecx+0x5c]` in loop 3 at `+320..+357`.

So "call-first / inline-last" is exact and now has a byte-level
definition: **one `erase` call in loop 2, none in loop 3, no
`operator++` call anywhere.** Target signature `'erase'`, body 566.

Frame: retail `sub esp, 0xa4`, ours `0xa8`. The extra 4-byte slot is
accounted for: our out-of-line `operator++(int)` needs a returned-iterator
temporary at `[ebp-0x24]` *in addition to* the iterator at `[ebp-0x18]`,
where retail's out-of-line `erase` needs only its return slot
(`[ebp-0x20]`). The +1 slot budget is a consequence of the loop-2
decision, not an independent defect — the same "frame is downstream"
relation established for `FUN_10061010`.

## 9.2 The `mxutilitylist.h` / STL channel is closed by construction

`MxDiskStreamController::~MxDiskStreamController` (`0x100c7530`) is at
**1.0** and contains three `PopFront` loops on the *same*
`list<MxDSObject*>` instantiation. Read off our object: it calls
`list<MxDSObject*>::erase` out of line at **all three** loops (offsets
150, 258, 308) and never inlines it.

That is a byte-exact retail row exercising the identical construct, so:

* `MxUtilityList<T>::PopFront`'s source shape is pinned — any respelling
  that changed its expansion would break `0x100c7530`;
* `MSVC420/include/LIST` is vendor code and out of bounds anyway;
* and it independently confirms the model: retail's C2 declines `erase` in
  a plain three-loop destructor and only inlines it where the surrounding
  pressure is low enough.

## 9.3 Bounded negatives for this row

| channel | states | result |
|---|---|---|
| carrier lattice (shape 60, padgrid 144, extern 161, fwdL/fwdP/fwdE 288, inc 60) | **713** | 713 × `'op++,erase'`; body 586 (588), 589 (115), 592 (10) — **566 never reached** |
| caller-side source forms (§9.4) | 10 | 10 × `'op++,erase'`, `sub esp` 0xa8 in all |
| text × carrier product (`s01_sepvar`, shape/extern/fwdE) | 317 | see §9.5 |

## 9.4 The source forms tried

All rewrite the destructor body only; all are period-plausible and
behaviour-identical unless marked PROBE.

| form | len | signature | note |
|---|---|---|---|
| `s00_base` | 586 | `op++,erase` | control |
| `s01_sepvar` | 592 | `op++,erase` | separate `MxDSObject* object` for loop 3 |
| `s02_topdecl` | 586 | `op++,erase` | all locals declared at function top |
| `s03_topdecl_sep` | 592 | `op++,erase` | both of the above |
| `s04_forloops` | 586 | `op++,erase` | `for (; PopFront(x);)` spelling |
| `s05_compat` | 592 | `op++,erase` | the `COMPAT_MODE` named-`MxDSAction` provider block |
| `s06_compat_sep` | 591 | `op++,erase` | s05 + s01 |
| `s07_blockscoped` | 592 | `op++,erase` | each loop's local in its own block |
| `s08_PROBE_notrace` | 586 | `op++,erase` | `MxTrace` removed — byte-identical, so `MxTrace` is already inert under NDEBUG |
| `s09_PROBE_loopsadjacent` | 586 | `op++,erase` | the two `MxDSObject` loops made adjacent |

The `+1` slot hypothesis (retail declares a second `MxDSObject*`, costing
exactly the one extra slot) is **refuted**: `s01`/`s03`/`s07` all declare
the second local and all keep `sub esp` at 0xa8 while growing the body by
6 bytes. This is the named-local rule again (`project-named-local-rule.md`,
STL §13.2a/§18.3) — naming a value does not create a slot.

## 9.5 Handover for this row

The row is now characterised the way `FUN_10061010` was:

* the residue is **two inline decisions**, in loops 2 and 3, on the same
  instantiation, in one function;
* the `+1` frame slot is downstream of loop 2's decision, not a target;
* the source text is right (retail's loop order and member offsets match
  ours exactly: 0x38 → 0x44 → provider 0x28 → 0x5c);
* the header that would change the expansion is pinned by a byte-exact row
  using the identical construct;
* and the carrier lattice does not reach retail's length in 713 states.

Anyone continuing should treat it as the *same* problem as
`FUN_10061010`, not a separate one, and validate the C2 stub against both:
a model must reproduce "decline `erase` in loop 2, take it in loop 3" here
and "decline the ctor at `FUN_10061010`, take it at `FUN_100609f0`" there.

## 10. Reproducing this lane

Everything is in the session scratchpad `.../3233884b-.../scratchpad/inl/`.
Nothing in the shared corpus was mutated and **no checked source was
changed** — every variant in this ledger was compiled out of tree.

| tool | what it does |
|---|---|
| `census.py` | whole-build `MxListEntry<T>` inline-decision census (§2) |
| `inlprobe.py` | the one-bit probe under carrier / include / `--src` text states; carrier rendering copied from `stl/sw.py` |
| `vartest.py` | compile a list of text variants, report verdict + body + `sub esp` |
| `v_anmgr.py` … `v_anmgr6.py` | batches 1–6 for `FUN_10061010` |
| `mksrc.py` | materialise the semantics-preserving variants for `--src` products |
| `rdis.py` | disassemble a retail row, naming call targets from the report |
| `odis.py` | disassemble one COMDAT of a probe object, naming relocations |
| `scprobe.py` / `v_sc.py` | the `~MxStreamController` loop-signature probe and its variants |

Build command for the baseline gate:

```sh
python3 tools/isle_build.py --build-dir /Users/foxtacles/Projects/isle-build-inl1 \
  --compiler /Users/foxtacles/Projects/MSVC420/wine/x86/cl --jobs 6
```

Note: the worktree needs `legobin` symlinked to the main checkout's
`legobin/` before `isle_build.py` will run; it is left untracked.

