# Lane INL — can a C2 inline decision be flipped at all?

Successor to Lane STL (`docs/stl-family-ledger.md` §19). Worktree
`agent-a76c38a47569ceb59`, base `7467fc53` (ancestry verified before any
work — the worktree was found stale at `31bd20de` and was reset).
Build dir `/Users/foxtacles/Projects/isle-build-inl1`.

Baseline verified in this worktree before any change:
`ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE: LEGO1 4850/4934,
ISLE 172/172, CONFIG 111/111 in 111.7s`.

**Final: LEGO1 4851/4934** — `0x100c1290 MxStreamController::~MxStreamController`
landed (§9.4b), zero LOST, ISLE and CONFIG still MD5-identical, 53 tests
green. The landing also removes the image's only function-set defect
(§9.3a), so the build-wide audit now returns zero.

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

# 9. `0x100c1290 MxStreamController::~MxStreamController` — **CLOSED**

The wave's second target. The same instrument turns the "566-byte
call-first/inline-last form" that has been sought for several sessions from
a description into a **measured signature** — and then the row closed on the
text channel (§9.4b), taking the image's only function-set defect with it.

**Result: LEGO1 4850 → 4851, zero LOST, ISLE 172/172 and CONFIG 111/111
still MD5-identical, 53 tests green.**

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
| text × carrier product (`s01_sepvar`, shape/extern/fwdE) | **317** | 317 × `'op++,erase'`; body 586/589/592, **566 never reached** |

Total for the *compiler-state* channel on this row: **1,040 compiled
states, zero signature hits, and the retail body length is not reachable in
any of them.** The row closed on the **text** channel instead (§9.4b) —
which is the campaign's standing verdict about where the leverage is, and
another case where a complete carrier negative was the signal to stop
sweeping and go read the oracle.

## 9.4 The source forms tried (first pass — all negative)

All rewrite the destructor body only; all are period-plausible and
behaviour-identical unless marked PROBE. Every one of them keeps loop 3 as
a `PopFront` loop, which §9.4b shows is the wrong premise — they vary
everything *except* the thing that mattered.

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

## 9.3a Build-wide function-set audit — there was exactly ONE defect

`fsaudit.py` walks every `.text` COMDAT of every object linked into
LEGO1.DLL and masked-searches retail's `.text` for the body (relocation
operands masked, so a body differing only in call/data targets still
matches). `fsimage.py` then promotes each miss to the image level, because
a COMDAT nobody calls is discarded by the linker and never reaches the
image.

**23 object-level misses → exactly 1 real function-set defect.** The other
22 split cleanly:

* **15 linker-discarded** — never reach LEGO1.DLL: `MxThread::SuspendThread`
  / `ResumeThread` / `TerminateThread` / `Get`+`SetThreadPriority`,
  `MxSemaphore::TryAcquire`, `MxPalette::SetPalette`,
  `MxString::CharSwap`, `LegoCacheSound::CopyFrom` / `Get`+`SetFrequency`,
  `Direct3DDeviceInfo::Direct3DDeviceInfo`, `TowTrackBitmapEmitter`,
  `EraseFirstCtrlEdge`, `EraseBEWithMidpoint`.
* **7 present in retail after all** — `Vector3::DotImpl`, `LenSquared`,
  `Vector2::AddImpl` / `MulImpl` (×2) / `DotImpl`, `Matrix4::Element`.
  These are emitted by many objects (up to 48) and *some* copies differ;
  the copy the linker selects matches retail. That is a link-selection
  question, not a function-set one, and it is not this lane's.

The single real defect was
`??Eiterator@?$list@PAVMxDSObject…::operator++(int)` — and §9.4b removed it.
**As of this lane's landing the audit returns zero.**

## 9.4a A goal-2 consequence: we emitted a function retail does not have

*(This section describes the pre-landing state; §9.4b removes it.)*

Because loop 2 inlines `erase` and then declines the nested
`iterator::operator++(int)`, our build emits an out-of-line COMDAT for it:

```
??Eiterator@?$list@PAVMxDSObject@@V?$allocator@PAVMxDSObject@@@@@@QAE?AV01@H@Z
23 bytes:  83ec04 8b01 8b10 8911 8bc8 8b442408 8908 83c404 c20800
```

A literal search finds **1 copy in our linked `LEGO1.DLL` and 0 copies
anywhere in retail's image**. It is not an unused symbol the linker could
drop — `~MxStreamController` calls it.

So this row was not only a score defect: it put an extra 32 bytes (23
aligned to 32) of `.text` into the image and displaced everything after it.
That made it a **goal-2 (byte-identity) blocker**, not just a goal-1 row.
Closing the loop-2 decision removes the function entirely — which is what
§9.4b does.

## 9.4b LANDED: `0x100c1290` closes, and the defect is gone

**Gated:** `ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE: LEGO1 4851/4934,
ISLE 172/172, CONFIG 111/111`. `GAIN 0x100c1290`, **zero LOST**.
`terminal ISLE: IDENTICAL`, `terminal CONFIG: IDENTICAL`. 53 tests pass.

The edit, in `mxstreamcontroller.cpp` (loop 3 only):

```cpp
	while (!m_unk0x54.empty()) {
		MxDSObject* object = m_unk0x54.front();
		m_unk0x54.pop_front();
		delete object;
	}
```

### Why this is retail's form, not a fitted guess

Two independent reads, neither of which is the score:

1. **BETA10 `0x1014e354` has only TWO `PopFront` loops.** Its body is
   MxTrace → AUTOLOCK → loop on `+0x1f4` → loop on `+0x200` → the
   `m_provider` block → the `m_unk0x2c` block → epilogue. The `m_unk0x54`
   loop **did not exist in June 1997**, so it is not bound to the idiom
   loops 1 and 2 use. (BETA10 also confirms our statement order and shows
   the provider block constructing a named `MxDSAction` into a frame slot.)
2. **Retail's own register allocation says loop 3 has no reference
   parameter.** Retail loop 1: `mov edx,[eax+8]` / `mov [ebp-0x18],edx` —
   the popped value is *spilled*, which is what a write through
   `PopFront`'s `T&` looks like. Retail loop 3: `mov esi,[eax+8]` — the
   value stays in a **register**, i.e. a plain local. Same function, two
   different idioms, and retail's bytes say which is which.

Mechanically it also removes one inline-nesting level
(`PopFront` → `pop_front` → `erase` → `operator++` becomes
`pop_front` → `erase` → `operator++`), which is exactly what lets C2
decline `erase` in loop 2 the way retail does.

### Verification

| check | result |
|---|---|
| body length | 586 → **566** = retail |
| masked byte distance to retail | **nd = 0** |
| frame | `sub esp` 0xa8 → **0xa4** = retail |
| signature | `op++,erase` → **`erase` @ +173 (loop 2)** = retail |
| relocation target identities (S72) | all 22 agree with retail's call sequence |
| symbol set — removed | **only** `??Eiterator@?$list@PAVMxDSObject…` (23 B) |
| symbol set — added | **none** |
| `list<MxDSObject*>::erase` (retail row 0x100c14d0, 1.0) | retained |
| `operator++` copies in linked LEGO1.DLL | 1 → **0** |
| build-wide `??Eiterator` COMDATs | 1 → **0** |

Four other loop-3 spellings also reach 566/`erase`/0xa4 or near it
(`u2_rawreuse` 575, `u4_rawsize` 566, `u5_deletefront` 573); `u1` and `u4`
are the two that hit 566, and `u1`'s `!empty()` test is the idiom the
codebase already uses. `u3_rawerase` (explicit `erase(begin())`) is much
worse at 609.

### The compose unit had to be re-derived (the "landings re-dial their TU" trap)

The TU carries a `compose_equal_body_comdat` unit for
`?FUN_100c1a00@…` on a `declaration_shape(3,30)` donor. The edit moved the
*seed*, so `expected_changed_offsets` went stale and the build refused with
`seed/donor body delta changed`. Re-derived: the **donor body sha is
unchanged** (`a573f5af…`), so the carrier state still holds; only the delta
set moved, `[62,66,69,72,78]` → `[66,69,72,78,114]`.
`expected_code_renames` (`+12 "L"`, `+424 "T"`) and the xdata rename
offsets were re-checked and are unchanged.

### Honest layout accounting — this costs alignment, and why

| metric | before | after |
|---|---|---|
| LEGO1 rows at 1.0 | 4850 | **4851** |
| address-aligned rows | 2089 | **2074** |
| terminal LEGO1 byte distance | 545273 | **545819** |

Removing a 23-byte COMDAT (32 B aligned) and shrinking the destructor by
20 B (16 B aligned) takes **48 bytes** out of `.text`. Every row from
`0x100c14d0` onward moved down by exactly 48, and the 15 rows at
`0x100cb840`–`0x100cc3c0` (mxdsselectaction.cpp) that had been
address-aligned are now off by 48. No row's *content* got worse — zero
LOST.

The useful part of that: those 15 rows were aligned **only because our
image carried 48 bytes retail does not have**. The alignment was
coincidental, propped up by the defect. The region from `0x100c14d0` was
already misaligned before the change (our recomp ~0x40 *below* retail) and
still is. So this landing does not create a layout problem — it *exposes*
one that was masked, which is what the function-set doctrine predicts and
is strictly better information for the goal-2 lane.

## 9.4c The `mxutilitylist.h` channel: measured, and refuted by the symbol-set test

Before finding the loop-3 form I tested changing `MxUtilityList::PopFront`
itself (the header is outside this lane's files, so this was measurement
only — the shadow copy in this lane's private build dir was edited and
restored). Four spellings, each scored against the target signature **and**
against the collateral (every other `PopFront` user must stay byte-identical):

| spelling | len | signature | collateral |
|---|---|---|---|
| `q0_base` (`pop_front()`) | 586 | `op++,erase` | baseline |
| `q1_erasebegin` | 610 | `op++` | 7 bodies changed in mxdiskstreamcontroller, 2 in mxdiskstreamprovider |
| `q2_iterator` (`*begin()` + `erase(begin())`) | 575 | **`erase`** | 9 bodies changed, incl. `??1MxDiskStreamController` — **an exact row** |
| `q3_size` | 586 | `op++,erase` | 5 bodies changed |
| `q4_ifelse` | 629 | `op++S,op++,op++` | 6 bodies changed |

`q2` reaches the target signature and is still **not landable**: it breaks
`MxDiskStreamController::~MxDiskStreamController` (`0x100c7530`, 1.0) and
*introduces* a fresh `??Eiterator` COMDAT into mxdiskstreamcontroller.cpp —
it moves the function-set defect rather than removing it. `q1` does the
same. This is the symbol-set test cutting both ways, and it is what sent
the search back into `mxstreamcontroller.cpp`, where the answer was.

Recorded so nobody re-opens the header: **no `PopFront` spelling tested
leaves the collateral byte-identical.**

## 9.5 What generalises from this row

The row is **closed**, so the handover is the method, not the target.

1. **A function-set defect is a source question, and it was answered by
   reading the oracle, not by sweeping.** 1,040 carrier states and 10
   source forms were all negative because they all preserved the wrong
   premise (loop 3 is a `PopFront` loop). The premise broke the moment two
   oracles were consulted: BETA10 for *when the statement was written*, and
   retail's own register allocation for *what kind of statement it is*.

2. **"Spilled vs register" is a readable source signature.** A value
   written through a `T&` out-parameter is spilled at the call site; the
   same value produced by a plain local stays in a register. Retail's loop
   1 and loop 3 differ on exactly that, in one function, which is what
   proved two different idioms were in play. This is a cheap, reusable
   discriminator for any wrapper-vs-inline question.

3. **BETA10's absences are evidence.** Lane STL §18.1 recorded "BETA10 has
   nothing usable here" for `FUN_10061010` and stopped. For this row the
   *absence* of loop 3 in BETA10 was the load-bearing fact: it freed loop 3
   from the idiom its neighbours use. An unannotated or missing construct
   in BETA10 should be recorded as a dated fact ("did not exist in June"),
   not as a dead end.

4. **The symbol-set test cuts both ways and it earned its keep here.**
   `q2_iterator` reached the target signature and would have been landed by
   a score-only gate; it breaks an exact row and relocates the defect into
   a second TU (§9.4c).

`FUN_10061010` remains open and remains the C2-stub problem (§8). Nothing
in this landing changes that bound — but it does show that a
"same-mechanism" classification is not a reason to stop looking for a text
answer, which is worth weighing against §8's recommendation.

## 10. Reproducing this lane

Everything is in the session scratchpad `.../3233884b-.../scratchpad/inl/`.
Nothing in the shared corpus was mutated. Exactly one checked-source change
was landed (§9.4b, `mxstreamcontroller.cpp` loop 3, plus the re-derived
compose pin); every other variant in this ledger was compiled out of tree.

| tool | what it does |
|---|---|
| `census.py` | whole-build `MxListEntry<T>` inline-decision census (§2) |
| `inlprobe.py` | the one-bit probe under carrier / include / `--src` text states; carrier rendering copied from `stl/sw.py` |
| `vartest.py` | compile a list of text variants, report verdict + body + `sub esp` |
| `v_anmgr.py` … `v_anmgr6.py` | batches 1–6 for `FUN_10061010` |
| `mksrc.py` | materialise the semantics-preserving variants for `--src` products |
| `rdis.py` | disassemble a retail row, naming call targets from the report |
| `odis.py` | disassemble one COMDAT of a probe object, naming relocations |
| `scprobe.py` / `v_sc.py` / `v_sc2.py` | the `~MxStreamController` loop-signature probe and its variants (`v_sc2` holds the landed form) |
| `beta2.py` | BETA10 read-off with export naming + frame-slot census |
| `fsaudit.py` | build-wide function-set audit (COMDATs absent from retail) |
| `fsimage.py` | promotes an object-level audit miss to the image level (drops linker-discarded COMDATs) |
| `popfront.py` | `MxUtilityList::PopFront` spellings with collateral accounting |
| `rederive.py` | re-derive a compose unit's pins after a source edit re-dials its TU |
| `vcheck.py` | masked byte comparison of a probe COMDAT against retail + S72 relocation listing |
| `repin_inl1.py` | accepted-row re-pin against this lane's build dir |

Build command for the baseline gate:

```sh
python3 tools/isle_build.py --build-dir /Users/foxtacles/Projects/isle-build-inl1 \
  --compiler /Users/foxtacles/Projects/MSVC420/wine/x86/cl --jobs 6
```

Note: the worktree needs `legobin` symlinked to the main checkout's
`legobin/` before `isle_build.py` will run; it is left untracked.

