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

# 11. Wave 3 — the allocation lens applied, and the instrument that was missing

Base `e880d515`, verified before any change:
`ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE: LEGO1 4851/4934,
ISLE 172/172, CONFIG 111/111`.

## 11.1 `adiff.py` — the metric these rows were never scored with

Every prior wave on `FUN_10061010` scored source variants by **body length**
and **`sub esp`**. The ledgers say repeatedly that length is not the metric,
and §7.2 showed `sub esp` was pinned across 19 forms — so both signals were
flat and every variant read as "no change". They were not no-change.

`adiff.py` aligns our COMDAT against the retail row with `difflib` (so it
works across a length mismatch) and reports three levels:

| level | erases | answers |
|---|---|---|
| SHAPE | registers, frame displacements, relocated/absolute operands | is our source producing retail's *program*? |
| STRUCT | registers only | …and retail's frame layout? |
| EXACT | nothing but relocation/branch operands | …and retail's colouring? |

Masking has to be symmetric or the alignment is noise: a relocated operand
is a zero placeholder in our COFF and a resolved address in retail. Three
normalisation bugs were found and fixed while building it (bare-zero
relocations unmasked; `[ecx+0x4c]` mistaken for a frame slot; `0xfffffffd`
mistaken for an image address; absolute memory operands unmasked). **No
number in this section predates those fixes.**

## 11.2 `FUN_10061010` — two improvements that anti-compose, and the frame moves

Scored against retail (731 B, 211 insn). Base: SHAPE 92.12, STRUCT 67.30,
EXACT 62.53.

| variant | SHAPE | STRUCT | EXACT | `sub esp` |
|---|---|---|---|---|
| base | 92.12 | 67.30 | 62.53 | 0x2c |
| `h01_flagsvalue` — `MxU32 flags = tranInfo->m_flags;` hoisted above the branch | **94.74** | 72.73 | 62.20 | 0x2c |
| `h03_testonce` — `MxBool raise = … & c_bit2;` hoisted | 93.56 | 71.60 | 64.92 | 0x2c |
| `v04_flagfirst` — `animRunning = TRUE;` first in the else arm | 91.65 | **73.03** | **67.78** | **0x30** |
| `h01` + `v04` | 94.26 | 69.38 | 60.29 | 0x30 |
| `h03` + `v04` | 93.08 | 68.26 | 62.53 | 0x30 |

Three results, none of which the length/`sub esp` metric could see:

1. **The upstream hoist is a real improvement** — `h01` moves SHAPE by 2.6
   points, i.e. it makes us emit more of retail's actual operations. Lane
   STL §18.3 tested this exact form and recorded "neither moves the frame
   by a single byte", which was true and beside the point.
2. **`sub esp` is NOT pinned at 0x2c.** `v04_flagfirst` — moving
   `animRunning = TRUE;` to the top of the else arm — takes the frame to
   **0x30**. Retail is 0x38. This is the first movement of that frame in
   the campaign; §7.2's "0x2c across 19 forms" is superseded.
3. **The two improvements anti-compose.** `h01`+`v04` is EXACT 60.29,
   *worse than either alone and worse than base*. They are not independent
   corrections that can be stacked, which contradicts the campaign's
   "text corrections compound" doctrine for this row.

The remaining SHAPE gap for `h01` is entirely the held addresses: retail
spills `&m_unk0x14`, keeps `m_flags`' value in `ebx`, and reloads the
spill twice. Retail also computes `mov eax,ebx; and al,2` and **never uses
the result** — dead code at /O2, which is the signature of a named boolean
whose uses were folded into flag re-tests, i.e. `h03`'s form.

**Nothing landed on this row.** `v04` buys EXACT at the cost of SHAPE —
that is fitting to the metric, not source truth — and the row needs ~38
more points of EXACT to close. Recorded as characterisation.

## 11.3 `ViewManager::ManageVisibilityAndDetailRecursively` (0x100a66f0, .8848)

`docs/residue-runs.md` records this as one `cmpdir` byte at +517 surviving
~7,800 carrier states. adiff on the seed says the seed's own divergence
starts at **+309**, inside the inlined `CalculateLODLevel`:

```
ours    cmp [g_maxLODLevels], esi ; jle …  fld [esp+0x10]; fld [esp+0x18]
        fld st(1); fcomp st(1); fnstsw ax; test ah,1;    je
retail  cmp esi, [g_maxLODLevels] ; jge …  fld [esp+0x18]; jmp INTO the loop
        fstp [esp+0x10]; fcom [esp+0x10];  test ah,0x41; jne
```

Reading the allocation: retail keeps `p_maximumScale` in `st0` across the
loop and `i` in memory, and enters the loop with a `jmp` past the first
store — the shape of a loop whose exit test is the **loop condition**, not
a `break` inside the body. Ours loads both operands every iteration, the
shape of a `break`.

**Result — the break folded into the loop condition reaches retail's exact
length and jumps 4 points:**

| variant | len | SHAPE | STRUCT | EXACT |
|---|---|---|---|---|
| base (`if (i >= p_maximumScale) break;`) | 557 | 94.27 | 94.27 | 92.71 |
| `a1_swapcmp` `p_maximumScale <= i` | 557 | 94.27 | 94.27 | 92.71 |
| `a2_ioutside`, `a3`, `a5_mulswap`, `a6_muleq`, `a7_intswap` | 557 | 94.27 | 94.27 | 92.71 |
| **`a4_whilecond`** — `lodLevel < g_maxLODLevels && p_maximumScale > i` | **561** | **97.92** | **97.92** | **96.35** |

Every comparison-*spelling* variant is bit-identical to base, which
independently re-confirms the standing canonicalisation law. Only the
structural change moves anything.

At retail's length the masked residue is **nd=7** at
`[204, 239, 309, 319, 353, 359, 396]` — three iterator-loop compares
(`cmp it, end` where retail has `cmp end, it`) and two LOD-loop
compare+branch pairs. Crossing `a4` with the end-first and int-swapped
spellings (8 combinations) is **completely inert**: all eight are
97.92/97.92/96.35. So the residue is allocator, not source.

### 11.3a …and it lands on exactly the same floor — NOT LANDED

A full carrier sweep over the `a4` text (659 states: shape, padgrid,
extern, fwdL/fwdP/fwdE, inc; 0 failed) floors at

```
best: nd=1 @ pad-1-4, offsets [517]
```

**The same nd and the same byte** as the base text's ~7,800-state search.
Two structurally different source forms, ~8,500 carrier states between
them, one shared floor on one byte. That is a considerably stronger bound
than the row had before, and it is the *right* kind of evidence for the
"one shared allocator decision" reading: it is now text-invariant as well
as carrier-invariant.

**Not landed, for a reason worth recording.** `a4` also changes
`ViewManager::UpdateViewTransformations` (442 B, body sha
`b583423bfc` → `942a0daedc`), and that row is at **1.0**. So the trade is
"risk an exact row, gain nothing" — the floor does not move. This is the
collateral test from §9.4c applied to body *content* rather than symbol
presence, and it is the second time this wave that a variant which looked
like an improvement failed it.

## 11.4 `MxDSBuffer::FUN_100c6fa0` (0x100c6fa0, .9882) — read, tested, negative

adiff: **84 of 85 instructions align**. The entire residue is one load
moved by one slot:

```
ours    cmp [esp+0xc], edx   mov eax, [esp+0xc]
retail  mov eax, [esp+0xc]   cmp [esp+0xc], edx
```

`current` is `MxU8* volatile`, so those two reads cannot be reordered by
the optimiser — their order **is** the source order. Retail evaluates the
address expression for the size read before the comparison; we evaluate the
comparison first. `docs/residue-runs.md` had tested `p_data == current` and
inverting the `if` (both inert — consistent, since neither moves a read)
and hoisting to *function* scope (worse, +4 bytes for a slot). The
untested move was hoisting into the case's own **block**, which costs no
slot:

| variant | len | SHAPE/STRUCT/EXACT | note |
|---|---|---|---|
| base | 234 | 98.82 | — |
| `c4_blockonly` | 234 | 98.82 | the block itself is free — byte-identical to base |
| `c5_hdrptr` `MxU32* header = (MxU32*) current` | 238 | **99.42** | best shape, +4 bytes |
| `c2_sizevalue` value hoisted into the block | 238 | 98.25 | fixes +161, breaks later |
| `c3_chunk` | 236 | 98.25 | |
| `c1_sizeptr` | 240 | 97.67 | |

So the read order **is** reachable from the source, and every form that
reaches it costs at least 4 bytes — a slot for the hoisted name. Same law
as §9.4b's refutation and `docs/residue-runs.md`'s: naming a value creates
a slot, not a lifetime. Nothing landed.

## 11.5 `MxDisplaySurface::Create` (0x100ba7f0, .9953) — one instruction

adiff: **211 of 212 aligned (99.53%)**. A single `inc eax` sits one slot
later in ours:

```
ours    mov eax,[esi+0x10]; sub eax,[esi+8]; mov [esp+0x84],0x6040; inc eax
retail  mov eax,[esi+0x10]; sub eax,[esi+8]; inc eax; mov [esp+0x84],0x6040
```

The independent `ddsCaps.dwCaps = 0x6040` store is scheduled into the slot
after `sub` in ours and after `inc` in retail. `docs/residue-runs.md`
already tested all four statement orderings of that block (nd 15/18/22/23
against baseline 9). Confirmed as one scheduler placement, not a
statement-order question; no new lever found.

## 11.6 `MxDisplaySurface::VTable0x30` (0x100bb1d0, .8611)

adiff separates this row's two problems, which the byte metric had merged:
**SHAPE 96.43 but EXACT 73.81** — a small shape gap sitting on top of a
large colour gap (the taxonomy's 27 regrole sites).

The shape gap appears twice and looked source-addressable:

```
ours    mov r,[esp+0x98]; imul r,[esp+0x28]; …; add r,[esp+0x3c]
retail  mov r,[esp+0x28]; imul r,[esp+0x98];    add r,[esp+0x3c]
```

— the two factors of `p_bottom * ddsd.lPitch` loaded in the opposite
order. Six variants (swap either site, swap both, reorder the addends,
both) at lines 547/573 — the only two occurrences inside this function —
are **all bit-identical to base**: 811 B, 96.43/96.43/73.81.

**So integer `imul` operand order canonicalises, exactly as comparison
direction does.** That corrects my own hypothesis for this row and is the
generalisation in §11.7.

## 11.7 What the lens can and cannot name — refined by this wave

Wave 2 established "read retail's allocation to name the idiom". This
wave bounds it. Across four rows and ~40 source forms:

**Canonicalised — operand order of a reversible operation is NOT source
addressable.** Every one of these was bit-inert:

* integer comparison direction (`lodLevel < max` vs `max > lodLevel`);
* FP comparison direction (`i >= pmax` vs `pmax <= i`);
* iterator comparison direction (`it != end` vs `end != it`) — re-confirmed
  on a second, structurally different text;
* integer multiplication operand order (`a * b` vs `b * a`);
* addend order in an address expression.

**Addressable — the shape of the program is.** These moved things:

* folding a `break` into the loop condition (`a4`: +4 bytes to retail's
  exact length, EXACT 92.71 → 96.35);
* replacing a wrapper call with the operations it performs (wave 2's
  `PopFront` → raw list loop, which closed a row);
* hoisting an expression across a branch (`h01`: SHAPE 92.12 → 94.74);
* moving a statement between arms (`v04`: the first movement of
  `FUN_10061010`'s frame in the campaign, 0x2c → 0x30).

The rule that follows: **when the allocation names a difference in operand
order, it is telling you about the scheduler, not the source. When it
names a difference in which operations exist, or where a value lives
across a branch, it is telling you about the source.** The wave-2 win was
the second kind; three of this wave's four rows are the first kind, which
is why they did not move.

# 12. Wave 4 — re-scoring the campaign's recorded negatives under SHAPE

Base `3804e1b5`, verified before any change: `LEGO1 4851/4934, ISLE 172/172,
CONFIG 111/111`.

## 12.1 Neither metric dominates — and my first statement of this was wrong

**Correction, recorded because it was published.** My first reading of this
wave was "`nd` and SHAPE agree on permutations and diverge only when the
operation set changes, so only operation-set changes are worth
re-checking". §12.6 refutes that: on `MxDisplaySurface::Create` two *pure
statement reorderings* are SHAPE-identical to base (99.53) while `nd` puts
them at 22 and 18 against base's 9. Permutations are exactly where the two
metrics diverge most.

The correct statement is that **they measure different failure modes and
neither dominates**:

* **`nd` is positional.** One instruction displaced by four slots inflates
  `nd` in proportion to the displacement. It therefore over-penalises a
  permutation of the right operations, and that is how a form that emits
  retail's exact program can read as "much worse".
* **SHAPE is alignment-based, and it saturates.** One misplaced
  instruction costs one misalignment whether it moved by one slot or by
  forty, so SHAPE cannot rank two forms that differ only in *how far* a
  single operation sits from its retail position.

So the two are complementary: **SHAPE answers "does our source emit
retail's operations at all", `nd` answers "given the operations match,
how close is the placement".** Scoring with only one is how the campaign
was misled; scoring with only the other would mislead in the opposite
direction. Rows whose residue is a placement distance (`Create`) need
`nd`; rows whose residue is a missing or extra operation
(`FUN_10061010`, `ManageVisibility`) need SHAPE.

That is a narrower and more useful result than the one the wave was
commissioned on, and it means the re-score's yield is inherently limited:
most recorded negatives were rejected on the metric that was right for
their residue class.

## 12.2 `OrientableROI::UpdateTransformationRelativeToParent` — the vec.h debt row

The highest-value target: `docs/residue-runs.md` rejects **seven** levers on
this row purely by `nd` against a baseline of 99, and MEMORY flags the
`3rdparty/vec/vec.h` edit as must-resolve-before-completion.

Re-measured at the same carrier state the recorded numbers used
(`declaration_shape(5,27)`, body 2515 = retail's length):

| lever | len | SHAPE | STRUCT | EXACT | nd | recorded nd |
|---|---|---|---|---|---|---|
| base | 2515 | **90.13** | **90.13** | **88.83** | **99** | 99 |
| `parent2world` hoisted | 2515 | 90.13 | 90.13 | 88.83 | 99 | — |
| `MXM4d` | 2515 | 89.76 | 89.76 | 87.52 | 115 | 115 |
| copy-loop order | 2515 | 89.39 | 89.39 | 88.08 | 131 | 131 |
| `j` outer | 2490 | 88.06 | 88.06 | 87.31 | — | 2190 |
| decl order C | 2513 | 78.84 | 78.84 | 76.79 | — | ≥107 |
| decl order A | 2506 | 78.17 | 78.17 | 76.87 | — | ≥107 |
| `MXM4` operands swapped | 2515 | 70.76 | 70.76 | 69.46 | 156 | 156 |
| `MXM4d` + swapped | 2515 | 70.39 | 70.39 | 68.16 | 172 | 172 |
| `unsigned int i, j` | 2549 | 52.95 | 52.95 | 52.03 | — | 2281 |
| decl order B | 2516 | 46.33 | 46.33 | 44.47 | — | ≥107 |

**Every recorded `nd` reproduces exactly** (99, 115, 131, 156, 172), which
validates the reconstruction, and **SHAPE ranks the levers in the same
order as `nd`**. No verdict flips; the base source is closest on all three
metrics. This is the expected outcome under §12.1 — every lever here is a
reorder, retype or operand swap, the category where the metrics cannot
disagree. `docs/residue-runs.md`'s conclusion now stands on a second
independent metric.

## 12.3 `CopyTransform` — not re-scorable by construction

`docs/stl-family-ledger.md` §13.1's five declaration-order variants all
produced body 941 and the ledger states "not one byte moves". Identical
objects cannot differ under SHAPE. Excluded, correctly.

## 12.4 A real flip — and why it still does not close the row

`MxDSBuffer::FUN_100c6fa0` (§11.4). `docs/residue-runs.md` rejected the
hoisting variants because they "cost 4 bytes". Under SHAPE:

| variant | len | SHAPE | verdict |
|---|---|---|---|
| base | 234 | 98.82 | — |
| `c5_hdrptr` (`MxU32* header = (MxU32*) current`) | 238 | **99.42** | **better than base** |

The recorded verdict does flip: the form the length metric rejected emits
more of retail's program. **But a SHAPE improvement that costs length is
not automatically a win** — it has to reach retail's length too. A full
carrier sweep over `c5_hdrptr` (713 states: shape, padgrid, extern,
fwdL/fwdP/fwdE, inc; 0 failed) holds at **238 bytes in every state**; 234
is never reached. The flip is real and the row is still closed.

## 12.5 `LegoTextureContainer::GetCached` — the remaining slot is allocator, not source

The coordinator's live row, after the named-surface landing (987 B =
retail's length, nd 61). adiff: **SHAPE 98.52**, STRUCT 90.24, EXACT 86.69.
The residue is three things, only one of them source-shaped:

* `sub esp, 0xfc` vs retail `0xf8` — the one extra dword slot;
* one `mov [F], r` store one instruction late, twice;
* two `cmp r,[F]` vs `cmp [F],r` — cmpdir, canonicalised, **not** source
  addressable (§11.7).

Five source variants aimed at the slot:

| variant | len | SHAPE | STRUCT | EXACT | `sub esp` |
|---|---|---|---|---|---|
| base | 987 | 98.52 | 90.24 | 86.69 | 0xfc |
| `f1_nowh` — drop `width`/`height`, compare `desc.dwWidth` directly | 975 | **98.81** | **91.96** | **90.18** | 0xfc |
| `f2_nound` | 982 | 97.63 | 89.02 | 83.98 | 0xfc |
| `f3_mxbool` | 988 | 97.48 | 85.33 | 81.48 | 0xfc |
| `f4` | 976 | 97.47 | 85.54 | 83.46 | 0xfc |
| `f5_noshadow` | 987 | 98.52 | 90.24 | 86.69 | 0xfc |

**`sub esp` is 0xfc in all six.** Removing two named locals does not remove
a slot — the standing law now confirmed in the *subtractive* direction as
well as the additive one: naming a value does not create a slot, and
un-naming it does not free one. GetCached's extra dword is an allocator
decision and the text channel has no handle on it.

`f1_nowh` is still a genuine improvement on all three metrics
(EXACT 86.69 → 90.18) because it removes two redundant *operations* — the
`width`/`height` cache stores — not because it removes a slot. It is 12
bytes short of retail, so it is recorded, not landed.

## 12.6 `MxDisplaySurface::Create` — the measurement that corrected §12.1

`docs/residue-runs.md`: "all four statement orderings of the
`dwFlags`/`dwWidth`/`dwHeight`/`dwCaps` block are **worse** (nd 15, 18, 22,
23 against the baseline 9), so the current source order is already the
closest one."

Re-scored (retail 660 B, 212 insn):

| variant | len | SHAPE/STRUCT/EXACT | nd | recorded nd |
|---|---|---|---|---|
| base | 660 | 99.53 | 9 | 9 |
| `h1_capsfirst` | 660 | **99.53** | 22 | 22 |
| `h3_capsbeforewh` | 660 | **99.53** | 18 | 18 |
| `h2_whfirst` | 660 | 99.06 | 23 | 23 |
| `h4_hwswap` | 660 | 97.17 | 15 | 15 |

All four recorded `nd` values reproduce exactly. But **`h1` and `h3` are
SHAPE-identical to base**, and the `-v` diff shows why: base, `h1` and `h3`
each have exactly *one* divergence from retail — the
`mov [esp+0x84], 0x6040` store in the wrong slot — and SHAPE counts that
as one misalignment regardless of distance. `nd` sees base's store 1 slot
away and `h1`'s 4 slots away, hence 9 vs 22.

And the ranking inverts: `nd` puts `h4` (15) ahead of `h3` (18) and `h1`
(22), while SHAPE puts `h4` *last* (97.17) — because `h4` really does move
six operations (it swaps the two `GetRect()` calls), whereas `h1`/`h3`
move none. `nd` rewarded the structurally worst variant.

**Verdict: `docs/residue-runs.md`'s conclusion stands but its reasoning
needs a footnote.** Base is still the best form — `nd` is the right metric
for this row because the residue *is* a placement distance. What is wrong
is the implication that `h1`/`h3` are meaningfully worse source: they emit
retail's program exactly as base does. The row's lever is the scheduler,
and no statement ordering reaches it.

## 12.7 `MxDSBuffer::FUN_100c6fa0` function-scope hoists

| variant | len | SHAPE | nd | recorded |
|---|---|---|---|---|
| base | 234 | 98.82 | 4 | 4 |
| `g2_size_fn` — `MxU32 size;` at function scope, read still inside the `if` | 234 | 98.82 | **4** | (18) |
| `g1_chunk_fn` — `MxU8* chunk;` at function scope | 236 | 98.25 | — | 13 |
| `g3_folded` — the two `+=` folded | 232 | 97.65 | — | 59 |

`g1` and `g3` reproduce as worse, matching the record. `g2` does **not**
reproduce the recorded nd=18: mine is 234 bytes and nd=4, the ledger's was
238 bytes. The ledger's variant also moved the read (`assigned before the
if`), so it is a different form — mine hoists only the declaration. Noted
rather than treated as a contradiction: **a function-scope declaration
alone costs nothing here**, which is a small addition to the standing
named-local law, and the recorded nd=18 belongs to the read-hoisting
variant I re-measured separately as `c2_sizevalue` (§11.4, 238 B).

## 12.8 A SHAPE census of the whole open set

The re-score's most useful product is not a list of flipped verdicts — it
is the classifier that falls out of §12.1. `shapecensus.py` scores **all
83 open rows** by reading both bodies out of the *linked images* (ours at
the report's `recomp` address, retail at its `address`), so it needs no
symbol lookup and covers rows this lane has never touched.

**Result: 11 open rows are at SHAPE 100.00, 72 are below.**

> **Correction, recorded because the first numbers were published.** The
> first run of this census reported 12/71 and put
> `UpdateTransformationRelativeToParent` at 100.00. That was an artefact of
> over-coarse masking: the instrument blanked *every* numeric operand of any
> instruction carrying a relocation, so `cmp dword ptr [g_x], 0` lost its
> real immediate too and matched things it should not. It now attributes the
> relocation to the exact field using capstone's `disp_offset`/`imm_offset`,
> and masks segment-prefixed absolutes (`fs:[0]` is a relocation against
> `__except_list` in our object and a literal 0 in the image) on both sides.
> Under the corrected instrument that row is **90.13**, which matches the
> object-level measurement in §12.2 exactly.
>
> **Cross-validation after the fix**: the census (read from linked images,
> sliced by adjacent row addresses) reproduces the independent object-level
> `adiff` measurements to two decimals — `0x100a46b0` 90.13/90.13,
> `0x100a66f0` 94.27/94.27, `0x100bb1d0` 96.43/96.43, `0x100998e0`
> 98.52/98.52, `0x100c6fa0` 98.82/98.82, `0x100ba7f0` 99.53/99.53. Six of
> six agree; `0x10061010` differs (93.08 vs 92.12) only because the linked
> body is the composed one and §11.2 measured the seed.

The **SHAPE == 100 direction is sound**: we emit retail's exact operation
sequence, so whatever is left is placement or colouring and **the text
channel is provably closed for these rows**. They should never receive
another source variant:

| SHAPE | EXACT | m | addr | ours/ret | row |
|---|---|---|---|---|---|
| 100.00 | 70.59 | .7059 | 0x1002a1b0 | 82/82 | `_Tree<LegoCacheSoundEntry>::_Erase` |
| 100.00 | 79.71 | .7971 | 0x100a3b40 | 197/197 | `TglImpl::MeshBuilderImpl::Clone` |
| 100.00 | 93.15 | .9315 | 0x1002f770 | 188/188 | `LegoPathActor::UpdatePlane` |
| 100.00 | 94.17 | .9417 | 0x100720d0 | 323/323 | `Act3List::RemoveByObjectIdOrFirst` |
| 100.00 | 94.65 | .9251 | 0x100ba2c0 | 577/576 | `MxStillPresenter::Clone` |
| 100.00 | 95.41 | .9538 | 0x10038b10 | 1232/1232 | `Pizza::HandleEndAction` |
| 100.00 | 95.87 | .9545 | 0x10080be0 | 779/778 | `LegoCarRaceActor::CalculateSpline` |
| 100.00 | 96.08 | .9608 | 0x1004bd10 | 438/438 | `MxTransitionManager::DissolveTransition` |
| 100.00 | 96.12 | .9612 | 0x100b24f0 | 346/346 | `MxVideoPresenter::AlphaMask::AlphaMask` |
| 100.00 | 97.39 | .9739 | 0x100c3750 | 1157/1157 | `MxRegion::AddRect` |
| 100.00 | 99.06 | .9907 | 0x100035e0 | 1148/1148 | `Helicopter::HandleControl` |

Two independent confirmations that the classifier is right:
`AddRect` is the row §11.6 found six source variants
bit-identical on; and `Helicopter::HandleControl` is recorded in
`docs/beta10-wave2-ledger.md` as *"Base is June-true"* with BETA10
confirming our declaration order. `MxStillPresenter::Clone` and
`CalculateSpline` are SHAPE 100 with a **one-byte** length delta — the
encoding cost of a slot tie, exactly the confusion §13.1 flagged.

**The SHAPE < 100 direction is NOT sound and must not be over-read.** A
differing operation sequence is *consistent with* a source defect, but an
allocator that spills where retail keeps a register also adds a `mov` —
§12.5's `GetCached` is precisely that case (its SHAPE gap is a spill store,
not a missing statement). So SHAPE < 100 means "worth reading", not
"source defect confirmed".

`UpdateTransformationRelativeToParent` is the sharpest illustration and a
useful calibration point: it sits at **90.13**, comfortably inside the
"worth reading" band, and §12.2 has just shown that **no source lever moves
it** — because its differing operations are six permuted FP addend spans
produced inside `3rdparty/vec/vec.h`'s `_DOTcol4`, i.e. vendor code and
scheduler state, not first-party text. A row can be far from SHAPE 100 and
still have an empty text channel.

Ranked worst-first, the largest operation-sequence gaps in the open set
are:

| SHAPE | m | addr | ours/ret | row |
|---|---|---|---|---|
| 88.44 | .9482 | 0x10055a60 | 4120/4112 | `LegoNavController::Notify` |
| 90.13 | .8696 | 0x100a46b0 | 2515/2515 | `OrientableROI::UpdateTransformationRelativeToParent` |
| 91.30 | .6522 | 0x10057180 | 57/57 | `_Tree<LegoAnimPresenter*>::_Erase` |
| 92.31 | .8227 | 0x1004c580 | 413/412 | `MxTransitionManager::SetupCopyRect` |
| 93.08 | .5411 | 0x10061010 | 717/731 | `LegoAnimationManager::FUN_10061010` |
| 94.23 | .8896 | 0x1009f490 | 1074/1121 | `LegoAnimScene::CalculateCameraTransform` |
| 94.27 | .8848 | 0x100a66f0 | 557/561 | `ViewManager::ManageVisibilityAndDetailRecursively` |
| 94.69 | .9552 | 0x10046050 | 693/703 | `LegoPathController::PlaceActor` |
| 95.04 | .9504 | 0x100a4420 | 520/514 | `OrientableROI::OrientableROI` |
| 94.87 | .6667 | 0x100a12a0 | 83/83 | `TglImpl::TextureImpl::SetImage` |

`LegoNavController::Notify` is the largest operation-sequence gap in the
whole open set and has never been read at this level (there is a stale
`salvage/islK-navcontroller-notify-shape` branch). It is the single
best-evidenced next target for the text channel.

## 12.9 The inventory, and why the re-score's yield is small

The campaign's recorded text-cell negatives were inventoried across
`docs/nearmiss-wave4-ledger.md`, `docs/beta10-wave2..5-ledger.md` and
`docs/stl-family-ledger.md` §13. The result explains the low yield
directly:

* a large fraction are recorded as **bit-inert** — byte-identical objects,
  which cannot differ under any metric (`GetRefCount`'s five cells,
  `FindPath` family A, `LinkEdgesAndFaces`' three cells, `HitActor`'s four,
  `AddRect`'s five per-site hoists, `LegoPartPresenter::Read`'s loop
  mirrors, `~LegoROI` v2/v6, `TowTrack` t3, `JetskiRace` at 0 of 58
  bodies…);
* many of the rest were rejected on **victim counts in other bodies**, not
  on the target's own distance (`~LegoROI` v1's 11 changed bodies,
  `RemoveActor`'s five 1.0 victims, the `varab`/`varb` hunks' two deleted
  COMDATs) — a collateral test that SHAPE does not overturn and that
  §9.4c independently vindicated;
* `beta10-wave5-ledger.md` contains **no** source-text variants at all;
* and several were killed on evidence stronger than any distance metric —
  the `LenSquared` reassociation was refuted by a retail disassembly census
  showing **retail itself uses both term orders**, which no single source
  spelling can produce.

That leaves a genuinely small re-scorable set, and §12.2/§12.6/§12.7 found
the recorded verdicts standing in every case that this lane owns and could
reconstruct. The one flip (§12.4) did not close its row.

# 13. Wave 5 — `LegoNavController::Notify`, and two more metric asymmetries

Base `cd8692bb`, verified before any change: `LEGO1 4853/4934, ISLE 172/172,
CONFIG 111/111`. Instrument: the corrected `adiff.py` taken from the `fin`
lane's scratchpad rather than re-derived, repointed at this worktree.

## 13.1 LANDED: `0x10055a60` .9482 → .9818 from the salvage branch

The coordinator flagged a stale `salvage/islK-navcontroller-notify-shape`
branch. It was worth a pass: commit `d65a2947` had already derived **three**
beta-attested shapes for this row.

Hunk 1 — the `MxU8 key = GetKey();` / `m_keyPressed = TRUE;` statement
order, attested by BETA10 `0x1009c74d..0x1009c75b` at /Od — **has landed
since** (that is the .9438 → .9482 the tree already had). Hunks 2 and 3 had
not:

2. the password sites read the **cached local `key`**, not a second
   `GetKey()`. With the member store after the load, a re-read can no
   longer CSE through the possible alias, yet retail uses the cached key in
   `ebx` at those sites — so 1997 read the local.
3. the check is `if (*g_currentInput) { advance-or-reset } else { switch }`,
   not the negated spelling. The two canonicalise identically only while
   the else-block carries the re-read, and the block layout flips once it
   uses `key`.

Applied to the current tree, **all four metrics move together**:

| metric | before | after |
|---|---|---|
| reccmp | .9482 | **.9818** |
| body length | 4120 | **4112 = retail's exact length** |
| SHAPE | 94.42 | 94.71 |
| EXACT | 92.96 | 93.08 |

**Gated:** `ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE: LEGO1 4853/4934,
ISLE 172/172, CONFIG 111/111`; terminal ISLE and CONFIG **IDENTICAL**;
53 tests pass. **Zero collateral — exactly one row's score changed in the
whole tree.** The row does not reach 1.0; the residue is the `calcStep`
constant-store scheduling seesaw, which `d65a2947` had already classed as
compile-state and which §13.3 confirms is five instructions.

## 13.2 A tenth asymmetry: an instruction can carry MORE than one relocation

`adiff.py`'s `reloc_site()` documents "An instruction carries at most one
relocation" and returns a single field. That is false for the ordinary
`pointer_global = &other_global`:

```
mov dword ptr [g_currentInput], offset g_debugPassword
c7 05 <DIR32 g_currentInput> <DIR32 g_debugPassword>
```

Two DIR32s — one in the displacement, one in the immediate (verified in
`Notify`'s relocation table at offsets 117 and 121). The single-site rule
lets the absolute memory operand win, masks the displacement only, and
leaves our placeholder `0` against retail's resolved address, so **every
`ptr = &global` store scores as a difference**.

Fixed by attributing each relocation to its field by byte range
(capstone `disp_offset`/`imm_offset`), falling back to the old heuristic
when no encoding is available. `Notify`'s first divergence moves
**+115 → +337** and SHAPE 94.71 → 94.80. The fix is in
`scratchpad/inl/adiff_fin.py` (`reloc_sites`).

## 13.3 An eleventh: the switch-table detector only sees the TRAILING table

MSVC's dense-switch lowering emits **two** tables:

```
movzx eax, byte ptr [eax + <byte-index table>]
jmp   dword ptr [eax*4 + <dword target table>]
```

The relocation-based detector finds the dword table (a dense run of DIR32s
to `$L` labels). The **byte-index table has no relocations at all** — its
entries are small case indices — and it sits *before* the dword table, so
it is disassembled as code.

Measured on `Notify` (verified by hand, not by heuristic): code ends at
3666 with `c2 04 00` (`ret 4`) followed by `8b ff` padding; 3668–4090 is the
byte-index table (values 0x00–0x18) and 4092–4112 the dword table. That is
**444 of 4112 bytes**. Scoring code only:

| | full row | code only |
|---|---|---|
| ours / retail instructions | 1190 / 1153 | **929 / 929** |
| SHAPE | 94.15 | **99.46** |

The instruction counts become *identical*, and the row's real residue is
**5 instructions out of 929** — the scheduling seesaw, exactly as
`d65a2947` said.

**This inverts the row's classification.** §12.8 named
`LegoNavController::Notify` "the largest operation-sequence gap in the open
set" at SHAPE 88.44. Almost all of that was table noise; its true code-only
gap is ~0.5%.

### 13.3a Extent, and what is NOT claimed

A scan of the open set finds **16 rows carrying an embedded table**. Three
movers were verified by hand — each ends in a real `ret` + padding followed
by a tail of dword addresses inside the image:

| row | full | code only | tail |
|---|---|---|---|
| `Infocenter::HandleKeyPress` 0x1006fda0 | 91.86 | **99.10** | 67 B, `2afe0610 63fe0610 …` |
| `Act3::TriggerHitSound` 0x10072ad0 | 92.86 | **98.73** | 24 B, `ed2a0710 1b2b0710 …` |
| `LegoNavController::Notify` 0x10055a60 | 97.35 | **99.46** | 444 B |

**Not claimed**: the naive "cut at the last `ret`" detector I used to scan
has false positives — `TowTrack::HandlePathStruct` (740-byte tail, only 33
instructions left) and `MxVideoPresenter::PutFrame` (865 B) are certainly
mis-cut, and their numbers must not be used. A sound detector needs the
relocation evidence for the dword table plus the `movzx …, byte ptr [reg +
X]` reference that locates the byte table. Handed to the lane publishing
the corrected map rather than republished here.

## 13.4 Re-verifying §11.2's anti-compose claim under the corrected instrument

The coordinator flagged that §11.2 rested on 2–5 point gaps inside the
instrument's error bar. Re-scored with the corrected `adiff`:

| variant | SHAPE | STRUCT | EXACT |
|---|---|---|---|
| base | 93.08 | 68.26 | 63.48 |
| `h01_flagsvalue` | **95.69** | 73.68 | 63.16 |
| `v04_flagfirst` | 92.60 | **73.99** | **68.74** |
| `h01` + `v04` | 95.22 | 70.33 | **61.24** |

**The claim holds.** The combination is 2.24 EXACT points *below base* and
7.50 below `v04` alone, and below either on STRUCT — gaps larger than the
~1–2 point absolute shift the correction introduced. All orderings are
preserved. §11.2's conclusion stands; only its absolute values were low.

Corollary for the rest of this ledger: **every SHAPE number in §11 and
§12 is a lower bound.** The conclusions drawn from them were comparisons
between variants measured with the same instrument, and the corrections
shift rows without reordering them, so the verdicts stand — but the
absolute figures should be re-read from the corrected instrument before
being quoted anywhere else.

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
| `adiff.py` | **the wave-3 instrument** — SHAPE/STRUCT/EXACT aligned instruction diff of a COMDAT against a retail row, across a length mismatch |
| `scoreall.py` | score every compiled variant of a function with adiff |
| `vgen.py` | generic source-variant runner (TU + symbol + retail VA) scored by adiff |
| `ndsweep.py` | generic carrier sweep scored by masked nd taken **straight from `legobin`**, so it cannot inherit an oracle-length defect |
| `v_vm.py` / `v_vm2.py` / `v_buf.py` / `v_mds.py` | the wave-3 row batches |
| `v_ori.py` / `v_gc.py` / `v_rerun.py` | the wave-4 re-score batches (vec.h debt row; GetCached; buffer + Create) |
| `shapecensus.py` | **SHAPE census of every open row**, read from the linked images so it needs no symbol lookup |
| `adiff_fin.py` | the `fin` lane's corrected adiff, repointed here, **plus the wave-5 multi-relocation fix** (`reloc_sites`) |
| `codeend.py` / `tablescan.py` | embedded-switch-table detection and its extent over the open set (§13.3 — detector is NOT sound, see §13.3a) |
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

