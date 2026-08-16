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

---

## 5. Sweeps

*(filled in as they complete — see §5.x)*
