# Specification: two COMDAT-splicing extensions

Status: **specified, not implemented.** User-authorised 2026-08-16.
Author: main loop. Implementer: next free lane. Red-first — every test in §4
must be written and observed to FAIL before any implementation lands.

## 0. Why

Two open rows are already proven byte-exact in some compile state and cannot be
landed:

| row | proven state | blocked by |
|---|---|---|
| `0x1009f490 CalculateCameraTransform` | 1121 B, masked nd 0, SHAPE/STRUCT/EXACT 100.00 | both extensions |
| `0x1003cf20 ~LegoCacheSoundManager` | 258/258, masked nd 0, 100.00/100.00/100.00 | extension B (and A unless its callee-cost route lands) |

`0x100a4420 OrientableROI::OrientableROI` sits one EH-store scheduling
instruction behind and becomes reachable if the bit ever is.

Neither row has any other route. For `0x1009f490` the source/callee-cost axis is
refuted **arithmetically** (retail's per-site vector is (1,0,1); our
`CreateLocalTransform` sites saturate at cost ≥ 2 while `CalculateCameraTransform`
needs cost ≥ 12 — disjoint), the carrier axis is sealed across ~24,000 cells on
two independent lanes, and the body axis can only *raise* R where this site needs
it to fall.

## 1. Extension A — donor body-variant production

**The gap.** Donor objects are compiled from the **identical TU text** as the
seed. The only permitted variation is a force-included generated header selected
by `compile_lane: {required_define: ...}`, validated
`non_emitting_declarations_only`. A `/FI` header cannot reach a function body
defined in the `.cpp`, so the donor lane cannot produce either state that yields
the correct body (inject cost into `Interpolate`, or drop its definition).

**Design (amended — see A6).** A new donor recipe kind that carries a **typed
`source_overlay` op-list applied to the donor's rendered copy of the TU only**. Reuse the existing
op machinery wholesale — same verbs (`insert`/`replace`/`delete`/`append`), same
typed generator taxonomy, same content-hash anchors. No new generator kinds are
required: `0x1009f490`'s donor is a `delete` of `Interpolate`'s definition.

**Obligations.**

- A1. The donor's rendered TU must be reproducible from checked-in source plus
  typed ops alone. No literal payloads, no invented code.
- A2. The **seed's** rendered TU is bit-identical to what it is today. The op-list
  applies to the donor rendering only; a regression here is a hard failure.
- A3. The donor's rendered source sha256 and the produced body sha256 are both
  pinned in the manifest.
- A4. The donor object is a **byte source only**. It must never enter the link.
  The build must assert this rather than rely on convention.
- A5. Anchors must seat uniquely against the donor's clean input, and drift
  refuses exactly as `repin_overlay.py` already refuses.
- **A6 (amendment 3 — authorised). The op-list may render a donor-private
  HEADER as well as the `.cpp`.** A `.cpp`-only rendering does not compile for
  the `0x1003cf20` case — verified, not assumed:
  `s.cpp(72) : error C2084: 'LegoCacheSoundEntry::~LegoCacheSoundEntry(void)'
  already has a body` — because the fix spans the header (which declares the
  inline body) and the `.cpp` (which would define it). The donor already
  compiles in its own probe directory with `/I{source.parent}` seated first, so a
  private header shadows the real one **for that one compile only**.
  This is what keeps all 16 includers on clean source, which is precisely why the
  −48 never arises. Additional obligations that come with it:
  - A6a. The donor-private header must itself be rendered by **typed ops from the
    checked-in header**. No literal payloads, no invented declarations.
  - A6b. The **shipped tree's** header rendering must be bit-identical to today's.
    The build must assert this, not assume it.
  - A6c. The include-path shadowing must be scoped to the donor compile. No other
    compile in the build may see the private header.
  Trust note: this means a donor compiles against a header differing from the
  shipped tree. The correctness anchor is unchanged — the donor object is a byte
  source only, and B1 still requires the spliced body to be byte-identical to
  retail.

- **A7 (amendment 4 — authorised). ONE new typed generator: a member
  signature emitter.** Verified necessary, not assumed: the donor rendering needs
  a destructor declaration `~LegoCacheSoundEntry();` and a qualified definition
  header `LegoCacheSoundEntry::~LegoCacheSoundEntry()`, and no existing generator
  can emit either — `source_range_relocation_v1` with `byte_destination` returns
  the range without a signature wrapper, and `declaration_sequence_v1`'s
  `function_prototype` always emits a return type and its identifier validator
  admits neither `~` nor `::`. The donor cannot route around it either:
  adding/deleting functions is barred by B4's multiset check, declarations are
  the sealed carrier axis (~15,100 cells) and statements the refuted body axis
  (441 cells).

  Parameters: `{class_identifier, member_identifier, kind}`. Obligations:
  - A7a. Both identifiers must be **validated to exist in the checked-in
    source** — the class declared, the member present on it. Nothing literal.
  - A7b. `kind` is a **closed enum**, `destructor` only. Adding a kind is a spec
    amendment, never an implementation detail.
  - A7c. It emits **signature text only** — never a body, never a return type,
    never parameters. The body comes from the existing authenticated
    relocated-range mechanism.
  - A7d. Usable **only in a donor rendering**. It must never appear in the
    shipped tree's rendering, and the build must assert that.
  - A7e. Tests must prove it **cannot emit an arbitrary function**: reject a kind
    outside the enum, and reject an identifier absent from the checked-in source.

  Rationale for authorising: it renders from checked-in identifiers via a typed
  generator, which is squarely inside the standing mandate, and the outcome is
  measured rather than estimated — GAIN 1, LOST 0, aligned rows +334.

## 2. Extension B — splice class `retail_exact_reloc_divergent`

**The gap (amended).** Every existing class requires donor and seed bodies to
carry the same relocation *targets*. The trigger is **not** simply a count
change — measured on the two customer rows:

| row | seed relocs | donor relocs | how they differ |
|---|---|---|---|
| `0x1003cf20` | 14 | **14** | one **global target SUBSTITUTION**: `??3@YAXPAX@Z` (`operator delete`) → `??1LegoCacheSoundEntry@@QAE@XZ`, plus one `$T` local rename |
| `0x1009f490` | 12 | **13** | one **added** target (`call Interpolate`) |

Inlining the entry destructor drags its own `operator delete` along, so
*declining* it substitutes a global target rather than adding one. **A class that
only relaxed count-equality would not land `0x1003cf20` at all.** The class must
be defined over the relocation *target set*, admitting substitution and/or count
change.

Corollary, measured: for `0x1003cf20` every other `same_slot_resize` precondition
already passes — seat, section count, function multiset, header shape, line
counts, COMDAT selection, closure and closure seats, xdata raw bytes, and both
the xdata and `debug$S` relocation pairings. Exactly one ordinal blocks it. So
**B7's relocation-table rebuild is not exercised by that row**: with equal counts
the existing in-place loop suffices, and the only change is that a substituted
ordinal must write the seed index *of the donor's target name* rather than
reusing the seed's. The reindexing path is required only by `0x1009f490`.

**Original framing retained for reference.** Every existing class requires donor
and seed bodies to carry the same relocations. `compose_same_slot_resize` requires `relocation_count` equality
in its header-shape check; `_normalized_relocation_renames` requires literal
relocation equality except compiler-local `$L`/`$T`/`$S` serial renumbering, never
a global symbol change. **A call is a relocation**, so an inline accept/decline
flip changes the relocation set by construction. Measured: our `0x1009f490` body
is 1074 B with **12** relocations; the correct body is 1121 B with **13**.

**Obligations.** All of `same_slot_resize`'s checks, minus relocation-set
equality, plus:

- B1. **THE LOAD-BEARING ONE — retail-exactness.** The composed body must be
  **masked nd 0 against the retail oracle body at retail's exact length**.
  Extract from `legobin/LEGO1.DLL` (already sha256-pinned in the manifest) at a
  per-function pinned `retail_va` + `retail_length`; mask our relocation fields;
  require zero differing bytes. Not "matches a pinned hash" and not "improves the
  row" — this class may only ever install retail's own code. That is what makes
  it safe and what stops it becoming a general escape hatch from
  relocation-equivalence discipline.
- B2. Same mangled name; same section seat (`sp["number"] == dp["number"]`).
- B3. Correct 16-byte linked contribution span.
- B4. Existing COMDAT child-closure and function-multiset checks, unchanged.
- B5. **Every EXTERNAL relocation target in the donor body names a symbol the
  seed object already defines or declares**, with matching target type and
  storage class. **Compiler-local targets (`$L`/`$T`/`$S` serials) are excluded**
  and stay paired by the existing rename machinery — they are per-compile and
  are *never* present in the seed. (Amendment 2: B5 as first written rejected the
  very row it exists to land, on the donor's `$T65428`.)
- B6. The symbol remap into the seed's symbol table must be **unambiguous** — a
  duplicate name is a hard failure, never a first-match.
- B7. The seed's relocation table for the target section is rebuilt from the
  donor's with remapped indices; debug/xdata/line records repaired exactly as
  `same_slot_resize` already does.

**What this changes about the trust argument.** Today "the donor body is the same
function compiled differently" is proved from relocation equivalence with the
seed. Under this class it rests instead on mangled name + section seat + B1's
comparison against retail. That is a different basis, and arguably a stronger one
since retail is the actual oracle — but it is different, and B1 is the reason it
is sound. Do not implement B without B1.

## 3. Scope limit

These extensions buy **at most three rows** (`0x1009f490`, `0x1003cf20`,
`0x100a4420`). They do nothing for the ~75 allocator rows and nothing for goal 2.
Any design pressure to generalise them further should be refused.

## 4. Tests — write these first and watch them fail

Each must reject, with a distinct error:

1. donor body **not** retail-exact under the mask (off by one byte)
2. donor body correct but at the wrong length
3. donor relocation naming a symbol absent from the seed object
4. donor relocation whose seed symbol differs in type or storage class
5. ambiguous symbol remap (two seed symbols share the name)
6. section-seat mismatch
7. linked-span mismatch
8. differing function multiset
9. extension A: donor op-list that perturbs the **seed** rendering
10. extension A: anchor that does not seat uniquely
11. extension A: donor object reaching the link

A **twelfth test is required: a positive control.** A class that rejects
everything would satisfy the eleven rejection tests vacuously. The fixture must
model a real customer row — equal relocation counts with one global substitution
plus one `$T` rename — and must fail today with the same error string the real
objects produce (`primary: relocation target differs`).

B1 note: the pinned retail extraction needs a PE reader and the pinned image,
which unit tests cannot ship. Split it — the **build** performs the pinned
extraction (it already validates `original_sha256`) and passes the body to the
composer, which enforces length and masked nd 0.

The existing 53 tests must stay green throughout, and all three image gates must
be unchanged except for the intended row gain.
