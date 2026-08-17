# Specification: two COMDAT-splicing extensions

Status: **implemented, tested, and gated.** Extensions A, B, A7/A7f and B7 are
in the production path. `0x1003cf20` is landed. The distinct
`retail_exact_target_closure` class described in §7 landed `0x1009f490` with a
full-build gain of one and zero losses; ordinary B4 remains unchanged.

## 0. Why

### Authenticity boundary

Entropy additions may change compiler state, declaration order, or flags, but
must be proven unable to emit or alter program logic. A transplanted function or
COMDAT may cross translation-unit or target-module boundaries only when it is
compiler-produced from authenticated source and the composer proves the
identity/seat, complete relocation and closure mapping, unwind/debug structure,
and linked retail result required by its splice class. Masked-byte equality is
only a discovery signal; it is never sufficient proof by itself. No literal or
invented behavior is admissible.

The work began from two rows proven byte-exact in a donor compile state:

| row | proven state | blocked by |
|---|---|---|
| `0x1009f490 CalculateCameraTransform` | 1121 B, masked nd 0, all 13 relocation targets retail-authenticated | **landed** through the distinct target-closure extraction class (§7) |
| `0x1003cf20 ~LegoCacheSoundManager` | 258/258, masked nd 0, 100.00/100.00/100.00 | **landed** through extensions A+B |

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

  Parameters: `{class_identifier, member_identifier, kind, form}` (amendment 5).
  Obligations:
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
    outside the enum, reject a **form** outside the enum, reject smuggled
    `body`/`return_type`/`parameters` keys, reject an identifier absent from the
    checked-in source, and reject a recipe naming an undeclared class.
  - **A7f (amendment 5 — authorised). `form` is a CLOSED ENUM with exactly two
    members**: `in_class_declaration` (renders `~X();`) and
    `qualified_definition_header` (renders `X::~X()`, no terminator). Two texts
    are required from the same three identifiers — the donor **header** seat and
    the donor **`.cpp`** seat — and one generator with no discriminator can only
    reach the first. Adding a third form is a spec amendment, never an
    implementation detail.

    The second seat cannot be avoided, and this was **measured, not assumed** —
    deleting the declaration from the donor header instead compiles, but:

        v1 pure delete    len 242 (retail 258)  entry_dtor_calls 0  masked nd 106
        v2 declaration    len 258 (retail 258)  entry_dtor_calls 1  masked nd 0

    With no declaration the destructor is implicitly trivial, nothing is called
    at the `erase` site, and the body comes out *shorter than today's* (242 vs
    our 274) while the out-of-line definition compiles and is simply never
    called. That failure is silent, not loud — it would have shipped as a
    regression. The relocated-range mechanism cannot supply the qualified form
    either: the header contains `LegoCacheSoundEntry` and `~LegoCacheSoundEntry()`
    but never adjacently, and assembling one from scavenged fragments would be
    neither typed nor honest.

    Every other obligation survives untouched: A7a still validates both
    identifiers, A7b's `kind` enum is unchanged, A7c still holds because both
    forms are signature-only, and A7d/A7e are unaffected.

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

## 3. Manifest-declared single-evaluation source permutations

The compiler-facing source permutations belong in the entropy manifest, not in
`byte_identity.py`.  The engine contains only a reusable structural grammar:
bind one existing expression to one fresh, explicitly typed local, then use the
local exactly once as either an evaluated array extent or an evaluated member-
assignment receiver.  It cannot accept a free-form use template, unevaluated
`sizeof`, string/comment substitution, identifier fragments, conditional use,
or short-circuit use.

For each customer the manifest owns the type, local name, expression, closed
use record, exact clean-source anchors, removed-range hash, and complete seed
and donor function-window pins.  The validator reconstructs the original
statement from that same record and requires byte equality with checked-in
source.  All other donor operations remain fresh non-emitting entropy outside
the target window.  The donor is compiled afresh from the rendered source and
excluded from the link; composition still requires the retail-exact body and
the complete ordered semantic relocation oracle.

The first admitted customer has an 822-byte body in an 832-byte linked span and
changes the COFF line table from 27 to 29 rows.  Its accepted source rendering is
29,815 bytes with SHA-256
`168b3e2098e2bcc12ac0c3ece497e781a995862c351ca7cf70e0e2f079668691`.
Scratch source/object hashes are evidence only and are never manifest inputs.

## 4. Scope limit

Extensions A and B buy **at most three rows** (`0x1009f490`, `0x1003cf20`,
`0x100a4420`). The first two are landed. They do nothing for the allocator bulk
and nothing for goal 2.
Any further use requires a distinct fail-closed proof and a measured customer;
no premise may be weakened merely to admit another donor.

## 5. Tests — write these first and watch them fail

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

## 5. B7 implemented, and A8 — historical blocker analysis (2026-08-16)

This section records the evidence that motivated §7. Its conclusion that the
row was not landable is superseded: the user explicitly permitted authentic
cross-module/target-closure extraction, and §7 resolves the issue without
relaxing ordinary B4 or linking the donor object.

**B7 is implemented and tested.** The donor may now carry MORE relocations than
the seed. Seed rows pair with a **prefix** of the donor's; each extra donor row
must be an ORDINARY target the seed can already name (B5/B6) and is appended.
The primary relocation table is rebuilt as a third `replacements` region rather
than overwritten in place, and the section header adopts the donor's count.
Refusals, both tested: a donor with FEWER relocations, and an appended
compiler-local target (which would need a symbol this class does not invent).

`0x1009f490`'s donor was verified against the real objects: **1121 bytes = retail's
1121, masked nd 0, 13 relocations against the seed's 12**, and the divergence is a
single trailing extra — `?Interpolate@LegoAnimNodeData@@SAMMAAVLegoAnimKey@@M0M@Z`
at offset 905. Indices 0-11 pair exactly, with the usual `$T4562`→`$T4554` rename.

**The row is still not landable, and the reason is a LATENT DEFECT in extension A.**

`render_donor_source_overlay` reads its base with `data = (root / path).read_bytes()`
— i.e. **checked-in clean source**. But `legoanim.cpp` is overlay-owned (two shipped
ops, a `seq` inserting carrier classes), so a clean-base donor compiles a *different
TU than the seed*. Measured:

    donor rendered from the SHIPPED rendering + delete : len 1121, masked nd 0
    donor rendered from CLEAN source        + delete : len 1121, masked nd 41

**A8 IS RETRACTED — the clean base is not a blocker.** A donor recipe carries the
same typed op machinery as the shipped overlay, so it can simply **reproduce the
shipped ops itself** and then apply its own. Verified end to end: a recipe whose
`operations` are `[shipped op#1, shipped op#2, replace-with-reserved-lines]`
renders through `render_donor_source_overlay` from clean source and compiles to
**1121 bytes = retail's 1121, masked nd 0, 13 relocations**. No extension-A change
is required. (The duplication of the shipped ops is a real maintenance cost — if
they change, the donor's copies must too — but it is expressible today.)

### THE ACTUAL BLOCKER: B4's function multiset (measured)

Lifting `Interpolate`'s definition removes the function from the donor object
entirely, so the donor is no longer "the same TU compiled differently":

    seed  406 sections, 131 functions
    donor 400 sections, 129 functions
    in SEED not DONOR: ?Interpolate@LegoAnimNodeData@@SAMMAAVLegoAnimKey@@M0M@Z
                       ?Scale@Matrix4@@QAEXABM00@Z          (knock-on)

`compose_*` refuses with **"global section count differs"**, and B4's
`function_multiset(seed) == function_multiset(donor)` would refuse next. Both
refusals are correct: a donor missing two functions is not a recompile of the
seed's TU.

Two routes exist and **neither should be taken without authorisation**:

- **(a) Widen A7 to emit a signature WITH a return type**, so the donor can
  define `Interpolate` **out-of-line** (dropping only the `inline` keyword)
  instead of deleting it. The function then still exists, so the multiset holds.
  But A7c forbids return types *by design*, precisely to stop the generator
  becoming a general code emitter — and a non-inline definition is emitted as a
  regular function rather than a COMDAT, so the section-shape checks may refuse
  anyway. Unverified.
- **(b) Parameterise B4** to allow a declared, pinned set of dropped functions.
  This is a validator relaxation of exactly the kind refused three times this
  session, and it would remove the check that proves a donor is a recompile of
  the seed. **Not recommended.**

Route (a) is the principled one and should be measured before being funded: first
confirm that a non-inline `Interpolate` still yields masked nd 0 at
`0x1009f490` **and** leaves the section shape intact. If it does not, this row is
not landable by splicing at all and should be sealed.

**B7 remains implemented and tested** — it is required by any future attempt and
is independent of this blocker.

## 6. Class C — `comdat_selection_override`: landed with frozen-input reproof

**Built and tested** (`compose_comdat_selection_override`, validator + build
dispatch, `donor_source` on the pad_shape recipe). Rationale: some template
instantiations are emitted by several objects in one link, the linker keeps
whichever comes first, so the copies are interchangeable *to it* — installing
another copy selects among genuine compiler outputs and invents nothing. C2
(retail-exactness) is the load-bearing obligation, exactly as B1.

Verified on the real objects for `0x1001d890 _Tree<MxCore*>::erase`: infocenter's
copy composes into legoworld's object at **masked nd 0, 1106 = retail's 1106**,
with relocation offsets, types and target names all identical and the line table
identical apart from its symbol sentinel.

The earlier apparent losses were confounded. A frozen-input A/B/A2 proof hashed
all 122 response-file objects plus every resolved library/DEF input, linked the
seed, changed only the 36 non-relocated target-code bytes, linked the candidate,
then restored and relinked the seed. The two seed reports were identical; the
candidate changed exactly `0x1001d890` from nonexact to raw 1.0 and lost no row.
The source-generated donor is excluded from the link. Class C is therefore
landed, while any future use still requires its own full zero-loss gate.

## 7. Class D — `retail_exact_target_closure`

The user authorised a narrower proof basis for authentic cross-module or
cross-rendering extraction: the donor need not be a whole-object recompile when
only one compiler-produced target closure is copied and the seed keeps every
other definition. This does **not** weaken ordinary B4. A separate class replaces
only B4's two global-equality premises with stronger target-extraction premises:

1. The complete seed and donor source renderings remain SHA-pinned. Unique
   function-boundary markers select a complete target range, and byte, size,
   line-count and significant-token pins prove that range identical in both.
2. Seed and donor section counts are pinned. The donor function multiset must be
   a strict subset: it may add none and may omit exactly the sorted manifest list.
3. The broader primary-COMDAT identity multiset—owner name/type/storage, section
   kind, selection and associative-child names—must also be a strict subset.
   This prevents a hidden added or exchanged data COMDAT from balancing an
   omitted function.
4. Every donor relocation is represented by one ordered, non-overlapping oracle
   record. The record pins offset, type, addend, COFF target identity and symbol
   metadata. Its operand is decoded directly from the SHA-pinned retail window;
   DIR32 and REL32 must resolve to the declared retail symbol base before any
   relocation mask is applied.
5. Compiler-local targets outside the copied closure require exact shared-section
   header, definition-auxiliary, raw-byte, relocation-table and line-table
   identity. Ordinary targets resolve unambiguously into the seed symbol table.
6. All existing seat, span, COMDAT selection, FPO/debug closure, line-table,
   relocation rewrite and output-conservation checks remain. The output must
   retain the seed's complete function set and every non-target seed section;
   the donor object is explicitly excluded from the link.
7. The donor recipe has a class-specific recursive leaf policy. It permits only
   non-emitting declaration/layout generators plus line reservation. Every
   introduced top-level declaration identity must be fresh and unique in the
   clean translation unit, preventing an entropy declaration from changing
   lookup of an existing name. Every
   destructive replacement must be outside the target, remove exactly one
   authenticated complete definition, preserve its physical line count, and be
   bound by symbol and qualified source identity to a definition retained in
   the seed/output. Archive pulls, probes, suppliers, constants and live body
   statements are refused even if the resulting target happens to match retail.

`0x1009f490 CalculateCameraTransform` is the first customer. Its target source
window is 2,283 bytes/97 lines and is identical in seed and donor. The donor
hides only the later `Interpolate` definition from this compile, making VC4.2
preserve the source's apparently unused call just as retail did. It has 400
sections/129 functions versus the seed's 406/131, omitting exactly
`Interpolate` and `Matrix4::Scale`; the composed output retains all 406/131.
The 1,121-byte body is retail-exact under 13 semantically authenticated
relocations, including the trailing `Interpolate` call at offset 905.

A tempting source rewrite, `RotateZ(z)`, was tested in a shadow compile and
rejected: it produced 1,105 bytes and 12 relocations, not retail's 1,121/13.
The landed route changes no target source logic. Full gates measured
4860/4934 from 4859/4934, exactly one gain at `0x1009f490`, zero losses, with
ISLE and CONFIG still literal-byte identical.

## 8. Class E — `retail_exact_instruction_mosaic`

This class is a narrow same-function construction, not a general binary patch:

1. Seed and every donor are freshly compiled from the current checked-in
   translation unit. A donor may differ only by a manifest-declared
   non-emitting declaration carrier or a closed, source-window-pinned source
   permutation, and is never linked.
2. The exact mangled function, section seat/count, body length, COMDAT
   selection, function multiset, primary-COMDAT identity multiset,
   relocation/line counts and debug/EH closure must agree. Seed and donor
   relocation semantics must be identical. Structurally identical
   compiler-local `$L`/`$T` serial renames are allowed; a same-named ordinary
   target may occupy a different section seat only when both uniquely resolve
   to the identical primary COMDAT identity. The general relocation comparator
   remains strict; this reseating rule is mosaic-specific because the output
   retains the seed relocation table.
3. Every imported range is a sorted, non-overlapping, manifest-pinned complete
   x86 instruction, or a bounded sequence of complete instructions, at the
   same offset. Both seed and donor encodings, instruction partitions and
   SHA-256 values are pinned. Multi-donor rows name the supplying donor on
   every range and must use every declared donor through that closed set. A
   range may contain a
   relocation operand only when the complete operand lies inside the same
   instruction in both objects, its ordered relocation record and semantic
   target are identical, and its raw bytes are identical. Partial overlap,
   shifted/unpaired operands or changed operand bytes are refused.
4. The output starts as the seed object and changes only those target-text
   bytes. It retains the seed relocation table, line table, debug/EH children,
   function set and every non-target byte. A complete ordered semantic
   relocation oracle binds the result to the SHA-pinned retail image, and the
   final body must be byte-exact under that relocation mask.
5. Cross-function or merely similar-function instruction borrowing is
   forbidden, regardless of apparent instruction equivalence.

The first customers are `0x1009a8c0 LegoWEGEdge::LinkEdgesAndFaces` (four
instructions/four changed bytes) and `0x100c3750 MxRegion::AddRect` (ten
instructions/ten changed bytes). Fresh source regeneration plus the complete
gate raised LEGO1 from 4864/4934 to 4866/4934 with exactly those two gains and
zero losses. `0x1007ca30 LegoPartPresenter::Read` is the first relocation-
containing customer: four complete instructions change four non-relocation
bytes in its 2,633-byte body, while two unchanged `_Nil` DIR32 operands are
fully contained and verified by the 111-row oracle. Its fresh confirmation
raised LEGO1 from 4867/4934 to 4868/4934 with exactly one gain and zero losses;
ISLE remains 172/172 and CONFIG 111/111.

`0x100586e0 LegoPathBoundary::RemovePresenter` is the first two-donor source-
permutation customer. The checked-in standalone-iterator form remains the
canonical seed because landing the authentic for-initializer form directly
perturbs an existing exact row. One fresh declaration-carrier donor supplies
six complete instruction sequences; one fresh, closed old-to-for-initializer
source donor supplies the seventh. Both define the exact same mangled 314-byte
COMDAT. The output retains all seed relocations, line/FPO/debug data and every
non-target byte, and both donor objects are excluded. Its confirmation gate
raised LEGO1 from 4868/4934 to 4869/4934 with exactly that gain and zero losses;
ISLE remains 172/172 and CONFIG 111/111.

## 9. Class F — `retail_exact_source_target_closure`

This class covers a donor-private, manifest-declared source permutation whose
retail-exact target has a different length/relocation closure and whose donor
object may emit unrelated extra COMDATs. It remains seed-authoritative:

1. The target translation-unit text and complete target source window are
   identical in seed and donor. Header permutations use closed typed generators
   and an explicitly selected path-preserving private source-root projection;
   flattened basename overrides are forbidden for this class.
2. The same mangled target COMDAT, section/closure seats, section counts, seed
   body, donor body, debug/xdata hashes, relocation/line counts and complete
   retail semantic-relocation oracle are pinned.
3. A donor target absent from the seed may become one appended undefined
   external only when its exact name is declared in the manifest and the donor
   symbol has value zero, function type and external storage. The output checks
   its name/value/type/storage and the retail oracle proves its linked target.
4. Composition reuses the same-slot resize machinery. The donor target body and
   normalized closure are installed, but every non-target seed section/function
   is retained byte-for-byte and the donor object is excluded from the link.

The first customer is `0x100a4420 OrientableROI::OrientableROI`. Its donor-only
header permutations make VC4.2 emit the retail 514-byte constructor and the
otherwise-inlined `Vector3(float*)` call. All 23 relocation targets are retail
authenticated. The confirmation gate raised LEGO1 from 4866/4934 to 4867/4934
with exactly that gain and zero losses; ISLE remains 172/172 and CONFIG 111/111.
