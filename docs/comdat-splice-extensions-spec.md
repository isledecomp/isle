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

`0x100c6fa0 MxDSBuffer::FUN_100c6fa0` is the first source-permutation mosaic
whose supplying COMDAT has a different body length. A closed five-fragment
manifest contract declares a cursor snapshot and tail-return spelling; no
function-specific source text appears in the framework. The fresh donor is
225 bytes and the canonical seed is 234 bytes, but the imported range is an
equal-width sequence of two complete four-byte instructions at seed offsets
161--168. The donor's short-body branch and all donor metadata remain unused.
The output keeps the complete seed body outside that range, all seed
line/FPO/debug data, the seed function/COMDAT sets and every non-target byte.
Its 234-byte body is literally retail-exact (there are no target relocations),
and the donor object is excluded from the link. The confirmation gate raised
LEGO1 from 4869/4934 to 4870/4934 with exactly this gain and zero losses; ISLE
remains 172/172 and CONFIG 111/111.

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

## 10. Class G — `retail_exact_cross_tu_instruction_hybrid_resize`

This class covers the narrow case where a clean current-source translation
unit emits the one retail instruction needed by a differently sized target
donor for the exact same mangled COMDAT. It composes an internal hybrid first,
then delegates the finished hybrid to the unchanged same-slot resize path:

1. The target donor is a fresh declaration-only carrier over the current
   effective target translation unit. The instruction donor is a different,
   SHA-pinned checked-in translation unit compiled unmodified through its own
   pinned compile command. It is declared and consumed exactly once, solely in
   this instruction-donor role. Both donor objects are excluded from the link.
2. Both objects must define the exact same mangled primary COMDAT with equal
   COMDAT selection and associated-child names. Their independent body,
   section-count, section-seat, relocation-count and line-count facts are
   pinned; section seats and body lengths need not be equal.
3. Every transfer is a sorted, non-overlapping, equal-width complete x86
   instruction at independently declared source and target offsets. Both byte
   strings and their SHA-256 values are pinned. The live composer binds each
   COFF line-table sentinel to the unique exact target definition, selects the
   nearest non-sentinel compiler line row at or before the range, and decodes
   continuously through both endpoints in both objects. The isolated range
   must also be exactly one instruction in the closed IA-32 grammar. Thus a
   byte string that happens to decode in isolation but starts inside another
   instruction is refused. Any overlap with a relocation operand in either
   object is refused.
4. The internal hybrid changes only the declared target-donor instruction
   bytes. It retains the target donor's relocations, line/debug/FPO data,
   closure and non-target bytes. Same-slot resize then installs that hybrid
   while retaining the canonical seed's non-target sections and functions.
5. A complete semantic relocation oracle binds the result to the unique pinned
   retail image for the owning translation unit's target, and the final target
   body must be byte-exact under that mask. Similar functions, different
   mangled names and non-current artifact provenance are never admissible.

The first customer is `0x10059dc0 _Tree<LegoTextureInfo*>::erase`. Its fresh
1,102-byte target donor differs from the 1,104-byte clean cross-translation-
unit donor, but both define the same mangled COMDAT and compatible child
closure. One complete four-byte instruction, `394c2410`, moves from donor
offset 145 to target offset 151 and replaces `3b4c2410`; neither range overlaps
a relocation. The resulting body SHA-256 is
`851f0e9a57984afaf02ecf6d1e52c5ad0daae945e12b8cd820e58759e2c6787a` and
is retail-exact under all 16 authenticated relocations. The final object keeps
the target donor's relocation/line/debug/FPO metadata and the canonical seed's
non-target contents. A forced-fresh confirmation raised LEGO1 from 4870/4934
to 4871/4934 with exactly that gain and zero losses; ISLE remains 172/172 and
CONFIG 111/111.

## 11. Typed fixed-array-fill source-permutation profile

`fixed_array_fill_loop_v1` is a closed source-derived profile of Class E. It
does not admit arbitrary statement text:

1. Its six manifest parameters name one array, one fresh local index, one
   closed integral index type, a literal bound, the exact value `-1`, and
   indentation. The inverse renderer must reproduce the complete checked-in
   `memset(array, -1, sizeof(array));` line byte-for-byte; the forward renderer
   emits exactly one `for` line. Layout overrides and extra fields are refused.
2. The literal bound is not trusted independently. A whole-file-SHA-pinned
   header proof must identify one unique depth-one integral member-array
   declaration with the same array name and extent. The declaration line is
   byte/token pinned, its header must be the unique ordinary checked-in file
   of that basename, and the target translation unit must directly include it
   through one exact pinned quoted-include line.
3. The source class named by the selected brace-balanced function window must
   equal the declaration owner and the exact owner component extracted from a
   closed MSVC constructor/destructor/ordinary-member decoration. Substring
   owner matches are forbidden. The array identifier may occur in that window
   only in the two positions of the authenticated `memset`; a same-named
   parameter, local, or other reference refuses, preventing declaration
   shadowing from invalidating the extent proof.
4. The index type is selected from a closed integral spelling set wide enough
   for the admitted 1--4096 extent, and the index identifier must be absent
   from the complete target window. The value is exactly `-1`; pointer,
   const-qualified, class, arbitrary named and eight-bit index types are
   rejected.
5. The permutation is donor-only and manifest-wide role confined: its recipe
   has exactly one total primary donor use, that use is the one source-aware
   binding, and variant, instruction-donor or other non-primary reuse is
   forbidden. The checked-in/effective seed translation unit remains
   unchanged, the donor object is excluded from the link, and the instruction
   mosaic retains every seed byte outside authenticated complete target
   instructions, including all non-target functions and seed
   relocation/line/debug/EH metadata.

The first customer is `0x10017af0 PizzeriaState::PizzeriaState`. Landing the
typed loop directly perturbs the already-exact `Serialize`, so the canonical
source retains its whole-array `memset`. A fresh private rendering emits
`for (MxS32 i = 0; i < 5; i++) m_states[i] = -1;`, with `5` structurally bound
to the pinned `MxS32 m_states[5]` declaration in the directly included header.
The seed and donor are both 264 bytes with 17 equivalent semantic
relocations. Three complete instruction sequences at offsets 186--197,
202--209 and 211--219 produce body SHA-256
`12d517ae112fa47477a5f6e35e0361641ad502c057ef64df08aeef8160da48d6`.
The final object keeps the canonical seed's nine-row line table and metadata
closure; the fresh eight-row donor is only an instruction source. The
forced-fresh confirmation raised LEGO1 from 4871/4934 to 4872/4934 with
exactly this gain and zero losses; ISLE remains 172/172 and CONFIG 111/111.

## 12. Typed inclusive-extent source-permutation profile

`inclusive_extent_assignment_v1` is a closed source-derived profile of Class
E for an inclusive-coordinate extent. It is not a general expression or inline
assembly generator:

1. Its manifest parameters name one closed integral coordinate type, one local,
   one source object plus aggregate accessor, three distinct extent/endpoint
   accessors, one destination object/member, indentation and the single barrier
   enum `msvc_i386_empty_inline_assembly_v1`. The inverse renderer must
   reproduce the complete checked-in
   `destination = source.aggregate().extent();` line byte-for-byte. The forward
   renderer emits only a typed `upper - lower` declaration, prefix increment,
   the exactly guarded empty MSVC/i386 assembly block, and the same destination
   assignment. Extra fields, layout overrides, arbitrary types, repeated roles
   and any other barrier are refused.
2. The algebraic equivalence is source-proved rather than asserted. Three
   whole-file-SHA-pinned headers must be connected to the target translation
   unit by an exact three-edge chain of uniquely resolved quoted includes. The
   selected source owner has one pinned member declaration of the source type;
   that type has one pinned side-effect-free aggregate accessor; and the
   aggregate template has pinned lower, upper and inclusive-extent accessors.
   Their token forms must be exactly `return lower`, `return upper` and
   `return (upper - lower + 1)`. A pinned concrete public inheritance binds the
   aggregate to the same integral coordinate type used by the generated local.
   The complete concrete class body is also byte/token pinned, and it must
   contain no class-scope occurrence of any witnessed accessor name; a derived
   declaration or overload that could hide an inherited accessor refuses.
   All three witness headers are globally forbidden from the effective source
   overlay, so the bytes certified here are exactly the bytes seen by the
   compiler.
3. The selected brace-balanced source window must have the exact class owner
   extracted from the closed MSVC decorated member name, and that decorated
   name must be the mosaic target. The authenticated source member may not be
   a parameter or local redeclaration. The generated local must be absent from
   its destination block and every visible ancestor scope; a same spelling in
   a lexically disjoint sibling scope is admissible because it cannot be
   observed at the insertion seat.
4. A donor based on a translation unit with an existing shipped source overlay
   must replay every canonical operation byte-for-byte. Those operations are
   matched by normalized operation identity, may only be non-destructive
   insert/append operations outside the selected target, and may neither be
   omitted nor modified. This lets the private donor begin from checked-in
   source and reproduce the current effective source without weakening the
   clean-input rule.
5. The permutation is donor-only and manifest-wide role confined: exactly one
   total primary use, exactly one source-aware binding and no variant,
   instruction-donor or other secondary use. Composition imports only pinned
   complete same-offset instructions from the exact same mangled COMDAT. The
   output retains every seed non-target byte and all seed relocation, line,
   debug and FPO metadata; the donor object is excluded from the link.

The first customer is `0x100ba7f0 MxDisplaySurface::Create`. Its canonical
660-byte seed remains authoritative because the direct source donor perturbs
six other function bodies, including a length change in an already composed
non-target. The private rendering replaces one authenticated width assignment
with an `MxS32` right-minus-left value, increment and the closed empty barrier.
The same-mangled donor is also 660 bytes with the same three semantic
relocations. One complete 12-byte instruction sequence at offsets 489--500
changes the `[11, 1]` seed partition to the donor's `[1, 11]` partition and
produces body SHA-256
`966cdf3a4b96d872beb6b04c4b9568ba19767cc7975e17bcb77fa3bbf687b11b`.
The composed object retains the seed's 57-row line table, complete
`.debug$F`/`.debug$S` closure and every non-target byte; the 58-row donor is
only an instruction source. A marker-removed forced-fresh confirmation raised
LEGO1 from 4872/4934 to 4873/4934 with exactly this gain and zero losses; ISLE
remains 172/172 and CONFIG 111/111.

## 13. Class H — `retail_exact_source_instruction_hybrid_resize`

This class is the source-aware same-translation-unit counterpart to Class G.
It admits a donor-private typed source permutation only as an instruction
source, constructs a same-length hybrid over an ordinary carrier donor, then
passes that hybrid to the unchanged same-slot resize composer:

1. The source permutation must inverse-render the checked-in input bytes and
   render its output from a closed typed generator. It must replay every
   canonical operation on the owning translation unit exactly. The shipped
   source overlay explicitly rejects the generator, so the alternate spelling
   can never become the ordinary linked source by schema accident.
2. Raw-manifest preflight inventories source-permutation recipe IDs from the
   donor recipes themselves, before host-dependent checks. Each recipe must
   have exactly one authenticated binding and exactly one use in the role that
   binding declares. An instruction donor may not also be a primary donor,
   variant or unbound secondary donor; an entirely unbound recipe is fatal.
3. Seed, carrier donor and instruction donor independently pin body and
   metadata hashes, section seat/count, relocation/line counts, full
   function/primary-COMDAT censuses and exact associative closure. The two
   donors define the same mangled primary COMDAT. Both donor objects are
   excluded, and the output retains the seed's complete non-target object.
4. Each transfer is one supported complete IA-32 instruction, not a
   manifest-attested width. The shared decoder handles only the opcodes
   traversed by accepted Class G/H objects—`0x33`, `0x39`, `0x3b`, `0x75`,
   `0x76`, `0x80`, `0x83`, `0x89`, `0x8a`, `0x8b`, `0xff`, `0x46` and
   `0x47`—with deterministic ModRM, SIB, displacement and immediate widths.
   `0xb8`--`0xbf` exists solely to exercise the adversarial immediate-move
   regression. In both fresh objects, decoding
   begins at the nearest validated compiler line row and must place both range
   endpoints on boundaries. The regression `b8 83 c0 04 00` therefore rejects
   the apparently valid isolated `83 c0 04` subrange.
5. The hybrid keeps the carrier donor's complete metadata/closure and changes
   only the declared instruction bytes. The existing resize composer installs
   that hybrid into the canonical seed while preserving every seed non-target
   byte. A complete ordered semantic-relocation oracle binds all relocations to
   the owning target's unique pinned retail image.

The first customer is `0x10069b10 LegoAnimPresenter::BuildROIMap`. The checked-
in discarded postfix increment remains canonical because the direct prefix
form changes 40 shared bodies and emits an extra COMDAT. The closed
`discarded_postfix_increment_v1` generator replaces exactly `it++;` with
`++it;`; a compiler-state carrier is declaration-only. Its semantic witness
binds the unique loop local to `LegoAnimStructMap::iterator`, proves the full
project/header chain into the sealed VC4.2 `map`, `xtree`, iterator, utility and
memory definitions, and pins both overloads. Prefix performs exactly `_Inc()`;
postfix copies the iterator, invokes prefix once and discards the result. The
iterator has only one raw node-pointer member, empty iterator bases and no
user-defined copy, assignment or destructor effect, so the discarded
temporary adds no observable state.

The canonical pre-row seed is 622 bytes. The ordinary `pad_shape(92,22)`
carrier donor and the typed source donor are both 617 bytes, with body hashes
`1c38ac46a87c57b508c7f242095c8dd73d2a77e14accf3360844a115fc123dad`
and
`364432067111842fc7913ceab0a82c61f377a99f2348b4da834f87df12b50a2c`.
Eleven complete same-offset ranges are imported at 303--304, 344--345,
355--356, 366--369, 378--380, 416--418, 419, 426--427, 447--449, 532--534
and 538--540. The adjacent 416--419 and 419--420 ranges remain separate
three-byte and one-byte instructions. The hybrid body SHA-256 is
`43e4ef651a4d79561d766737b64ff6597055163640bd6bd3484f2df8979d0373`;
all 23 relocations are retail authenticated, while the carrier donor's
25-row line table and `.debug$S`/`.xdata$x` closure remain authoritative.

The packet objects were evidence only. Their longer scratch build-root name
made VC4.2 allocate 28 extra `.file` auxiliary symbol records. Canonical fresh
objects had identical bodies, source basenames, source/header renderings,
semantic line rows, semantic primary/child relocations, closure and complete
function bodies, but shifted raw symbol indices. Only the runner-authentic
metadata pins changed, to `9162966902f2e893b7eedc7fb26a7d09d2eb90d4dbe42f208a97f1d38d5305ea`
for the carrier and
`62b0b69aead015aa21df70e097ac8184af66572c85b6aa7988bf77789dcbe630`
for the source donor.

Discovery raised LEGO1 from 4873/4934 to 4874/4934 with the sole gain at this
address and no loss; its report SHA-256 is
`e7b9ca57fc3e8dbf9a2326cecf6c551bc6d58b632e00b790bb611c59dc859909`.
A marker-removed forced-fresh confirmation held 4874/4934 with zero delta;
ISLE remained 172/172 and CONFIG 111/111. Its report SHA-256 is
`616b87401af356edb31b9d320f17482480a2eb0b10017169d5aa7df87ed972fe`
and verdict SHA-256 is
`407a0dfcdb5e99a8915e50566d216960b5f8c95f2277c712cb9b528cfcd3b623`.

## 14. Class I — `retail_exact_same_tu_instruction_hybrid_resize`

This class is the source-identical same-translation-unit sibling of Classes G
and H. Two closed declaration-only carrier states compile the same effective
target source. One supplies the resize closure, the other supplies only
complete instructions, and the resulting hybrid enters the unchanged
retail-exact same-slot composer:

1. `prefix_forward_after_includes_extern` is the only admitted donor recipe.
   It renders one typed forward-declaration run at byte zero and one typed
   extern-object run immediately after the last include. The widths are fixed
   at three and two digits. Exact prefix, adjacent-line and centered-context
   witnesses authenticate both seats; the combined declaration bytes and full
   rendered source are SHA/size/line pinned. Every introduced identifier must
   be unique between the runs and absent from the effective source, so the
   carrier cannot redeclare or make visible a name used by the program.
2. A unique exact function marker selects the complete brace-balanced target
   source through the physical LF after its closing brace. The range's bytes,
   line count and significant tokens are pinned and must be identical in the
   effective seed and both freshly rendered donor sources. The proof's exact
   decorated owner is the composed same-mangled definition in all three
   objects; no alternate source or retained object is admissible.
3. Raw-manifest preflight inventories the carrier recipes themselves. Each is
   bound exactly once in one translation unit: the target carrier has exactly
   one primary use and the instruction carrier exactly one secondary use.
   Ordinary, variant, repeated, swapped-role and unbound uses fail before
   host-dependent validation. Both private donor objects are excluded from
   the linked output.
4. Seed and donors pin body and metadata hashes, section seat/count,
   relocation/line counts, function/primary-COMDAT censuses and the complete
   associative closure. The two donors must have identical topology and
   semantic relocations. Each transfer is the same-offset whole instruction
   in both bodies, certified by the exact-function COFF line sentinel and the
   nearest-line-row containing-stream decoder, and may not overlap a
   relocation operand. The hybrid changes only declared code bytes and keeps
   the target carrier's entire metadata closure.
5. The donor's rounded contribution span is authoritative. The canonical seed
   may have occupied a smaller prior bucket, provided its byte length does not
   exceed the declared donor span; requiring its old rounded span to match
   would wrongly reject a genuine boundary-crossing resize. The unchanged
   composer retains every canonical non-target byte while installing the
   hybrid target closure. A target-bound retail image and complete ordered
   relocation oracle prove the final body.

The first customer is
`0x100a66f0 ViewManager::ManageVisibilityAndDetailRecursively`. Its canonical
pre-row seed is 557 bytes. The two source-identical declaration carriers use
34 and 64 prefix declarations plus the same three after-include externs; they
produce 561-byte target bodies
`b1271a13524dc400bf0305b25b45d49fc8b9cff06bf5f4376cbf5c4b7bb97f2b`
and
`a3e8fd96e27f02f4ede351f764216c2361969b3552d423b2a2fc3362f529321e`.
Their target topology is identical at section 116 of 250, with 11 relocations,
28 line rows, 80 functions, 85 primary COMDATs and the complete
`.debug$F`/`.debug$S` closure. One line-certified two-byte instruction at
offsets 516--517 changes `3bc8` to `3bc1`, producing hybrid body SHA-256
`01949ffd3e0c851db40055f6a1c5978091144dea8b2de977502762fe061c76e8`.
The 561-byte donor rounds to the authoritative 576-byte linked span even
though the 557-byte seed rounded to 560. All 11 relocations resolve to the
pinned LEGO1 retail targets, and every non-target output byte remains the
canonical seed's.

The scratch packet objects were evidence only; the canonical runner freshly
regenerated both donors from the checked-in effective source and the two
manifest recipes without a pin drift. Discovery raised LEGO1 from 4874/4934
to 4875/4934 with this sole gain and no loss; report SHA-256 is
`e9e6f5413e72eceeec406ce46eab04dafa2ab50223a217ea7d9562fec384c5b9`.
A marker-removed forced-fresh confirmation regenerated the seed, both donors
and composition, held the identical 4875 accepted set, and left ISLE at
172/172 and CONFIG at 111/111. Its LEGO1 report SHA-256 is
`fda4683e20e1d7f4a03e8a080130f2d062720daeb905dd855cd590c7317042d1`
and verdict SHA-256 is
`32b792741c0bb1b7fe021b29c53e65aff7361d89992170ebfdb6a0b36765b9ea`.
The final manifest SHA-256 is
`ca98ce3721d3cfd7e54787e47c1843ec69ab771a30ed16cf01f23fb7c4a80176`.

## 15. Class E ordinary-FPO branch

The ordinary same-TU instruction mosaic has one additional, deliberately
narrow closure profile for classic FPO CodeView output. It does not weaken or
cross the existing EH profile:

1. A declaration-only donor recipe must declare the exact
   `retail_exact_instruction_mosaic_fpo_only_v1` role policy. Raw preflight,
   per-unit validation and manifest-wide validation require exactly one
   primary use, exactly one FPO-aware binding and no instruction, variant,
   source-refactor or other secondary role. The private donor is freshly
   compiled from the owning effective source, then excluded from the archive
   and link.
2. Seed and donor independently pin the primary body and metadata, section
   seat/count, code relocation and line tables, complete function/primary-
   COMDAT censuses, and the exact two-child `.debug$F`/`.debug$S` closure.
   Child order, seat, size, characteristics, selection, association, body and
   semantic relocations are exact. `.debug$F` must be the identical parsed
   classic FPO record with `procSize` equal to the primary length. Each full
   `.debug$S` body is independently pinned; its common `S_*PROC32` prefix must
   use marker `0x0205` and valid equal `cbProc`, `DbgStart` and `DbgEnd` fields.
   The ordinary EH identity and this FPO identity reject one another.
3. Every range is a same-offset sequence of whole instructions. The exact
   target-definition line sentinel and ordered in-body line rows are validated
   in both objects. Decoding starts at the nearest preceding compiler line row,
   must reach both endpoints, and must reproduce the manifest's exact
   instruction-length vector. The fail-closed live extension admits only
   `01`, `03`, `2b`, `0f af`, `41`, `43`, `45`, `74`, `7c`, `7d`, `7f`,
   `eb`, and `f7 /3` beyond the already accepted decoder families. Mid-start,
   mid-end, same-sum repartition, unsupported opcode, malformed `0f`, and
   non-`/3` `f7` cases are fatal.
4. The result changes only the declared primary code bytes. It retains the
   seed's complete code relocations, line table, `.debug$F` and `.debug$S`
   children, raw metadata, FPO/CodeView facts and every non-target byte. The
   full ordered retail relocation oracle and literal retail body remain the
   final authority.

The first customer is `0x100bb1d0 MxDisplaySurface::VTable0x30`. Its canonical
seed and fresh `declaration_shape(4,27)` donor are both 811 bytes at section 51
of 88, with two relocations and 44 line rows. Their bodies are
`0e6db537fdd488dac53f74ca9d45e2060a52c637b7236305593aaa644b521630`
and
`86be2090dc2f9e3604436b8a7d343d6f598fef2decc878eb75114b85aef193c4`;
the seed-authoritative output body is
`9fba51eb1777b626f4ff595f7789292b9d2dfe17772f535a6acbaf6882b0594d`.
The exact half-open imported ranges are `[337,360)`, `[389,398)`,
`[400,429)`, `[444,453)`, `[472,473)`, `[481,490)`, `[491,499)`,
`[549,568)`, `[604,613)`, `[615,637)`, `[648,650)`, `[711,720)` and
`[721,729)`. Donor-only changes beginning at 499, 506, 729 and 736 are not
imported. The two retail relocations resolve to the pinned rectangle-
intersection and transparent-RLE targets, while the seed metadata SHA-256
`53262ef7c4ccc08c022ba8173dd20b759281086dcf2e3d37241f453ee76d194f`
and exact `.debug$F`/`.debug$S` closure remain authoritative.

Discovery raised LEGO1 from 4875/4934 to 4876/4934 with this sole gain and no
loss; report SHA-256 is
`d57c52a00d76ec86de9b6fca065be39c9e25d60a1fdd00eb223775ead3996dce`.
A marker-removed forced-fresh confirmation regenerated the eight-function TU
composition and marker, held the identical 4876 accepted set with zero delta,
and left ISLE at 172/172 and CONFIG at 111/111. The regenerated marker SHA-256
is `6fca23e5f3864bb247477997e6fb33019d9546d514413476d6c353c42522a963`;
the confirmation LEGO1 report SHA-256 is
`4826fca34cc7d0529e189e714a0a66330a32ae7e7339ea51bc80f25ef95e7ead`
and verdict SHA-256 is
`62e74837bf86d0430cd1047af4b044db6aacd2532fb46c4d5d90e25ad09755c0`.
The final manifest SHA-256 is
`ba5dca4ab7df9f4331fd973a28661f828f0ff2c95c9e820fec62b826ac2359ae`.
