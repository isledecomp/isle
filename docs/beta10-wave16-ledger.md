# Wave 16 — A7 implemented as authorised; one seat still unreachable

**A7 is implemented with all five obligations enforced and tested. The row is
still NOT landed.** A7's three parameters emit exactly one text, and the donor
needs two different ones. Reported rather than widened in place.

Tree: `tools/byte_identity.py`, `tools/tests/test_comdat_splice_extensions.py`,
this ledger. No source change, no manifest change.

## 1. Gate readings, taken by me

| reading | value |
|---|---|
| clean gate, **full 42-unit recompose** | LEGO1 4853/4934, ISLE 172/172, CONFIG 111/111 — PASSED |
| test suite | **74 collected, 3 skipped, 71 green** (53 existing + 18 mine) |

## 2. A7 as implemented

`member_signature_v1`, lean key `member_sig`, parameters exactly
`{class_identifier, member_identifier, kind}`.

* **A7a** — `source_overlay_member_is_declared` strips comments first (so a
  mention in prose cannot authorise a signature) and searches only the named
  class's own brace-balanced body (so a member of *another* class never
  satisfies it). Enforced across the recipe's clean inputs, deferred until all
  are read so a signature seated in the `.cpp` can be authorised by the header
  that actually declares the class.
* **A7b** — `MEMBER_SIGNATURE_KINDS` is a frozenset containing `destructor`
  and nothing else, checked in both the validator and the renderer.
* **A7c** — structural, not merely checked: the parameter set contains no
  return type, no parameter list and no body, so none can be rendered.
  `exact_audit_keys` rejects any attempt to add one.
* **A7d** — `assert_member_signature_is_donor_only` is called from
  `validate_source_overlay`, so the **shipped tree's** overlay is asserted free
  of the generator on every build rather than by convention.
* **A7e** — tests reject four kinds outside the enum, four attempts to smuggle
  a body/return type/parameters, three identifier pairs absent from the
  checked-in source, and a recipe whose signature names an undeclared class.

Rendered output is exactly `\t~LegoCacheSoundEntry();\n` — byte-for-byte the
header text that wave 14 proved yields **258/258, masked nd 0**. So the header
seat is solved.

## 3. Why the row still cannot land

The donor needs two distinct texts from the same three parameters:

| seat | required text |
|---|---|
| donor header | `\t~LegoCacheSoundEntry();` |
| donor `.cpp` | `LegoCacheSoundEntry::~LegoCacheSoundEntry()` |

A single-form generator supplies one of them. A7 authorises one generator with
three parameters and no discriminator, so the second seat is unreachable.

**Both seats are genuinely required — measured, not argued.** The tempting
economy is to delete the declaration from the donor's header entirely and let
the `.cpp` definition stand alone, which would need only the qualified form.
MSVC 4.2 *accepts* that, so it fails silently rather than loudly:

```
v1_pure_delete   COMPILED  len=242 (retail 258)  entry_dtor_calls=0  masked_nd=106
v2_declaration   COMPILED  len=258 (retail 258)  entry_dtor_calls=1  masked_nd=0
```

With no declaration in the class the destructor is implicitly trivial, the
element is destroyed by nothing at the `erase` site, and the body comes out
*shorter* than today's — 242 against our 274 and retail's 258. The out-of-line
definition compiles and is simply never called. So the declaration is
mandatory, and the qualified definition header is mandatory with it.

Nor can the qualified form come from the existing relocated-range mechanism:
the header contains `LegoCacheSoundEntry` and `~LegoCacheSoundEntry()` but
never adjacently as a qualified name, and assembling one from scavenged
fragments would be neither typed nor honest.

## 4. The minimal amendment, if wanted

Add `form` to the parameter set as a **closed enum with exactly two members**:

* `in_class_declaration` → `\t~<member>();`
* `qualified_definition_header` → `<class>::~<member>()`

Every existing obligation survives untouched: A7a still validates both
identifiers against checked-in source; A7b's `kind` enum is unchanged; A7c
still holds, since both forms are signature text with no body, no return type
and no parameters; A7d and A7e are unaffected. The second form is the strictly
smaller of the two — it does not even emit a terminator.

Everything else for the landing is already built and proven: extension B
composes the real row at 258/258 masked nd 0 (wave 15), and the end-to-end
reading was measured at **GAIN 1 / LOST 0**, aligned 1516 → 1850.
