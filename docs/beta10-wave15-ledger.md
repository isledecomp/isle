# Wave 15 — extension B implemented and proven; extension A blocked on grammar

**Extension B is done, tested, and measured end to end: `+1 GAIN, 0 LOST`.**
**Extension A's guards are done. Extension A's *rendering* cannot express this
row's donor without a new typed generator, so the row is NOT landed.**

Tree: `tools/byte_identity.py` and `tools/tests/test_comdat_splice_extensions.py`
only. No source change, no manifest change.

## 1. Gate readings, taken by me

| reading | value |
|---|---|
| clean gate, full recompose of all 42 units | **LEGO1 4853/4934, ISLE 172/172, CONFIG 111/111 — PASSED** |
| test suite | **68 collected, 3 skipped, 65 green** (53 existing + 12 new) |
| measured splice (probe build) | **LEGO1 4854/4934** |
| GAIN / LOST vs baseline, keyed by **address** | **GAIN 1 (`0x1003cf20`) · LOST 0** |
| address-aligned rows | **1516 → 1850** (+334, improved) |

The full recompose is the one that matters for safety: `compose_same_slot_resize`
is shared by 25 pinned functions, and clearing every marker and recomposing from
scratch still yields 4853 with the gate passing. The refactor is
behaviour-preserving.

## 2. Extension B — `retail_exact_reloc_divergent`

Implemented as a mode of the existing same-slot composer, so the intricate COFF
repair logic has exactly one copy. `retail_body=None` reproduces today's
behaviour bit for bit; passing a retail body selects the new class.

What the class actually relaxes, and nothing more: where seed and donor both
name ordinary symbols and **those names differ**, the ordinal is recorded as a
substitution and the donor's target is resolved into the seed's symbol table.
Everything else — role, type, addend, local pairing, closure, multiset, seat,
span, line and debug repair — is unchanged.

`_resolve_substituted_seed_symbol` carries B5/B6: exactly one seed symbol may
bear the donor's name (ambiguity is a hard failure, never a first match), its
type and storage must match, and compiler-local `$L`/`$T`/`$S` targets are
explicitly refused entry — they belong to the rename machinery.

**B1 runs before anything is written.** Length is checked against the pinned
`retail_length`, both bodies are masked at the donor's relocation fields, and a
single differing byte refuses. A post-composition pass then re-reads the
composed object and proves every ordinary relocation now reads as the donor's
target — so the substitution is verified in the output, not merely intended.

### Proven on the real objects, not only the fixture

```
COMPOSED OK   splice_class=retail_exact_reloc_divergent
  seed_length 274 -> donor_length 258      linked_span 272
  substituted_relocations 1                mapped_locals 5
composed body length : 258 (retail 258)
masked nd vs retail  : 0
ordinal 6: symbol_index=202  ??1LegoCacheSoundEntry@@QAE@XZ  section=39
           type=0x20 storage=2
```

Ordinal 11 (`$T65444`) correctly keeps the **seed's** local symbol — the mapping
moves its value, not its name. That was a real bug in my first post-composition
check, caught by the positive control.

## 3. Extension A — guards implemented, rendering blocked

`validate_donor_source_overlay_recipe` enforces A1/A6a (the op grammar admits no
literals), A2/A6b (a hard failure if the shipped tree's renderings are touched),
A3 (clean and rendered shas pinned, and clean drift refuses rather than letting
the donor silently follow the tree), and A5 (every anchor resolved against the
clean input; ambiguity and absence both refuse).
`validate_donor_object_excluded` enforces A4 by comparing hashes rather than
trusting convention.

### The blocker, stated precisely

The donor rendering for `0x1003cf20` needs two things no existing typed
generator can emit:

1. in the header, `\t~LegoCacheSoundEntry();` — a **destructor declaration**;
2. in the `.cpp`, `LegoCacheSoundEntry::~LegoCacheSoundEntry()` — a
   **qualified out-of-line definition header**.

Everything else is already expressible: the body is an authenticated range and
`source_range_relocation_v1` already copies clean source between outputs with a
token pin. But its renderer emits **only** the range — checked, not assumed:
with `byte_destination` set it returns `source_overlay_render_relocated_range(...)`
and nothing else. And `declaration_sequence_v1`'s `function_prototype` shape
always emits a return type and validates its identifier with
`_source_overlay_identifier`, which admits neither `~` nor `::`.

A `.cpp`-only rendering is not an escape — verified:
`s.cpp(72) : error C2084: 'LegoCacheSoundEntry::~LegoCacheSoundEntry(void)'
already has a body`.

Nor can the donor route around it. Deleting some other function from the donor
`.cpp` to shift the inline decision is barred by **B4** (the function multiset
must match the seed); adding functions is barred the same way; adding
declarations is the carrier axis, sealed at ~15,100 cells; adding statements is
the body axis, refuted at 441 cells with a positive control in wave 14.

So the minimum addition is one typed generator emitting a member
declaration/definition signature from `{class_identifier, member_identifier,
kind: destructor}`, with the body supplied by the existing relocated range.
That is small and strictly within A6a's intent — the identifiers come from the
checked-in source and nothing is literal — **but it is source grammar**, which
is the most safety-critical surface in this project and is not what A6
authorised. Reported rather than improvised.

## 4. What is proven, so the decision is cheap

The measurement hook was temporary, env-guarded, and is reverted; it never
touched a committed file. It applied the real class to the real objects inside a
real build:

> **GAIN 1 — `0x1003cf20 LegoCacheSoundManager::~LegoCacheSoundManager`**
> **LOST 0**, aligned 1516 → 1850, LEGO1 4853 → 4854.

So the only open question is the generator, and the answer to "is it worth it"
is already measured rather than estimated.
