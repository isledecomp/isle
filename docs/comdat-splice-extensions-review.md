# Specification review — the two COMDAT-splicing extensions

Reviewer: lane B10, wave 15. Contract reviewed:
`docs/comdat-splice-extensions-spec.md` (`2a72627b`).

**Status: red-first stage complete, implementation NOT started.** Twelve tests
are written and observed failing. Three corrections below are material — one
of them changes extension A's scope — so this is reported before implementing,
as instructed.

The good news first: for `0x1003cf20` the design is **sound and much smaller
than the spec assumes**. Every `same_slot_resize` precondition already passes
on the real seed/donor pair. Exactly one thing blocks it.

## 1. What the real row actually needs — measured

Seed = today's shipped compile. Donor = the out-of-line-definition compile
proven in wave 14.

| precondition | result |
|---|---|
| section seat, global section count, function multiset | PASS |
| header name / **relocation_count** / characteristics | PASS |
| line counts, COMDAT selection, closure is the EH pair | PASS |
| closure seats, xdata + debug$S section shapes | PASS |
| xdata raw bytes equal | PASS |
| xdata relocation pairing | PASS |
| debug$S relocation pairing | PASS |
| **primary relocation pairing** | **FAIL — `primary: relocation target differs`** |

The primary table, ordinal by ordinal, is identical except **one** entry:

```
  6  off 160/147  ??3@YAXPAX@Z  ->  ??1LegoCacheSoundEntry@@QAE@XZ   SUBSTITUTED
 11  off 254/238  $T65444       ->  $T65428                          local rename
```

Ordinal 11 is a compiler-local `$T` serial rename, which the existing pairing
machinery already tolerates. **Ordinal 6 is the whole blocker.**

## 2. Correction 1 — B's trigger is not "the count changes"

§2 motivates the class with "a call IS a relocation, so an inline flip changes
the relocation set by construction", and cites `0x1009f490` at 12 vs 13.

For `0x1003cf20` the counts are **equal: 14 and 14.** The flip does not add a
relocation, it *substitutes* one — inlining the entry destructor brought its
own `operator delete` call along, so calling the destructor instead removes one
`??3@YAXPAX@Z` and adds one `??1LegoCacheSoundEntry@@QAE@XZ`.

**Consequence:** a class that only relaxes the count-equality check would not
land this row. It must handle *equal count with a substituted global target*.
Conversely, and usefully, **B7's relocation-table rebuild is not exercised
here at all** — with equal counts the existing in-place rewrite loop works,
and the only change needed is that the substituted ordinal must write the seed
symbol index **of the donor's target name** instead of blindly reusing
`left["symbol_index"]`. The table-rebuild-and-reindex path the wave brief
flagged as the risky part is required only by `0x1009f490`, which is another
lane's row.

## 3. Correction 2 — B5 as written rejects the row it is meant to land

B5: "*every* relocation in the donor body names a symbol the seed object
already defines or declares."

Measured: the donor's `$T65428` is **absent from the seed**, and necessarily
so — `$L`/`$T`/`$S` serials are assigned per compile and will essentially never
agree between two different compiles of a TU. Enforcing B5 literally fails on
ordinal 11 before it ever reaches ordinal 6.

**Proposed wording.** B5 applies to **external/global** relocation targets
only. Compiler-local `$L`/`$T`/`$S` targets are instead paired by role and
consistently mapped, exactly as `_pair_same_slot_relocations` already does
today, and their existing structural checks (same kind letter, same target
type and storage, same role) continue to carry the proof. This keeps the
safety property that matters — *we never invent a reference to a symbol the
seed does not have* — without contradicting the framework's own local-rename
discipline.

## 4. Correction 3 — extension A must be able to render a HEADER (scope change)

§1 says the op-list applies to "the donor's rendered copy of **the TU**".

For `0x1003cf20` that is not sufficient. The only route to the correct body is
the out-of-line definition, which spans two files: delete the inline body from
`LEGO1/lego/legoomni/include/legocachesoundmanager.h` **and** insert the
definition into the `.cpp`. A `.cpp`-only rendering does not compile — verified,
not assumed:

```
s.cpp(72) : error C2084: function 'LegoCacheSoundEntry::~LegoCacheSoundEntry(void)'
                         already has a body
```

Mechanically this is easy and *strengthens* the argument rather than weakening
it: the donor already compiles in its own probe directory with
`/I{source.parent}` seated first, so a privately rendered header shadows the
real one for that one compile only. Every other TU — including all 16
includers — still compiles from clean checked-in source, which is precisely
why the token-stream perturbation that caused wave 14's −48 never happens.

**But it is a real broadening of the contract** (a donor now compiles against a
header that differs from the shipped tree), so it needs explicit sanction
rather than my improvisation. Suggested shape: the recipe carries a list of
`{path, clean_sha256, rendered_sha256, operations}` renderings; A2 becomes
"no path's **seed** rendering changes"; A3 pins every rendered sha.

## 5. B1 — verified end to end on the real row before writing any of it

```
legobin sha256 : 14645225bbe81212e9bc1919…
manifest pin   : 14645225bbe81212e9bc1919…   PIN MATCHES
retail body    : 258 B at file offset 0x3c320   (va 0x1003cf20)
donor body     : 258 B
relocations masked: 14
masked nd      : 0        B1 SATISFIED
```

**One API note.** B1's extraction needs a PE reader and the pinned image; unit
tests cannot ship a DLL. The clean split is that the **build** performs the
pinned extraction (it already validates `images/LEGO1/original_sha256`) and
passes the extracted body to the composer, which enforces length and
masked-nd-0. The tests are written against
`compose_retail_exact_reloc_divergent(seed, donor, function, retail_body)`.

## 6. The tests — twelve, all red

`tools/tests/test_comdat_splice_extensions.py`. Eleven are §4; a twelfth is a
positive control, because a class that rejects everything would pass §4
vacuously.

The fixture is validated to model the real row rather than merely to exist:
it parses, carries a complete EH COMDAT closure, has equal relocation counts,
one global substitution plus one `$T` rename — and fails today with the
**identical** error string the real objects produce:

```
--- ordinal relocation pairs ---
  0: ?Common@@YAXXZ         -> ?Common@@YAXXZ
  1: ?SeedCallee@@YAXXZ     -> ?RetailCallee@@YAXXZ   SUBSTITUTED
  2: $T100                  -> $T200                  SUBSTITUTED
--- what same_slot_resize says today ---
  ByteIdentityError: primary: relocation target differs
```

Red output:

```
Ran 12 tests in 0.003s
FAILED (errors=12)
AttributeError: module 'byte_identity' has no attribute
                'compose_retail_exact_reloc_divergent'
```

The existing suite is unchanged: **56 collected, 3 skipped, 53 green.**

## 7. Recommendation

Approve corrections 1–3 and I implement immediately. Correction 3 is the only
one that needs a judgement call rather than a wording fix; without it this row
cannot be landed by extension A at all, because the fix is not expressible in
the `.cpp` alone.

Scope discipline holds either way: this buys `0x1003cf20` now and
`0x1009f490` for whichever lane owns `legoanim.cpp`. Nothing here helps the
~75 allocator rows or goal 2, and none of it should be generalised further.
