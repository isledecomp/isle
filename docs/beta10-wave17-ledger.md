# Wave 17 — `0x1003cf20` landed: 4857 → 4858, LOST 0

A7f implemented; extension A's renderer and build path built; the row landed.
The donor compiles against a private rendering of the header, so the shipped
tree keeps its inline definition and **none of the 16 includers is perturbed** —
which is why the −48 of wave 14 does not occur.

## 1. Gate readings, taken by me

Baseline established by stashing only the manifest change and rebuilding.

| reading | baseline | after |
|---|---|---|
| LEGO1 rows at 1.0 | **4857/4934** | **4858/4934** |
| ISLE / CONFIG rows | 172/172 · 111/111 | 172/172 · 111/111 |
| gate | PASSED | **PASSED** (after repin) |
| **GAIN / LOST** (keyed by address) | — | **GAIN 1 · LOST 0** |
| address-aligned rows | 1970 | **1919** |

* `GAIN 0x1003cf20 LegoCacheSoundManager::~LegoCacheSoundManager` — the only one.
* Full **37-unit recompose from cleared markers**: 4858, gate passed.
* Test suite: **77 collected, 3 skipped, 74 green** (53 existing + 21 mine).
* Repin: `LEGO1: 4857 -> 4858`.

### Two readings reported against myself

**The aligned count fell by 51 (1970 → 1919).** The composed body is 16 bytes
shorter than the seed's, so everything after it in `.text` shifts. On the
wave-15 tree the same splice moved alignment *up* by 334; on this tree it moves
down by 51. Alignment response is a property of the surrounding layout, not of
the splice, and it is a goal-2 cost that came with a goal-1 gain.

**ISLE/CONFIG MD5 identity could not be directly verified**, because the final
gate requires LEGO1 at 4933/4933 and refuses before finalising. What is
verified: their row sets are unchanged (172/172, 111/111) and their aligned
counts are unchanged (171, 105). Their iteration-build image hashes *do* differ
run to run — but a **control of two consecutive builds of the unmodified
baseline shows the same difference**, so that is build non-determinism (PE
timestamps) and not evidence about this change either way.

## 2. A7f

`form` is a closed two-member enum, checked in validator and renderer.
Neither form carries indentation or a line break: the generator emits exactly
the specification's text and the seat's own clean source supplies the rest,
with the framework's standard `nl` layout override where the seat already
provides the newline.

```
in_class_declaration        -> ~LegoCacheSoundEntry();
qualified_definition_header -> LegoCacheSoundEntry::~LegoCacheSoundEntry()
```

A7e now also rejects a form outside the enum (five cases) and a missing form.

## 3. Extension A, completed

`render_donor_source_overlay` renders each donor-private path from checked-in
source by typed ops, reusing the existing machinery rather than duplicating it:
the same verbs, the same generators, the same content-hash anchors, and the
same `source_range_relocation_v1` producer/consumer pairing the shipped overlay
uses for `Vector3::LenSquared`. A `delete` removes its range and emits nothing —
matching the shipped behaviour, where `vector3d.inl.h` retains none of the
moved text.

The recipe for this row is two renderings and four operations:

| seat | op | generator |
|---|---|---|
| header | replace the destructor signature | `member_sig(in_class_declaration)` |
| header | delete the body | `reloc` producer, registering the range |
| `.cpp` | insert before the annotation | `member_sig(qualified_definition_header)` |
| `.cpp` | insert the body | `reloc`, rendering the registered range |
| `.cpp` | insert two blank lines | `lines` |

Nothing is literal. The signatures come from identifiers A7a proves exist in
the checked-in source; the body is an authenticated range of that same source,
pinned by sha, size, line count and significant-token sha.

**A bug fixed along the way:** wave 15's validator looked for an `anchor` key,
but validated operations carry `start_anchor`/`end_anchor`. A5 was therefore
never actually enforced — test 10 passed only because its malformed op tripped
the key audit first. Both anchors are now resolved against the clean input.

## 4. Extension B in the build

`retail_image_body` performs B1's extraction in the build, which already owns
image identity: it re-hashes `legobin/LEGO1.DLL` against
`images.LEGO1.original_sha256` **before reading a byte**, walks the section
table, and refuses if the window leaves its section. The composer receives the
bytes and enforces length and masked nd 0. `validate_donor_object_excluded`
runs on the composed object at every splice, so A4 is asserted per landing.

The manifest carries the class as `retail_exact_reloc_divergent` with the
existing `retail_oracle` shape — `{image, address, verdict, length}` — rather
than a new flat key, so the pinned oracle window is expressed the way the
framework already expresses one.

## 5. What this cost and what it bought

One row, no losses, and a general facility whose second customer
(`0x1009f490`) needs only B7's reindexing path — the branch this row did not
exercise, which refuses today with a message naming B7 rather than silently
mis-splicing.
