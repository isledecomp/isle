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

**Design.** A new donor recipe kind that carries a **typed `source_overlay`
op-list applied to the donor's rendered copy of the TU only**. Reuse the existing
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

## 2. Extension B — splice class `retail_exact_reloc_divergent`

**The gap.** Every existing class requires donor and seed bodies to carry the
same relocations. `compose_same_slot_resize` requires `relocation_count` equality
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
- B5. **Every relocation in the donor body names a symbol the seed object already
  defines or declares**, with matching target type and storage class.
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

The existing 53 tests must stay green throughout, and all three image gates must
be unchanged except for the intended row gain.
