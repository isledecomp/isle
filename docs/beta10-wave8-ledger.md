# Lane B10 — wave 8 ledger (redeployed to the unowned block)

Worktree reset to `b878d94a`; re-baselined **LEGO1 4853/4934, ISLE 172/172,
CONFIG 111/111**. New territory: the sixteen TUs the two retired lanes left
behind, **32 open rows**.

## CENSUS CROSS-CHECK — 32 of 32 agree with the published map

I refreshed `fin/adiff.py` (it had been updated at 02:39 with the tenth and
eleventh instrument fixes — multiple relocations per instruction, and the
byte-index switch table with no relocations) and re-ran `fin/census.py`
against **this** build dir, then compared every block row against
`docs/shape-census.md`.

**Zero disagreements**, to the second decimal, on all 32 rows. Both
instruments and both build trees agree. (Worth stating because two of the
three earlier census disagreements were real bugs — this one is not.)

Class distribution over the block:

| verdict | rows |
|---|---|
| TEXT-CLOSED (proof: SHAPE 100 & STRUCT 100) | 2 — `_Tree<LegoCacheSoundEntry>::erase` 0x1002a1b0, `LegoPathActor::UpdatePlane` 0x1002f770 |
| FRAME (decl-set) | 2 — `LegoTextureContainer::GetCached` 0x100998e0 (98.52/**90.24**), `LegoAnimationManager::FUN_10061010` 0x10061010 (93.08/**68.26**) |
| ENREG (same frame) | 3 — `BuildROIMap`, `CopyTransform`, `FindPath` |
| cmpdir (allocator) | 5 |
| SHAPE gap (text target) | 20 |

The block is much richer than my old lane: **two rows with a real frame
signal**, where my old lane had one.

## `LegoTextureContainer::GetCached` 0x100998e0 — a measured STRUCT gain

The row arrives at 987/987 (retail's exact length) with SHAPE 98.52 /
STRUCT 90.24, and the handover named two remaining causes. The instrument
localises both precisely.

`t2/slotset.py` (new — prints the distinct frame slots each side references,
with an example instruction, so an extra slot can be *named* rather than
guessed):

```
slot   ours#  ret#   example
 -4 … -48       same on both sides (with a -24/-32 pair exchange)
-52        1     0   mov dword ptr [ebp-0x34], 0x1800   <== ours only
-68        0     1   mov dword ptr [ebp-0x44], 8        <== retail only
-72        1     0   mov dword ptr [ebp-0x48], 8        <== ours only
   … every slot from -52 down is ours = retail - 4 …
```

So the extra dword is inserted **immediately below −0x30**, and `sub esp` is
0xfc against retail's 0xf8.

### The edit that moved it

`adiff -v` shows retail loading our −0x20 slot *before* our −0x18 slot at the
size test — i.e. **retail evaluates the height conjunct first**:

```c
-   if (newDesc.dwWidth == width && newDesc.dwHeight == height) {
+   if (newDesc.dwHeight == height && newDesc.dwWidth == width) {
```

| variant | SHAPE | STRUCT | EXACT | victims |
|---|---|---|---|---|
| base | 98.52 | 90.24 | 86.69 | — |
| **h1 conjuncts swapped** | 98.52 | **90.83** | **87.28** | 1 |
| h3 h1 + `DWORD height, width;` | 98.52 | 90.83 | — | 1 |
| h4 `height == newDesc.dwHeight && …` (operands mirrored) | 98.52 | 90.83 | — | 1 |

One line, +0.59 STRUCT and +0.59 EXACT, and h3/h4 show the *conjunct order* is
what matters while the operand mirror is (as everywhere) canonicalised.
**Not landed** — it does not close the row, and it recolours one other body in
the TU, so landing it alone is risk without gain. It is recorded here as the
correct source form for whoever finishes the row.

### Five refutations for the extra dword slot

| variant | SHAPE / STRUCT |
|---|---|
| g1 inner `surface` reuses the outer (drops the shadowing declaration) | 98.52 / 90.24 — inert |
| g2 g1 + `DWORD height, width;` | inert |
| g3 declaration order only | inert |
| g4 g1 + `und` hoisted | inert |
| i1 **drop `cached`**, use `(*it).first` directly | **89.91 / 80.42 — much worse; retail does have `cached`** |
| i2 / i3 / i5 (inner surface on top of h1; `cached` hoisted to function scope; outer `surface` split decl/assign) | all exactly h1's 98.52 / 90.83 — the compiler already coalesces these |

So the extra slot is **not** the shadowed inner `surface`, **not** `cached`'s
scope, and **not** the outer `surface`'s initialisation form. Same law this
lane hit on `LegoLOD::Read` and two other lanes reached independently: a local
must *earn* a slot, and naming or re-scoping a scalar the compiler can coalesce
buys nothing.

## Caution adopted

The handover's warning is now standing practice in this lane: **`nd` is
meaningless across a length change** — every number above is an `adiff`
alignment, never a masked byte count. (My own wave-4 `LegoOmni::Create`
landing is the positive case of the same phenomenon: nd said 1386 while the
row was one carrier state from exact.)
