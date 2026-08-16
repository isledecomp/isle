# The slot-forcing unused local: a real but weak body lever

Measured 2026-08-16, main loop. Scratch compiles only; the tree was never
touched.

## What it is

`empty_scopes` and `noop_assign` are inert as allocator levers (lane FRESH:
1,620 cells, zero body changes, with live positive controls that moved the body
at 118/124 positions). But not every body construct is inert.

An **unused local whose type cannot live in a register and has no constructor**
occupies a frame slot and emits **no instructions**. On `AlphaMask::IsHit`
(0x100b26f0, 101 bytes):

| construct | body length | body sha | moved? |
|---|---|---|---|
| baseline | 101 | ec6893ea… | — |
| `int mxUnusedA;` | 101 | ec6893ea… | no — eliminated |
| `MxU8* mxUnusedP;` | 101 | ec6893ea… | no — eliminated |
| `;` / `if (0) {}` / `{}` / re-bracketing | 101 | ec6893ea… | no |
| **`int mxUnusedArr[4];`** | **101** | e19cadd8… | **YES** |
| **`MxRect32 mxUnusedR;`** | **101** | e19cadd8… | **YES** |
| `Mx3DPointFloat mxUnusedR;` | **126** | — | yes, but **EMITS** (ctor) |

So scalars are eliminated; array and POD-class locals are not. Length and
relocation count are unchanged, so nothing is emitted — this is a genuine
non-emitting perturbation of the frame.

**Constraint: the type must have no constructor.** `Mx3DPointFloat` added 25
bytes of constructor call. Any generator built on this must reject
non-trivially-constructible types.

## But it does not find retail — 33 cells, three rows, zero improvements

| row | baseline nd | cells | best nd |
|---|---|---|---|
| 0x100b26f0 AlphaMask::IsHit | 8 | 11 | 8 (arr3/4/6/12 and MxRect32 → **24**, worse) |
| 0x100ba7f0 MxDisplaySurface::Create | 9 | 11 | 9 (arr3 → **18**, worse) |
| 0x100c6fa0 MxDSBuffer::FUN_100c6fa0 | 4 | 11 | 4 — **totally inert** |

Where it moves at all, nd roughly doubles. That is the signature of a **global
displacement shift** — the frame grew, so every `[esp+X]` displacement changed —
not of a re-colouring. It is a coarse frame-size dial, not a fine allocator
search.

## Where it might still pay

Not as a blind sweep. As a **targeted** fix for rows whose frame is smaller than
retail's by a known amount: add exactly enough slot to match. The frame census
names the candidates (`GetCached` +1 slot, `LegoLOD::Read` −1, `FUN_10061010`
−3); only rows where OUR frame is **short** can be fixed by adding a local.

## Verdict for the ~75 allocator rows

This is not the mechanism. Combined with lane FRESH's 1,620-cell negative, the
body axis in every form tested does not solve the colour rows. The two channels
with demonstrated yield remain:

1. **Harvest the corpus properly** — the coverage matrix's class B is 32 rows
   where a ledger claims coverage no result file backs, and re-scoring objects
   against a stem listing every open row has already produced three finished
   rows this session.
2. **Archaeology** — read the allocation, name the source idiom, check BETA10.
   That is what closed `~MxStreamController` after ~1,040 dead carrier states
   and `GetCached` via the named-surface idiom.
