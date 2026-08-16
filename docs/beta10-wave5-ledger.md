# Lane B10 — wave 5 ledger (the long extern grid)

Session continues in worktree `agent-ae4a0ccb643677ee3`, reset to the merged
tip `5eab6a09` (`entropy-stabilization`). Re-baselined from this build dir:
**LEGO1 4848/4934, ISLE 172/172, CONFIG 111/111** — the wave-4 landings and the
coordinator's `Vector4::operator=` annotation are all in.

Wave-4 states re-derived on the merged tip before any new work: `fwdE-311` →
`erase` 1102/nd=1 and `fwdE-7` → `Create` 2648/nd=0, both unchanged. The
retained corpus is still valid on this base.

## THE SEAT LAW, MEASURED (this corrects a project-wide rule)

The coordinator's wave-5 brief carries two rules from other lanes: *"a carrier
run is count-only — stem, width, declaration kind and seat are all inert"* and
*"one axis stands in for the whole strip"*. **Half of that is exactly right and
half of it is false in this lane, and my own `Act3Brickster::Animate` landing
is the counterexample.**

### What IS inert (confirmed, 43 measured pairs)

`extern_run_pair(0, k)` and `forward_declaration_run(suffix, k)` declare k
things at the same seat with different keywords, stems and widths. Across
k = 18..60 in act3actors.cpp they produce **identical bodies** — same length,
same nd, every cell:

```
k=18  extern(0,18) 1628/1153   fwdE-18 1628/1153
k=20  extern(0,20) 1628/1171   fwdE-20 1628/1171
k=30  extern(0,30) 1628/1171   fwdE-30 1628/1171
…  43/43 agree
```

So **declaration kind, stem and width are inert within a seat** — the
coordinator's law holds, and one generator does stand in for the others *on a
single seat*. (My own width-2-vs-3 forward-run test agrees: same distances,
different objects.)

### What is NOT inert: the two seats are independent coordinates

`extern_run_pair` seats `header_count = m` after the last `#include` and
`seat_count = k` at EOF. Those do **not** sum, and `k` cannot stand in for `m`:

| state | total declarations | body |
|---|---|---|
| `fwdE-71` = extern(0,71) | 71, all at EOF | 1628 / nd **1153** |
| `fwdE-59` = extern(0,59) | 59, all at EOF | 1632 / nd **7** |
| **`extern-12-59`** | 71, split 12 + 59 | 1632 / nd **0** ← the landing |
| `extern-12-60` | 72, split 12 + 60 | 1632 / nd **0** (byte-identical body) |
| `extern-11-59` | 70, split 11 + 59 | 1632 / nd 7 |

Same total count (71), two completely different bodies. The full m-stratum scan
over act3actors' 931-cell extern sweep makes the structure explicit:

| post-include count m | best nd for `Act3Brickster::Animate` |
|---|---|
| 0, 1, 2, 5, 6, 7, 8, 9, 10, 11 | 7 |
| 3, 4 | 9 |
| **12** | **0** (only at k = 59, 60) |
| 13 … 24 | never even reaches retail's 1632 length (best 1153) |

### The search rule this yields

**`k` selects the body-LENGTH family; `m` selects the COLOUR inside it.**
So the efficient order is:

1. Sweep the 1-D `m = 0` strip (i.e. any forward-run axis) far out — cheap,
   and it tells you which counts reach retail's length at all.
2. For each `k` in that family, sweep `m = 0..99` densely.

A blind 2-D lattice wastes most of its compiles: my stride-4 99×99 grid (1,117
states) *does* contain 72×72 and every other multiple of 4, and it found
nothing new in two TUs — because the cells that matter are at stride 1 in `m`
inside a narrow `k` family. The historical 8×17 box missed `extern-12-59`
because k = 59 was outside it, not because m = 12 was.

### Framework limitation worth fixing

There are three seats in play — pre-include (forward run, `placement:prefix`),
post-include (extern pair's header run), EOF (both the forward run's
`placement:suffix` and the extern pair's seat run). No landable recipe can fill
**pre-include + EOF** together, or all three at once. Since kind/stem/width are
now measured inert, a single typed `declaration_run_triple(pre, post, eof)`
generator would subsume `forward_declaration_run` and `extern_run_pair` and
open a coordinate the campaign has never reached. Recommended framework growth.

## THE `Vector3::LenSquared` CROSS-TU LEAD — CLOSED, SEALED NEGATIVE

The coordinator handed me this lead as unowned. It is dead, and the kill test
is one second of disassembly with no compiles (`scratchpad/b10w4/t/lensq2.py`).

The inlined `Vector3::LenSquared` builds two address temporaries for
`m_data[1]` and `m_data[2]` (`m_data[0]` is reached through the base register),
and the question was whether retail always leads with `base+8` — in which case
a different association in `LEGO1/realtime/vector3d.inl.h` might fix several
rows at once.

Census over every oracled row in the image, matching the
`add rA,<4|8> / add rB,<8|4>` prelude in front of each `fld/fmul` square pair:

```
retail first-temp displacement histogram: {8: 7, 4: 2}
sites agreeing with ours: 3    differing: 6
```

**Retail itself uses both orders.** Seven sites lead with `base+8`, two lead
with `base+4`, and the two orders appear in *different directions* relative to
ours:

| site | retail leads | ours leads |
|---|---|---|
| `LinkEdgesAndFaces` +300 | +8 | +4 |
| `LinkEdgesAndFaces` +379 | +8 | +4 |
| **`Act3Brickster::FUN_100417c0` +1098** | **+4** | **+8** |
| `LinkEdgesAndFaces` +1164 (third site) | +8 | +8 (agrees) |

No single spelling of a three-term sum can emit both orders, so **the order is
compiler scheduling state, not source text**. A header reassociation would fix
`LinkEdgesAndFaces` and simultaneously break `FUN_100417c0`, on top of
recolouring every TU that includes `vector3d.inl.h`. The lead is closed; do not
spend a session on it. (The earlier wave-4 note that "one site in the same body
already matches" was the right instinct — this is the measurement that settles
it.)

**Hand-off:** the census also flags one site outside this lane —
`Isle::Enable` (`all2-isle`) at +2211, where retail has a LenSquared prelude
leading with +8 and our build has no matching prelude at that offset at all
(a structural, not colour, difference). Whoever owns `isle.cpp` may want it.
