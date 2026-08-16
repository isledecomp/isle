# Lane B10 — wave 6 ledger (the third seat)

Worktree `agent-ae4a0ccb643677ee3`, reset to `bbbcb6a4`
("Add declaration_run_triple: all three seats, independently").
Re-baselined from this build dir: **LEGO1 4850/4934, ISLE 172/172,
CONFIG 111/111**.

## Harness validation before any sweeping

`t/sw.py` grew a `triple` state kind that renders the three seats
byte-for-byte the way `isle_build.py`'s `run_triple` placement does
(`seat(pre) + lines[:insert_at] + seat(post) + lines[insert_at:] + seat(eof)`,
stems `MxUnkRecVA`/`MxUnkRecVB`/`MxUnkRecVC`, width 3). Honesty check —
`triple(P,0,0)` must be the old `fwdL-P` exactly:

| state | len/nd | body sha |
|---|---|---|
| `tri-2-0-0` | 1494 / 2 | `cc7c96a8432d2fb1` |
| `fwdL-2` | 1494 / 2 | `cc7c96a8432d2fb1` |
| `tri-4-0-0` | 1485 / 896 | `3726914d6db15bfa` |
| `fwdL-4` | 1485 / 896 | `3726914d6db15bfa` |

Identical, so the new axis is faithful and the whole retained corpus remains
comparable with it.

## Also new this wave (from other lanes) — three composite kinds

`bbbcb6a4` and its neighbours also added `forward_run_with_shape`,
`extern_pair_with_shape` and `extern_pair_with_pad`. Two consequences for this
lane:

1. **`pad_shape` is landable at last** (my wave-4 framework request), through
   `extern_pair_with_pad`.
2. More importantly they are *stacked* carriers: a seated run **and** a
   force-included shape in one donor. Several of my stuck rows reach their
   floor from two independent states (e.g. `LinkEdgesAndFaces` hits nd=2 at
   `fwdL-2` *and* at `shape-5-40` *and* at `extern-2-0`). Stacking a row's two
   best states is a targeted probe that no recipe could express before, and it
   is what wave 6b runs.

## RESULT 1 — the pre-include × EOF plane (the coordinate that was missing)

`triplePR` = `declaration_run_triple(P, 0, R)`, stride-1 lattice
P ∈ 0..24 × R ∈ 0..99, 2,499 cells per TU.

| row | best before | best on the new plane | winning cell |
|---|---|---|---|
| `LegoWEGEdge::LinkEdgesAndFaces` 0x1009a8c0 | 2 | **2** | `tri-2-0-0` — i.e. the old `fwdL-2`, P alone |
| `Act3List::RemoveByObjectIdOrFirst` 0x100720d0 | 7 | **7** | `tri-0-0-2` — the old `fwdE-2`, R alone |
| `Act3::TriggerHitSound` 0x10072ad0 | 11 | **11** | `tri-0-0-1` |
| `Act3::Enable` 0x10073a90 | 105 | **105** | `tri-3-0-0` |

**Every winner is on an axis (P alone or R alone); no mixed cell beats either
edge.** For these rows the two seats do not combine constructively — the third
seat opened a genuinely new region and the region is flat.

That is a real answer, not a null: it says the seats are independent
*coordinates* but their effects on these particular rows are not *additive*.
The wave-5 seat law stands (`extern-12-59` still beats both its edges for
`Act3Brickster::Animate`), so combination CAN pay — it just does not pay for
the rows that are left in this lane.

## RESULT 2 — stacked carriers are a new state, not a refinement

The most targeted probe available this wave: legomain's
`_Tree<…LegoTextureInfo>::erase` sits at **nd=1** at `fwdE-311`, the closest
open row in the lane. `forward_run_with_shape(suffix, 311, c, f)` stacks that
exact run with all 550 declaration-shape cells.

```
505 states compiled; best erase = 269 (rws-E-311-5-45), len 1102
```

Adding *any* shape on top of the good run destroys it — from nd=1 to nd≥269.
**The force-included shape re-colours the whole compile; it does not preserve
the run's state and add to it.** So a composite kind must be searched as a
fresh 2-D family in its own right, and the intuition "stack a row's two best
states" is wrong. Recorded before spending the rest of the lane's budget on it.

## RESULT 3 — the composite families are flat too

`forward_run_with_shape` and `extern_pair_with_shape`, each crossed with the
full 550-cell declaration-shape grid on top of the row's best seated run:

| row | seated run held fixed | composite states | best |
|---|---|---|---|
| `LinkEdgesAndFaces` | `fwdL-2` | 505 | **2** (`rws-L-2-6-37`) |
| `LinkEdgesAndFaces` | `extern(2,0)` | 505 | **2** (`epws-2-0-6-37`) |
| `RemoveByObjectIdOrFirst` | `extern(0,2)` | 505 | **7** |
| `TriggerHitSound` | `extern(0,2)` | 505 | **11** |
| `Act3::Enable` | `extern(0,2)` | 505 | **105** |
| `TowTrack::HandlePathStruct` | `extern(0,1)` | 505 | **11** |
| `Act3Cop::FUN_10040360` (c1 text) | `extern(0,20)` | 505 | **6** |
| `_Tree<…LegoTextureInfo>::erase` | `fwdE-311` | 505 | 269 (from 1 — see Result 2) |

Note the composite reaches the same floor from a *different* cell than the
plain families do (`LinkEdgesAndFaces` bottoms out at shape (6,37) here versus
(5,40) alone), so these really are distinct states — they just have the same
floor.

## THE WAVE-6 INVARIANT

Every one of the five stuck rows now has the same distance in **every landable
carrier family**:

| row | forward run (1..999, both placements) | extern pair (plane to 99×99) | declaration shape (all 550) | pad | **triple pre×EOF (2,499)** | **composites (505 each)** |
|---|---|---|---|---|---|---|
| `LinkEdgesAndFaces` | 2 | 2 | 2 | 2 | **2** | **2** |
| `RemoveByObjectIdOrFirst` | 7 | 7 | 7 | 7 | **7** | **7** |
| `TriggerHitSound` | 11 | 11 | 11 | 11 | **11** | **11** |
| `TowTrack::HandlePathStruct` | 11 | 11 | 11 | 11 | **11** | **11** |
| `Act3::Enable` | 105 | 105 | 105 | 105 | **105** | **105** |
| `FUN_10040360` (c1 text) | 6 | 6 | 6 | – | – | **6** |

Six generators, six identical floors per row, ~28,000 states in this lane. A
floor that is invariant under every generator is not a search problem. These
rows are carrier-dead, and — per `docs/open-set-triage.md`, which classes all
of them as COLOUR (frame identical) — they are not text rows either.

**This is the honest boundary of what the current framework can express**, and
it is worth as much as a landing: it stops the next wave from spending its
budget here. The rows that DID move for this lane all moved on the *first*
family that reached them (`Create` on a forward run, `~LegoROI` on a longer
forward run, `Animate` on an extern pair at m=12, `erase` 651 → 1 on a forward
run at k=311). None of them needed a second family, and none of the stuck rows
was rescued by one.

## RESULT 4 — the all-three-seats cube, for completeness

The one sub-region neither the plane sweeps nor any older recipe touches is
P, Q, R all non-zero. For the lane's closest stuck row:

```
all-legowegedge triple3, P x Q x R = 1..12 each, 1,728 states
best nd=2 @tri-1-1-1
```

Flat as well. `LegoWEGEdge::LinkEdgesAndFaces` has now held **nd=2 across
roughly 12,000 carrier states in six generator families**, including every
seat combination the framework can express.

## SESSION STATE

No source or manifest change was made in wave 6, so the tree is exactly the
merged tip: **LEGO1 4850/4934, ISLE 172/172, CONFIG 111/111**, verified by a
gated run at the start of the wave and again at the end. Roughly **17,000
further carrier states** were compiled; all objects retained under
`scratchpad/b10w4/sweeps/`.

## WHAT I WOULD DO NEXT IN THIS LANE (and what I would not)

**Would not:** any further carrier sweeping on the five stuck rows. Six
families agree to the byte; the marginal value is zero.

**Would:** the two rows this lane moved but did not close are the only ones
with live evidence of responsiveness —
`Act3Ammo::Animate` (95, moved 935 → 105 → 95 by seats) and
`LegoCarRaceActor::CheckPresenterAndActorIntersections` (100, moved at m=66).
Both respond to the post-include seat and neither has had its *k*-family
enumerated the way the wave-5 rule prescribes: strip first for every count
that reaches retail's length, then dense `m` at each. For CPI that means the
`fwdL` (pre-include) length family, which is where its good lengths live —
a `triple(P, Q, 0)` plane, which is the one plane I did not run for it.

**Structural:** the residues that remain in this lane are register-role and
frame-slot assignments (`TowTrack` a 3-register rotation, `RemoveByObjectIdOrFirst`
an eax↔edx swap, `FUN_10040360` two stack slots 0x1c apart, `LinkEdgesAndFaces`
the `LenSquared` address-temp order which retail itself emits both ways). If
the campaign wants these, the lever is the C4 instrument — reading C2's
allocator decisions directly — not more declarations in the source.

## RESULT 5 — I ran my own recommendation, and it is flat too

Before closing I ran the one plane I had just flagged as untried for a
*responsive* row: `LegoCarRaceActor::CheckPresenterAndActorIntersections`
on the pre-include × post-include plane (`triplePQ`, P ∈ 0..12 × Q ∈ 0..99,
1,300 states), since that row's good body-length family lives on the
pre-include seat.

```
best nd=102 @tri-10-25-0  (len 1168 = retail)
```

No better than the 100 already reached at `extern-66-228`. So the
recommendation in the previous section is now itself a measured negative for
CPI; it stands only for `Act3Ammo::Animate`, whose k-family has still not been
enumerated. Amended so the next wave does not repeat it.
