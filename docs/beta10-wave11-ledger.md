# Lane B10 — wave 11 ledger (pad_shape, and the second radius)

Worktree at `7522c4e5`; tree reverted to the merged state and re-verified:
**LEGO1 4853/4934, ISLE 172/172, CONFIG 111/111**.

Three results, in the order they were produced.

## (a) SMOKE TEST — `pad_shape` works end to end, first use in the project

You were right that it is already legal: `byte_identity.py:8018` whitelists it
for `compose_equal_body_comdat`, `:8335` validates `classes` and
`functions_per_class` in [1,99], and `isle_build.py:711` renders it with
`placement = "force_include"`.

Exercised on the unmodified tree — `LegoCacheSoundManager::Stop`, donor swapped
from `declaration_shape(1,1)` to **`pad_shape(1,1)`**:

* `pad-1-1` reproduces the existing `expected_body_sha256`;
* S72 relocation guard clean, splice `same_slot_resize`;
* the real `compose_equal_body_comdat` accepted it;
* `/FIrun.h` was **not** rejected — `lego1`'s `allowed_force_includes` lists
  only `SMRTHEAP.HPP`, but the donor force-include travels the same path
  `declaration_shape` already uses, so no per-target policy change is needed;
* gate green: **4853/4934, ISLE 172/172, CONFIG 111/111**.

**No policy widening required. The kind is fully wired.** (Smoke change
reverted afterwards; it was an equivalent donor, not a gain.)

## (b) THE BLOCKER IS SOLVED — `pad-3-22`, and the law held

Sweeping `pad_shape` over `0x1002b980 LegoExtraActor::CheckPresenterAndActorIntersections`
against its existing pin (2,247 of 9,801 cells compiled before the hit):

```
HIT pad-1-3   _Tree<LegoPathActor*>::_Copy
HIT pad-1-35  _Tree<LegoPathActor*>::find
HIT pad-3-22  LegoExtraActor::CheckPresenterAndActorIntersections   <-- the blocker
```

and it **splices**:

```
?CheckPresenterAndActorIntersections@LegoExtraActor   pad-3-22
    equal_body_eh_reloc_layout    guard=ok
```

No "non-local relocation rename". The wave-10 law predicted exactly this:
`pad_shape` is force-included, so it never seats a declaration in the source,
never reorders COMDAT emission, and never moves the function's section index.
The 550-cell ceiling I hit was `declaration_shape`'s grid, not the donor space
— that correction was right and it cost the last blocker.

**All 13 re-dials are now available**, cells recorded:

| function | cell | | function | cell |
|---|---|---|---|---|
| `LegoCacheSoundManager::Stop` | shape-1-2 | | `_Tree<LegoPathActor*>::find` | shape-4-28 |
| `_Tree<MxCore*>::find` | shape-7-61 | | `_Tree<LegoPathActor*>::_Copy` | shape-1-3 |
| `LegoWorld::Enable` | fwdE-10 | | **`LegoExtraActor::CPI`** | **pad-3-22** |
| `_Tree<MxCore*>::_Lrotate` | shape-1-3 | | `LegoExtraActor::HitActor` | extern-10-29 |
| `LegoPathActor::CheckIntersections` | extern-10-4 | | `LegoExtraActor::StepState` | extern-23-13 |
| `LegoPathActor::CPI` | shape-3-26 | | `Act3Brickster::FUN_10042300` | extern-2-32 |
| `Act3Actor::StepState` | extern-4-1 | | `Act3Brickster::Animate` | extern-17-60 |

All applied cleanly; every unit re-dialled without error.

## (c) THE LANDING IS STILL REFUSED — and for a bigger, different reason

With the text change and all thirteen re-dials in place, the gated build:

```
LEGO1 rows 4806/4934 at 1.0, 793 address-aligned
  GAIN  0x1003cf20 LegoCacheSoundManager::~LegoCacheSoundManager
  LOST  ... 47 rows
```

**+1 / −47**, and address-aligned rows collapse **1786 → 793**.

The losses are not donor bookkeeping. They are spread across TUs that do not
even include the touched header — `LegoRaceCar::ParseAction`,
`LegoJetski::LegoJetski`, `MxList<MxPresenter*>::~MxList`, `Act2Actor::Animate`,
`LegoWorld::Add`, `LegoWorld::Find` — i.e. rows whose own bytes are unchanged
but whose **addresses moved**, so their relocated operands stop matching.

Mechanism, measured rather than assumed. It is *not* COMDAT removal:

```
objects defining ??1LegoCacheSoundEntry@@QAE@XZ
   before the edit: 1   (legocachesoundmanager.cpp.obj)
   after  the edit: 1   (legocachesoundmanager.cpp.obj)
```

It is that ~15 TUs which previously **inlined** the entry destructor now
**call** it. Every one of those functions changes size, and the cumulative
delta displaces everything downstream in the link. The aligned-row count
halving is that displacement.

## (d) THE LESSON — a text edit has TWO radii, and my wave-10 checker measured one

`t2/blast.py` answers "which pinned donor bodies stop reproducing?" That is
necessary and it found 13. It does **not** answer "which already-exact,
unpinned rows change size or move?", which for a header edit is the far larger
number — here 47 against 13.

**Recommended standing rule:** before funding re-dials for any edit that
touches a header, run the *gated build first with the pins deliberately
stale*, read the LOST list and the address-aligned count, and only then decide
whether the bookkeeping is worth doing. Had I done that in wave 10 I would have
seen −47 before spending a wave on thirteen re-dials. The re-dial work was not
wasted — it is recorded above and is correct — but the order was wrong.

## VERDICT ON THIS ROW

`~LegoCacheSoundManager` is byte-exact (SHAPE/STRUCT/EXACT all 100.00, 258/258)
and every piece of bookkeeping around it is now solved. It is **not landable as
a standalone change** at any bookkeeping price, because its true cost is a
global link displacement. It belongs to the goal-2 layout program: land it when
the image layout is being re-anchored anyway and the displacement is absorbed
rather than paid. Sealed as such — not as a text question, which it no longer is.
