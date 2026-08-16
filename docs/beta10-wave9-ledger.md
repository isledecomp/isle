# Lane B10 — wave 9 ledger (three text candidates, read out)

Worktree at `e20cce65`; re-baselined **LEGO1 4853/4934, ISLE 172/172,
CONFIG 111/111**. Tree is unchanged at the end of the wave and re-verified.

## 1. `0x1003cf20 ~LegoCacheSoundManager` — **SOLVED, byte-exact, and reverted**

### The read

`adiff -v` names our seven extra instructions exactly:

```
cmp dword ptr [r], 0 / jne T / mov r, [r+0xc] / test r, r / je T / push r
   … the aligned call …
add r, 4
```

That is not "a guarded block in our source and absent from retail's" — it is
the **inlined body of `LegoCacheSoundEntry::~LegoCacheSoundEntry`**:

```c
~LegoCacheSoundEntry() { if (m_sound == NULL && m_name != NULL) delete[] …; }
```

Retail does not inline it: at +146 retail emits `call 0x1003d030`, and
`0x1003d030` is annotated in our own header as that destructor, sitting in the
image between `~LegoCacheSoundManager` (0x1003cf20) and `Tickle` (0x1003d050)
— i.e. compiled in this TU. Ours pushes an argument and cleans the stack
(cdecl `operator delete[]`); retail's call takes none (thiscall member). The
source even carries the TODO: *"LegoCacheSoundEntry::~LegoCacheSoundEntry
should not be inlined here"*.

### The fix, and it is total

Declare the destructor in the class, define it in `legocachesoundmanager.cpp`
— the ordinary 1997 arrangement, and the thing the TODO asks for. Probed with
a new `t2/hprobe.py` (seed-lane compile with an **overridden header** staged
in a private include dir that is prepended to the include path, so one header
is shadowed and every other still resolves from the build's tree):

| variant | SHAPE | STRUCT | EXACT |
|---|---|---|---|
| base | 96.13 | 96.13 | 93.92 |
| **destructor defined out of line** | **100.00** | **100.00** | **100.00** |

258/258 bytes, masked **nd = 0**. The row is byte-exact. It also fixes
`LegoCacheSoundManager::Stop` in the same TU: its seed body goes 187 → 181
(retail's length), so that row's compose unit collapses from a
`same_slot_resize` to a plain `equal_body_strict` splice.

### Why it is not landed

`legocachesoundmanager.h` is included by 16 TUs, and removing an inline body
re-dials every one of them that destroys an entry. I measured the blast radius
rather than guessing — new tool `t2/blast.py` renders every manifest donor the
way `isle_build` does, compiles it, and checks each pinned body against its
`expected_body_sha256`:

```
lego1:…/paths/legopathactor.cpp     CheckIntersections, CheckPresenterAndActorIntersections
lego1:…/entity/legoworld.cpp        _Tree<MxCore*>::find, LegoWorld::Enable
lego1:…/actors/act3actors.cpp       FUN_10042300, Act3Actor::StepState, Act3Brickster::Animate
lego1:…/paths/legoextraactor.cpp    _Tree<LegoPathActor*>::find, ::_Copy,
                                    CheckPresenterAndActorIntersections, HitActor, StepState
```

**Twelve pinned functions across four TUs stop reproducing** — twelve rows
currently at 1.0 that would be LOST unless every one is re-dialled first.
(Four further units use the new composite recipe kinds my checker does not yet
render, so the true radius is ≥ 12.) Trading a certain −12 for a +1 is not a
gain, so I reverted to the merged tree and the gate is green at 4853.

**Handover — this is a two-step landing, and step 1 is done:**

1. the source change (header lines 18-23 → `~LegoCacheSoundEntry();` plus
   blanks, keeping the line count; definition appended after
   `~LegoCacheSoundManager` in the .cpp). Both files are in
   `…/scratchpad/b10w4/texts/lcsm-hdr-outofline.h` and `lcsm-cpp-outofline.cpp`;
2. re-dial the twelve functions above, then re-dial
   `legocachesoundmanager.cpp`'s own `Stop` unit — which I already derived:
   donor `declaration_shape(1,2)` (`d_6d3dd9e3e989`), splice
   `equal_body_strict`, expected body sha `840f4057…` (unchanged from today's
   pin), changed offsets [20, 100], S72 guard clean at 4/4.

Net if completed: **+1 row, and one fewer `same_slot_resize` in the manifest.**

## 2. `0x10062e20 FUN_10062e20` — the brief's read needs correcting

The brief has it as "retail addresses an indexed global where we address a
struct member". The raw bytes say something more specific — **both sides
address the same global, and differ only in where the base is folded**:

```
OURS    lea ebx, [ecx*8 + <reloc g_characters>]   ; base folded into the LEA
        cmp byte ptr [ebx + 4], 0                 ; small field offsets

RETAIL  lea esi, [ecx*8]                          ; index only, disp is a real 0
        cmp byte ptr [esi + 0x100f704c], 0        ; base+field folded per access
```

`0x100f704c` is `g_characters + 4`, and `ecx*8` with `ecx = i*3` is the same
24-byte stride on both sides. Our source already indexes `g_characters[characterId]`
at every use — retail's form — so this is **not** a member/global source
difference: MSVC CSE'd the element address for us and did not for retail. All
five divergent sites (+175, +289, +328, +344, +363) are the same pattern.

That makes it **addressing-mode base folding** — the same family as
`LegoOmni::Destroy`'s `add edi,8` hoist — and a *sixth* way for a colour
difference to wear a SHAPE gap: SHAPE erases registers and frame slots but
keeps a global displacement, so where the base is folded is visible to it.
Worth adding to the census's divergence classifier.

## 3. `0x10054050 Act3Ammo::Animate` — read out, and the flip is inert

The `fld [r+8]` / `fld [R]` site is at body+2309 and it is **not** a member
against a global — `[r+8]` is `[ebp+8]`, the `p_time` parameter:

```
OURS    fld [ebp+8] ; fadd [g_const] ; fstp [ebx+0x158]
RETAIL  fld [g_const] ; fadd [ebp+8] ; fstp [ebx+0x158]
```

`[ebx+0x158]` is `m_rotateTimeout`, so the statement is act3ammo.cpp:261
`m_rotateTimeout = p_time + 2000.0f;` and retail's source reads
`2000.0f + p_time`.

**Probed: bit-inert.** SHAPE 98.46 / STRUCT 98.60 / EXACT 95.53, unchanged to
the second decimal. So MSVC 4.2 canonicalises the operand order of a
floating-point `+` with a constant operand, exactly as it does integer
comparison mirrors. The wave-2 float finding (parens are a barrier) is about
*association*; **term order at a single `+` is not a lever**. New sealed
negative.

The row's other divergences are store scheduling (+1173, +1502, +1585, +1633)
and one spill difference (`cmp r, r` vs `cmp r, [F]` at +1408) — colour.

## Wave verdict

Of the three text candidates handed to this lane, **one was real and is
solved byte-exactly**; the other two are colour wearing a SHAPE gap — one a
new sub-kind (addressing-mode base folding), one a canonicalised FP term
order. The honest count of text candidates in this block is therefore **one,
not three**, and it is blocked on twelve re-dials rather than on any further
source question.
