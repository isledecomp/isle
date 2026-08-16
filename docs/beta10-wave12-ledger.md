# Lane B10 — wave 12 ledger (the inline bit, and what the framework permits)

Worktree at `7083c62a`. **No source or manifest change this wave.** Tree
verified green throughout: **LEGO1 4853/4934, ISLE 172/172, CONFIG 111/111**.

## 0. My two wave-11 claims were wrong, and both are now measured-wrong

Recording this first because the corrections are load-bearing.

* **"Displacement broke the 47 rows."** False. Measured in the current report:
  4,853 rows at 1.0, of which **1,497 are address-aligned and 3,356 are not**.
  A row keeps its match while displaced; reccmp resolves intra-image
  references. My attribution was wrong.
* **"The lost TUs don't include the header."** False. `act2actor.cpp` includes
  `legocachesoundmanager.h` at line 9, `legoworld.cpp` at line 7; there are 16
  direct includers. The −47 is real byte change in ~15 TUs that stop inlining
  the entry destructor — exactly what my own section (c) had measured.

Consequence, and it matters: **layout re-anchoring will not absorb this row.**
Sealing it as a goal-2 item, as I proposed, would have sealed it against a
mechanism that is not operating. That verdict is withdrawn.

## 1. The carrier axis, corroborated and sealed from this side

I had queued the sweep before the seal arrived; I let the queued families
finish and stopped the rest. On `legocachesoundmanager.cpp` alone:

| family | cells | `~LegoCacheSoundManager` |
|---|---|---|
| `declaration_shape` full domain | 550 | 274 B |
| `fwdL` / `fwdP` / `fwdE`, k = 1..300 | 900 | 274 B |
| `extern_run_pair` 9×18 | 161 | 274 B |
| **`pad_shape` full 99×99** | **9,801** | 274 B |
| `declaration_run_triple`, all three seats | 1,728 | 274 B |
| `triple` pre×EOF plane (partial, bounded) | ~2,000 | 274 B |
| **total** | **~15,100** | **274 B in every single cell** |

Retail is 258. The 16-byte delta is the inlined `~LegoCacheSoundEntry`, and
**not one cell in ~15,100 flips the accept/decline bit.** Independent
corroboration of the other lane's 8,963-cell seal, on a third TU and a
different row. `FindSoundByKey` likewise never beat its baseline (282 B,
nd 181) in any cell.

## 2. A measurement that supports "per site", from inside one compile

In the **same TU, same compile**, counting REL32 relocations naming
`??1LegoCacheSoundEntry@@QAE@XZ`:

```
?FindSoundByKey@LegoCacheSoundManager   len=282   calls-to-entry-dtor = 1
??1LegoCacheSoundManager                len=274   calls-to-entry-dtor = 0
```

MSVC **calls** the entry destructor from one function and **inlines** it in
another, in a single invocation, from one declaration state. That is the
per-site decision the other lane demonstrated with `inline_depth`, visible
here without any pragma: no global switch and no declaration-level state can
be responsible, because both outcomes coexist under one.

## 3. THE QUESTION — can the destructor be out-of-line for ONE TU?

Enumerated by reading the framework, not by assuming. The complete per-TU
surface is:

| # | mechanism | what it can express | verdict |
|---|---|---|---|
| 1 | `source_overlay.outputs[]` | typed generator ops on a **file**; headers are eligible (12 already overlaid, incl. `vector3d.inl.h`) | **Legal but global.** Keyed by path, so one header has one effective content for the whole shadow. This is the −47 lever. Cannot be scoped to one TU. |
| 2 | donor `/FI` header | the only genuinely per-TU input | **Cannot express it.** Validated `non_emitting_declarations_only`; every generator (`shape`, `pad_shape`, forward/extern runs, triple, composites) emits only *unused* classes and externs. Making an existing inline member non-inline is a change to an existing declaration, not an addition of an unused one. Doing it would need a second, differing definition of `LegoCacheSoundEntry` — an ODR violation *and* invented first-party code (mandate 5). |
| 3 | extra `/I` to a modified header copy | — | **Not expressible and not legal.** `translation_units[]` keys are exactly `command_policy, completion, donors, functions, mode, source, source_sha256, target` — there is no include-path field; the command comes from CMake's `compile_commands.json`. A modified header would be a first-party artifact not rendered from checked source (mandate 1). This is what my `t2/hprobe.py` does for *probing*, and it is exactly why that tool is a probe and never a landing path. |
| 4 | `graph.generated_tus[]` | `path`, `ordinal`, `after`, `before` — **link order only** | **Cannot express it.** It orders TUs that exist in the tree; it does not synthesise a TU, and any new TU would `#include` the same header and see the same inline body. |
| 5 | per-TU compiler flags (e.g. `/Ob0`) | `command_policy` has only `required_flags` and `forbidden_prefixes` — **assertions about the existing command** | **Not expressible.** No field adds a flag. It would also change every other function in the TU, several of which are exact today. |
| 6 | `#pragma inline_depth` / `auto_inline`, `#undef`/`#define` | — | **Forbidden** (mandate 4, and your standing instruction). |
| 7 | carrier/record state | the axis of §1 | **Sealed**, ~15,100 cells here + 8,963 there. |

**Answer: nothing the framework permits achieves it**, and the reason is
structural rather than incidental. The framework's only per-TU lever is a
*declaration-only, non-emitting* force-include. "Make an existing inline member
non-inline" is a modification of an existing declaration, which that lever
cannot express by construction and which the mandates forbid inventing. Every
mechanism that *could* express it (overlay a header, substitute a header,
change a flag, use a pragma) is either file-global or out of mandate.

Retail's image does contain both states at once — an out-of-line COMDAT at
0x1003d030 that already matches us at 1.0, plus inlined copies in the
includers — but that is C2 having made the per-site decision differently, not
evidence of a source-level switch. Our own object contains both states too
(§2), from one declaration state.

## 4. RECOMMENDATION

**Seal `0x1003cf20 ~LegoCacheSoundManager` as C2-internal.**

What stands, and should be carried forward:

* the row has a **demonstrated byte-exact endpoint** — 258/258, nd=0,
  SHAPE/STRUCT/EXACT all 100.00 (wave 9) — the only open row anywhere with one;
* the mechanism is exact and independently verified against the bytes: our
  offsets 146-163 are the inlined
  `if (m_sound == NULL && m_name != NULL) delete[] m_name;`, retail emits one
  call to 0x1003d030;
* the only known lever is a header change whose cost is **−47 rows**, and that
  cost is real code change in 16 includers, not displacement, so no layout work
  will absorb it;
* every other axis is sealed: carrier state (§1), the framework surface (§3),
  and the per-site nature of the decision (§2).

If C2's inline decision ever becomes observable and steerable — the C4
pool-dump instrument — this row is the one to re-open first, because its
endpoint is already proven. Until then it is not a search problem and not a
bookkeeping problem.

`0x1003d170 FindSoundByKey` is sealed alongside it on the carrier axis: 282 B /
nd 181 in all ~15,100 cells, unmoved. Its residue remains the `_Tree` sentinel
`cmpdir` plus a spill-vs-register choice, both allocator-class.

## 5. Harness note — three wedged compiles in one night

`cl` under wine hung three times tonight (act3actors, legoextraactor,
legocachesoundmanager), each costing 900 s before the per-probe timeout fired.
Mitigations applied: the sweep probe timeout is now **120 s** (a stall costs two
minutes, not fifteen), and an integrity pass re-parses every retained `o.obj`
and deletes any that fails, so a resumed sweep can never trust a truncated
object as a miss. Orphaned wine processes from the killed runs were identified
by their command line and killed — mine only.
