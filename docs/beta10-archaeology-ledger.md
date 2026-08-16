# BETA10 archaeology ledger

The debug images in `legobin/` (BETA10.DLL, ALPHA.DLL) are unoptimised builds:
statement order, named locals, un-inlined calls and frame-slot order all
survive. That makes them a **source oracle** for rows the carrier/generator
sweeps have sealed — the channel the sweep campaign ledger calls
"text archaeology".

Instrument: `tools/beta_disasm.py <va> [image] [max-instrs]`.

**Coverage: 41 of the 81 open LEGO1 rows carry a `// FUNCTION: BETA10 0x...`
annotation.** Those are the rows this channel can speak to.

## What the oracle can and cannot say

- It **can** settle: how many locals a function had, their declaration order
  (debug allocates frame slots in declaration order), statement order, whether
  a value was a named local or a repeated expression, and which call arguments
  were used.
- It **cannot** speak to residue that lives inside an *inlined* template body:
  the beta does not inline. `LegoPathBoundary::RemoveActor` (0x100574a0) is the
  worked example — the beta is a bare `call erase`, so the −5 byte residue in
  retail's inlined `set::erase` is out of its reach. Do not spend the read.
- The beta is an **earlier source revision**. Where it disagrees with a retail
  measurement, retail wins. See MxDSBuffer below.

## Rows read so far

### 0x100c6fa0 MxDSBuffer::FUN_100c6fa0 — beta 0x101582f2
Retail residue is a two-instruction transposition (nd=4, length-exact 234).
Full mechanism and sealed negatives: `project-volatile-read-order-lever`.
Beta findings and their verdicts:
- else-branch is `mov eax,[ebp-4]` ⇒ the source says `return current;`, **not**
  an alias local. Kills the alias-variable reading as authentic source.
- Beta has three frame slots (this, current, switch temp) and **no slot for
  `size`**; it reads `[current+4]` twice.
- **But** writing the expression twice at /O2 costs an extra volatile read of
  `current` (`mov ebx,[esp+0xc]` where retail has `mov ebx,eax`) → 237 bytes.
  Retail reuses the value, so retail's source **does** have the `size` local.
  The beta is an older revision here. Row left pristine at 234/nd=4.

### 0x1009f490 LegoAnimScene::CalculateCameraTransform — beta 0x10181a83
Ours 1074, retail 1121 (−47), 304 vs 320 instructions.
- Beta **confirms** the `case 2:` oddity our source flags with
  "Seems to be unused": the beta stores the `Interpolate` result to a slot and
  then passes `m_rotationKeys[i].GetZ()` to `RotateZ` anyway. Our text is
  faithful; do not "fix" it to `RotateZ(z)`.
- Live lead: the first three frame stores go to **different slots** than retail
  (`[esp+0x20]/[esp+0x54]/[esp+0x50]` vs `[esp+0x54]/[esp+0x50]/[esp+0x20]`).
  Frame-slot assignment follows **local declaration order**, so the block of
  `MxMatrix tempMatrix, original; Vector3 column0..column3;
  Mx3DPointFloat tempTranslation;` is mis-ordered relative to retail. The beta's
  own frame layout can decode the true order — that read is not yet done.

## Sealed negatives from this pass (do not re-run)

- **Relational operand order is not a source lever.** MSVC 4.2 canonicalises
  it. `p_data == current` ≡ `current == p_data` (byte-identical); and
  `m_width <= p_x` ≡ `p_x >= m_width` on 0x100b26f0 AlphaMask::IsHit
  (byte-identical). A `cmp A,B; jae` vs `cmp B,A; jbe` pair is therefore a
  **register-assignment** difference, i.e. allocator class — not text.
- **`MxU8* volatile current` is load-bearing** in FUN_100c6fa0. Removing the
  `volatile` collapses the body 234 → 162 bytes. It is not a cleanup target.

## Zero-compile row readings, 2026-08-16 (main loop)

Six open rows read instruction-by-instruction with relocations normalised
(`bench/fulldiff.py`). Recorded so no future wave re-reads them. None of these
is a text target; the class is given with the evidence that fixes it.

| row | len | class | evidence |
|---|---|---|---|
| 0x100ba7f0 MxDisplaySurface::Create | 660=660 | **schedule(reordered)** | Exactly one instruction moves. Ours `sub eax,[esi+8]; mov [esp+0x84],0x6040; inc eax`; retail `sub; inc eax; mov [esp+0x84],0x6040`. Both builds hoist the constant `ddsCaps.dwCaps` store up into the width arithmetic; they differ by one slot. Source order is already dwFlags→dwWidth→dwHeight→ddsCaps, so source order is not what places it. |
| 0x1009a8c0 LegoWEGEdge::LinkEdgesAndFaces | 1494=1494 | **colour** | Whole residue is `add ecx,4; add eax,8` vs `add ecx,8; add eax,4`, twice. Two induction variables, opposite register assignment. No operation differs. |
| 0x100b26f0 AlphaMask::IsHit | 101=101 | **colour** | `cmp eax,esi; jae` vs `cmp esi,eax; jbe` — same condition, operands reversed. Rewriting the source as `m_width <= p_x` is byte-identical (measured): MSVC canonicalises, so this is register assignment. |
| 0x1006ed90 Infocenter::Create | 380 vs 381 | **colour** | Retail inserts `mov ecx,eax` and tests `ecx` where we test `eax`; later `mov ecx,[eax+0x74]` vs `mov eax,[ecx+0x74]`. Register roles swapped around the `GetState` result. |
| 0x1003d170 FindSoundByKey | 282 vs 281 | **cmpdir → shape grid** | `cmp ebx,[_Nil]` vs `cmp [_Nil],ebx` inside the inlined `_Tree` sentinel test, plus a spill-vs-register choice for the `find` result. Same family as `_Tree<LegoPathCtrlEdge*>::_Ubound`, which closed on `declaration_shape` state 124 after 1,681 extern states. **Sweep the shape grid, do not read the text.** |
| 0x100c6fa0 MxDSBuffer::FUN_100c6fa0 | 234=234 | **PERMUTED, live** | Two-instruction transposition; full mechanism, six tested forms and the remaining blocker are in the section above. |

Method note: `fulldiff.py` originally showed dozens of false differences on
every row because our object stores `0` where retail stores the linked address.
**Normalise call/jmp targets and any immediate >= 0x100000 on both sides before
diffing**, or the relocation noise buries the real residue.
