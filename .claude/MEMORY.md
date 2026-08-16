# Goal 1 doctrine and live checkpoint

## Source-first doctrine

Always prefer an authentic or logic-neutral change in the checked-in C++ source
when the complete build/reccmp gate preserves every already-exact row.

Use this order:

1. Put the authentic correction/refactor directly in source and run the full
   zero-loss gate.
2. Use ordinary entropy-manifest carriers only to move compiler state without
   changing program logic.
3. Use an alternate source permutation plus target-only COMDAT composition only
   as a last resort: the direct source form must have been measured to cause
   unavoidable collateral, the permutation must be declared in the entropy
   manifest (never hard-coded in `byte_identity.py`), both source windows must
   be pinned, the donor must be freshly generated from source, and the complete
   retail-body/semantic-relocation/conservation gates must pass.

`GetActorROI` is the measured exception: its direct two-temporary refactor moves
nine COMDATs and loses the already-exact `Exists` row; the isolated manifest
permutation gives +1/-0. `UpdateEnabledChild` is the normal case: the clean
source alias changes only its own code COMDAT and is being landed directly in
`legocontrolmanager.cpp`.

Scratch source/object files are evidence and search results only. They may never
be build or manifest inputs. Every accepted artifact must be regenerated from
checked-in source plus the pinned entropy manifest and compiler.

## Process doctrine

Bound every Wine/compiler/link/reccmp run, monitor it periodically, and clean
only the process group/private Wine prefix that the run itself started. Never
kill an unrelated or another agent's Wine process. Verify a clean global census
after every bounded panel or full gate.

## Live checkpoint (2026-08-16)

- Accepted gate after the direct-source gain: LEGO1 4862/4934, ISLE 172/172,
  CONFIG 111/111. Removing only `0x100293c0` from the accepted set reproduces
  the prior 4861-set SHA-256 exactly, proving +1/-0.
- Manifest-declared single-evaluation source permutations are structurally
  limited to evaluated array extents and member-assignment receivers; no
  product-specific source text appears in `tools/byte_identity.py`.
- `UpdateEnabledChild` source candidate: `const char* const& atom = p_atom;`,
  then compare `GetInternal() == atom`. Its effective source SHA-256 is
  `7afe1fe6a4c0cd8d120a294e794b8820fa6cfc35357a6fea921249bdfea30cc1`;
  target body is retail-exact at 286 bytes and all 50 other code COMDATs in the
  object are invariant. The manifest-pinned 4862 row gate passed and the gain
  is committed in `093571b2c2eeb5ff5d3477e4834c87b1fee98896`.
- The `_Mynode()` ManageVisibility comparison panel is negative and retired;
  it preserves the same non-composable three-byte collateral pattern.
- `0x100998e0 LegoTextureContainer::GetCached`: moving `newDesc` to its first
  use and comparing height before width is a direct, logic-neutral source
  refactor. It changes only the target code COMDAT, preserves all 18 relocation
  semantics and 12 direct calls, reduces the object residue from 61 to 57
  bytes, and raises canonical raw matching from about 0.86965 to
  `0.878698224852071`. The complete 4862 accepted-row gate passed with no loss.

## Upstream entropy-aggregation oracle (2026-08-16)

The public `isledecomp/isle` accuracy page is the aggregate of 256 deterministic
entropy builds, not one binary. At upstream commit
`31bd20de79df0a2d2d26b63f734e155ddd17e8ae`, workflow run `31911463768`
generates 16 jobs x 16 headers with `tools/entropy.py`. The seed is
`(int(commit[:8], 16) & 0xffff0000) + (matrix << 8) + build_index`; each header
contains only unused classes and unused inline empty methods. `reccmp-aggregate`
selects the best raw row independently across those samples, so `recomp:
"various"` is expected.

The GitHub sample JSONs and their binaries/objects are evidence only. Reproduce
every candidate by running the checked-in deterministic generator contract from
its integer seed, compiling the current effective source, and then applying the
normal full-body, semantic-relocation, object-conservation, and zero-loss link
gates. Never admit or consume the downloaded artifacts themselves.

`0x100c6fa0 MxDSBuffer::FUN_100c6fa0` is not a better state: both our report and
the aggregate have raw `0.9882352941176471` with the same adjacent `cmp`/`mov`
schedule transposition. The page displays `100.00%*` only because the row is
marked effective.

Thirty aggregate rows have a strictly higher raw score than our 4862 report.
The most important measured targets are:

| Address | Ours | Aggregate | Smallest useful winning seed/shape |
|---|---:|---:|---|
| `0x100586e0` RemovePresenter | 0.775701 | **1.000000** | `834470658`, 6 classes/40 methods (`10,2,10,7,9,2`) |
| `0x100a12a0` SetImage | 0.666667 | 0.948718 | `834473472`, 2/4 (`3,1`) |
| `0x10083890` character-map `_Insert` | 0.707483 | 0.968326 | `834471431`, 5/20 (`9,1,2,3,5`) |
| `0x1002bff0` path-actor `erase` | 0.709239 | 0.967302 | `834472454`, 9/64 (`3,6,7,9,10,10,7,6,6`) |
| `0x1006c200` anim-subst `_Insert` | 0.782796 | 0.982906 | `834471940`, 5/36 (`3,10,9,5,9`) |
| `0x10059dc0` texture-info `erase` | 0.791328 | 0.986450 | `834469889`, 3/14 (`3,10,1`) |
| `0x1006a7a0` anim-struct `_Insert` | 0.798301 | 0.978903 | `834471941`, 2/16 (`6,10`) |
| `0x1004f9b0` texture-info `_Insert` | 0.805139 | 0.982833 | `834471173`, 1/6 |
| `0x1006e720` hide-anim `_Insert` | 0.847458 | 0.983122 | `834471695`, 3/8 (`3,2,3`) |
| `0x10038380` Pizza::StopActions | 0.744186 | 0.860465 | `834473485`, 1/1 |

The other strict improvements are `0x10062e20`, `0x1004ebd0`, `0x100a3840`,
`0x100a7960`, `0x100bb1d0`, `0x10069b10`, `0x10084030`, `0x10048310`,
`0x10073a90`, `0x100a66f0`, `0x1006b140`, `0x10029d50`, `0x10072ad0`,
`0x1003d170`, `0x10085500`, `0x100417c0`, `0x100a46b0`, `0x10054050`,
`0x1009a8c0`, and `0x100aa510`. Re-score them against current effective TUs;
upstream reachability is strong evidence but not proof after our source/entropy
changes.
