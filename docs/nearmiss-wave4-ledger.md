# Near-miss finish line — wave 4 ledger (Lane NM)

Session: 2026-08-15 night, three-lane parallel wave. Lane NM worktree
`agent-abdfe085f8e94c6b0`, branch `worktree-agent-abdfe085f8e94c6b0` reset to
`entropy-stabilization` **53a19e9c**. Build dir `/Users/foxtacles/Projects/isle-build-nm01`
(length-matched to `isle-build-lean`, harness trap #1).

Baseline at session start (from `isle-build-lean/LEGO1-report.json`,
ts 2026-08-15 20:15:41, copied to `nm/baseline-lean.json`):
**LEGO1 4831/4933**, ISLE 172/172 + MD5, CONFIG 111/111 + MD5.

Owned TUs: `legoextraactor.cpp`, `legopathactor.cpp`, `legopathboundary.cpp`,
`legopathcontroller.cpp`, `legocharactermanager.cpp` (+ their headers).

Lane scratchpad: `/private/tmp/claude-501/-Users-foxtacles-Projects-isle/3233884b-d405-46dd-ab8c-ee0c06400055/scratchpad/nm/`
* `bench/` — prior-wave `sweep-bench` + `fresh2` scripts, constants repointed at
  this worktree and `isle-build-nm01` (`wave2-oracles.json` `tu_obj` paths
  rewritten too).
* `oracle_index.py` / `oracle-index.json` — mangled-name -> retail span index
  merged over `wave2-oracles.json` + `oracles.json` + `direct-oracles.json`
  (121 names; wave2 spans win on conflict, they are the full padded spans).
* `scan.py` / `scan-<tu>.jsonl` — full near-miss ledger builder (below).
* `probe.py` — generic donor-lane state driver (carrier x include-perm x text),
  logs **best-nd for every target, always** (fresh-eyes C1.4 doctrine), never
  binary hits only.
* `ctx.py` — byte context around masked diffs.
* `gate.sh` — the full gated `isle_build.py` run for this lane.

Harness note recorded for the coordinator: a fresh git worktree has **no
`legobin/`** (it is gitignored and lives only in the main checkout);
`isle_build.py` dies in `verify_pins`. Fix: symlink
`legobin -> /Users/foxtacles/Projects/isle/legobin` in the worktree.

---

## Step 1 — the near-miss ledger rebuilt on the WHOLE retained corpus

`nearmiss.py` only globbed `sweep2-<stem>*`. `scan.py` instead scores **every**
retained probe object under
`aa9d0cc1.../scratchpad/{sweep-bench,wave3,fresh2}` whose directory belongs to
the owning TU, against the retail span for every Lane-NM queue row in that TU.
31,559 scored bodies total, zero compiles.

| addr | row | m | best nd | len | offsets | state |
|---|---|---|---|---|---|---|
| 0x10082ca0 | `_Tree<char*,LegoCharacter*>::erase` | .6848 | **1** | 1096 | [145] | `sweep2-all-legocharactermanager/fwdL-69` |
| 0x10083500 | `GetActorROI` | .9684 | 4 | 822 | [501,504,506,508] | `sweep2-all-legocharactermanager/fwdE-23` |
| 0x10083890 | `_Tree<char*,…>::_Insert` | .7075 | 94 | 652 | [180,190,193,…] | `sweep2-all-legocharactermanager/fwdL-69` |
| 0x10084030 | `CreateActorROI` | .9365 | **0** | 2294 | — | `sweep2-all-legocharactermanager/fwdL-82` (S72 TRAP) |
| 0x10085500 | `_Tree<char*,…>::insert` | .9244 | 12 | 653 | [400,402,405,…] | `sweep2-all-legocharactermanager/fwdL-66` |
| 0x1002a720 | `LegoExtraActor::StepState` | .9314 | 6 | 876 | [635,639,649,655,670,676] | `sweep2-all-legoextraactor/fwdE-30` |
| 0x1002aba0 | `LegoExtraActor::HitActor` | .9791 | 7 | 1617 | [889,892,894,897,964,967,977] | `sweep2-all-legoextraactor/fwdP-33` |
| 0x1002bff0 | `_Tree<LegoPathActor*>::erase` | .7092 | **0** | 1096 | — | `wave3/sweep-extra-ep/varab_pad-10-7` (varab text — BLOCKED) |
| 0x1002e8d0 | `LegoPathActor::CheckPresenterAndActorIntersections` | .9892 | **1** | 561 | [47] | `sweep2-all2-legopathactor/fwdL-6` |
| 0x10057180 | `_Tree<LegoAnimPresenter*>::_Erase` | .6522 | 7 | 57 | [4,10,20,23,31,34,44] | `sweep2-all2-legopathboundary/fwdL-46` |
| 0x100574a0 | `LegoPathBoundary::RemoveActor` | .7527 | **0** | 258 | — | `sweep2-all2-legopathboundary/pad-10-12` |
| 0x10057fe0 | `AddPresenterIfInRange` | .8571 | 44 | 214 | [19..25,37,38,39,41,42] | `sweep2-all2-legopathboundary/fwdL-1` |
| 0x100586e0 | `RemovePresenter` | .7757 | 3 | 314 | [194,197,199] | `sweep2-all2-legopathboundary/fwdL-19` |
| 0x10048310 | `LegoPathController::FindPath` | .8629 | 1741 | 2337 | [79…] | `sweep2-all2-legopathcontroller/fwdE-33` |

`0x10045c20` / `0x10046050` (`PlaceActor` x2) have **no oracle stem anywhere in
the corpus** — they were never swept. New oracles are needed before any carrier
work on them.

Corrections to the records the lane brief carried in:

* `0x1002e8d0` is recorded at **nd=1 @[47]** in the corpus object (not nd=2
  @[47,261] and not fwdL-6-with-two-diffs) — the wave-3 "RE-DIALED to nd=2"
  number was a *re-derivation on that session's shadow*; the retained object
  itself is one byte away. Both facts can be true (the TU re-dialed); the state
  must be re-derived here before either is trusted.
* `0x1002a720` StepState's corpus best is `fwdE-30` (nd=6), not `extern-1-12`
  (also nd=6) — same distance, different state; `0x1002aba0` HitActor's corpus
  best is `fwdP-33` (nd=7), not `extern-5-11`.
* `0x10057180` `_Erase` is emitted by legopathboundary (confirmed: only
  legopathboundary probe dirs define it) — ownership check in the brief
  resolved YES, it is mine.

### The 0x10082ca0 residue byte, read out (fresh)

`nm/ctx.py` on the fwdL-69 object, body offset 145:

```
ours  : … 8b 7c 24 10  8b 57 08  83 c7 08  [3b] 4c 24 10  0f 85 8f 00 00 00 …
retail: … 8b 7c 24 10  8b 57 08  83 c7 08  [39] 4c 24 10  0f 85 8f 00 00 00 …
```

i.e. ours `cmp ecx, [esp+0x10]`, retail `cmp [esp+0x10], ecx` — a pure CMPDIR
tie with identical operands, inside vendor `<tree>` template code (no source
text of ours is involved; `LegoCharacterComparator` is not called on this
path). 16 relocations, all `_Nil` + one `operator delete`; the relocation
sequence matches the seed 16/16 (wave-3 measurement, re-confirmed by the
identical reloc list here). One byte from a landable donor.
