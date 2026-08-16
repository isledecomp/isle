# Lane FIN — the finish-line ledger

Worktree `agent-af3e1ee806b530baf`, branch `worktree-agent-af3e1ee806b530baf`,
reset to `entropy-stabilization` **2e296568**. Build dir
`/Users/foxtacles/Projects/isle-build-fin1` (four-character suffix — harness
trap #1, shadow path length is load-bearing).

**Base ancestry verified before any work**: the worktree was handed to me at
`31bd20de`, 586 commits *behind* the assigned base, on a branch off upstream
master. `git merge-base --is-ancestor 31bd20de 2e296568` passes, working tree
was clean, so the branch was fast-forwarded to `2e296568` before anything else
happened. A fresh worktree also has no `legobin/` (gitignored, lives only in
the main checkout) — symlinked, per the wave-4 hand-off note.

Baseline reproduced by a full cold gated run **from this build dir**:
`ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE: LEGO1 4850/4934,
ISLE 172/172, CONFIG 111/111` in 99.6 s.

Lane scratchpad: `<session scratchpad>/fin/`.

| tool | what it is |
|---|---|
| `sw.py` | the coordinator's `bench/sw2.py` repointed at this build dir, plus three new axes: `externK` (long EOF strip at m=0) and `triE:/triP:/triM:` (the `declaration_run_triple` seats — pin two, sweep the third) |
| `relguard.py` | the S72 semantic-relocation guard, rebuilt against `oracles-v2.json` + this lane's own `LEGO1-report.json` (Lane NM's `relcheck.py` is pinned to a worktree that no longer exists) |
| `landfin.py` | lands a swept state into the manifest against a **fresh out-of-tree seed compile of this lane's shadow**; knows `extern_run_pair`, `declaration_shape`, `pad_shape`, `declaration_run_triple` and all `forward_declaration_run` placements |

Owned TUs: `legopartpresenter.cpp`, `helicopter.cpp`, `isle.cpp`,
`legovideomanager.cpp`, `mxbitmap.cpp`, `mxstillpresenter.cpp`,
`mxramstreamprovider.cpp`, `legoact2.cpp`, `infocenter.cpp`, `pizza.cpp`,
`pizzeria.cpp`, `legocontrolmanager.cpp`, `tglrl40.cpp`,
`legocarbuildpresenter.cpp`.

---

## 0. First act: mine the corpus before compiling anything

Before opening a sweep I re-read the *coordinator's* retained sweep results
(`bench/sw-*/results.json`) for my fourteen TUs. Seven of them had been swept
by another lane and the floors were never transcribed into any ledger:

| sweep | states | row | floor |
|---|---|---|---|
| `sw-all-legocarbuildpresenterrect` | 1,680 | `0x100796b0 FindNodeDataByName` | **nd=0 @ `extern-2-0`** |
| `sw-all-legopartpresenterrect` | 1,680 | `0x1007ca30 LegoPartPresenter::Read` | 4 @ `extern-0-4`, offsets [875, 939, 2397, 2401] |
| `sw-all-legopartpresenterlong` | 759 | " | 4 @ `extern-18-0`, offsets [1143, 1216, **2397, 2401**] |
| `sw-all-legovideomanagerrect` | 1,680 | `0x1007b770 LegoVideoManager::Tickle` | 19 @ `extern-0-1` |
| `sw-all-mxbitmaprect` | 1,680 | `0x100bd020 MxBitmap::BitBltTransparent` | 60 @ `extern-0-24` |
| `sw-all-tglrl40rect` | 1,680 | `0x100a12a0 TextureImpl::SetImage` | 16 @ `extern-22-0` |
| " | " | `0x100a3b40 MeshBuilderImpl::Clone` | 14 @ `extern-0-1` |

The first line is a **finished, unlanded row**. Nobody had noticed, because the
sweep that found it belonged to a lane that did not own the TU and
`docs/open-set-triage.md` still lists `0x100796b0` as `0 flat cells — UNSWEPT`.

Second line worth keeping: `LegoPartPresenter::Read`'s two residue *pairs* move
independently — offsets **2397/2401 are invariant** across both sweeps while
the other pair moves from [875, 939] to [1143, 1216]. That is the
joint-reachability signature, and it says the invariant pair is the one to
attack.

---

## 1. LANDED: `0x100796b0 LegoCarBuildAnimPresenter::FindNodeDataByName`

*(measured; gate result recorded in §1.1 below)*

Re-derived on this lane's shadow — the state label does **not** transfer across
shadows, so it was recompiled rather than trusted:

```
sw.py all-legocarbuildpresenter --axes base,extern --tag cbp1
  162 states, 0 failed
  0x100796b0 retail=106  nd=0 @extern-2-0  lens: 106x162
```

Every one of the 162 states produces a 106-byte body (the row is size-clean),
and `extern-2-0` is masked-exact.

**Relocation guard (S72) before landing** — this row has only two relocations
and both agree with retail's callee identities:

| offset | our symbol | retail target | named |
|---|---|---|---|
| +32 | `_stricmp` | `0x1008c110` | `__strcmpi` (the same CRT entry) |
| +77 | `?FindNodeDataByName@LegoCarBuildAnimPresenter@@…` | `0x100796b0` | `LegoCarBuildAnimPresenter::FindNodeDataByName` (the row's own recursive call) |

The donor's relocation sequence is **identical to the seed's** — no `$L`/`$T`
renumbering at all.

### 1.1 Gate

Landed as a new `compose_equal_body_comdat` unit for
`LEGO1/lego/legoomni/src/build/legocarbuildpresenter.cpp` (the TU had none),
donor `extern_run_pair(g_h=2, g_p=0, width 2)`, splice class
`equal_body_strict`, 16 changed offsets.

```
LEGO1 rows 4851/4934 at 1.0
  GAIN  0x100796b0 LegoCarBuildAnimPresenter::FindNodeDataByName
  (no LOST rows)
ITERATION_GATES_PASSED_FINAL_GATES_INCOMPLETE:
  LEGO1 4851/4934, ISLE 172/172, CONFIG 111/111
```

 was . **4850 -> 4851.**

**The transferable lesson**: before opening a sweep, re-score every retained
corpus directory that touches your TUs. Sweeps are run by whoever is holding
the bench, not by whoever owns the row, and a floor of 0 in another lane's
scratchpad is a landing nobody has taken. This one cost 162 compiles and a
relocation check.
