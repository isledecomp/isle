# Goal 1 doctrine and live checkpoint

## Source-first doctrine

Always prefer an authentic or logic-neutral change in the checked-in C++ source
when the complete build/reccmp gate preserves every already-exact row.

Use this order:

1. Put the authentic correction/refactor directly in source and run the full
   zero-loss gate.
2. Search authenticated compiler/build states and ordinary entropy-manifest
   carriers that make the compiler emit the complete expected function without
   post-compile instruction manipulation.
3. Splice an intact compiler-emitted target COMDAT/closure when a direct source
   landing has measured unavoidable collateral.
4. Keep instruction mosaics, manual instruction reordering and synthesized
   hybrids only as explicitly documented last resorts after the direct-source,
   compiler-state and intact-COMDAT searches are exhausted. Do not expand these
   mechanisms as the routine path. Any last-resort source permutation must be
   declared in the entropy manifest (never hard-coded in `byte_identity.py`),
   both source windows must be pinned, every donor must be freshly generated
   from source, and the complete retail-body/semantic-relocation/conservation
   gates must pass.

Do not add opcode-bearing inline assembly to spell retail instructions. The one
existing empty `__asm {}` compiler-scheduling barrier emits no instructions and
is retained only with the other last-resort mechanisms; do not use it as the
default model for new rows.

The objective is literal raw `matching == 1.0` on every row. Non-exact score
improvements are diagnostic only unless they isolate a concrete mechanism that
leads directly to an exact source/dial state. Do not spend broad compiler time
polishing non-1.0 aggregates. It is valid to compile one TU under several
independently declared entropy states and compose different retail-exact COMDATs
into the seed: every donor must be freshly generated from source and excluded
from the link, with the target closure and relocation semantics fully proved.
Multiple source versions may contribute disjoint complete-instruction ranges
to one exact same-mangled COMDAT, but every range must name its donor and the
declared donor set must be used exactly—never borrow from another function.

Partial code composition is permitted only between independently
source-generated versions of the exact same mangled function/COMDAT. Ordinary
same-TU mosaics require equal function identity, section seat, body length,
COMDAT topology, relocation semantics and compatible debug/EH closure; copied
instructions stay at the same offsets. The separate cross-TU hybrid-resize
route is admissible only from a different SHA-pinned, unmodified checked-in
translation unit compiled through its own command. The source-aware
hybrid-resize route may instead use a closed typed donor-private permutation
of the owning TU. The source-identical same-TU sibling may use two closed
declaration-only carrier states only when both complete renderings and the
target source window are exact, all generated identifiers are fresh, each
carrier has exactly one manifest-wide role, and the donor's rounded span is
allowed to cross the seed's former link bucket. All three require equal
primary COMDAT identity/selection/associated-child names, equal-width complete
instructions,
no relocation overlap in either object, exact-once role confinement,
target-donor metadata authority, an exact hybrid against the owning target's
retail image and exclusion of both donors. For each object, the line-table
sentinel must bind the unique exact target definition; decode starts at the
nearest preceding compiler line row and must prove both range endpoints are
instruction boundaries using the fail-closed accepted IA-32 subset. A valid
isolated byte sequence inside a larger instruction is not sufficient. Every
copied range must be manifest-declared and provenance-pinned, and the output
must pass full retail-body and object-conservation gates. Never copy code from
a different or merely similar function, even if its instructions are
equivalent.

`GetActorROI` is the measured exception: its direct two-temporary refactor moves
nine COMDATs and loses the already-exact `Exists` row; the isolated manifest
permutation gives +1/-0. `UpdateEnabledChild` is the normal case: the clean
source alias changes only its own code COMDAT and is committed directly in
`legocontrolmanager.cpp`.

Scratch source/object files are evidence and search results only. They may never
be build or manifest inputs. Every accepted artifact must be regenerated from
checked-in source plus the pinned entropy manifest and compiler.

## Process doctrine

Bound every Wine/compiler/link/reccmp run, monitor it periodically, and clean
only the process group/private Wine prefix that the run itself started. Never
kill an unrelated or another agent's Wine process. Verify a clean global census
after every bounded panel or full gate.

## Live checkpoint (2026-08-17)

- The uncommitted Helicopter seed-only instruction-permutation route is parked
  under the direct-codegen-first policy in the recoverable stash named
  `WIP last-resort Helicopter source-authenticated permutation (frozen)`.
  Its object/composition proof was exact, and the completed predecessor-bound
  Vector2/3/4 type closure was green, but four source-authenticity categories
  remain deliberately unfinished: live recursive include/preprocessor state,
  strict child environment construction, complete compiler invocation binding,
  and their associated adversarial tests. Do not apply, build, gate or commit
  that stash unless the row is explicitly returned to last-resort status.

- Direct-codegen panel negative: for
  `0x10081840 LegoCarRaceActor::CheckPresenterAndActorIntersections`, changing
  only the first owning-loop increment from discarded postfix `itap++` to
  prefix `++itap` did not reproduce retail. The fresh authenticated control was
  exact at 1,163 bytes/27 relocations; the sole variant grew to 1,288 bytes/30
  relocations with body
  `8194cc30ae19578c2cfe7c965fa0f310968377fa1f8bd8891ba7b49aca861649`
  and changed three non-target runtime COMDATs (`UpdateWorldSpeed`, the Jetski
  intersection function, and a tree `erase`). The bounded lane is sealed; do
  not repeat this spelling. Evidence is in
  `/tmp/codex-carrace-prefix.99Lb8c/result.json` (SHA-256
  `4ab720e1...`).

- Direct-codegen panel negative: for
  `0x10046050 LegoPathController::PlaceActor`, the authenticated
  `extern_run_pair(1,16)` control reproduced the exact 700-byte target and
  closure. The sole positive-nesting source variant compiled successfully but
  remained 700 bytes (retail is 703), emitted body
  `a86bc4a6d77102c36353790b53e550ff7f9ca5cbb27665e007252009eac790fc`,
  reduced the line count to 34, and produced the wrong 13-relocation seat
  sequence. Its union-masked diagnostic distance was 287 bytes. This spelling
  is sealed; no third cell ran and the compiler/Wine census drained cleanly.

- Direct-codegen panel negative: for
  `0x1003d170 LegoCacheSoundManager::FindSoundByKey`, fusing allocation and
  `strcpy` directly into the `LegoCacheSoundEntry` temporary compiled cleanly
  but was codegen-inert. The target stayed at the canonical 282-byte body
  `1ea542d85bfc6ffc9bc2595839886cf36367f477bd4a2b41972da95ae47418f2`
  with the original 12 relocation seats; retail distance remained 181. Only
  target line/CodeView metadata changed and every non-target runtime/data
  section stayed exact. Evidence is under
  `/tmp/codex-findsound-fused.6bVzHg`; do not repeat this fused spelling.

- Direct-codegen panel negative: for
  `0x1002f770 LegoPathActor::UpdatePlane`, replacing the exact inline
  `SetPosition(GetWorldPosition())` call with its public-member equivalent
  `m_position = GetWorldPosition()` was codegen-inert on the target. Both
  control and variant stayed at the same 188-byte body
  `6a97acb19f8a66ada8547c1bcc9dfd369d8575257763d23792106ba606e18473`
  with the same four relocations and five retail-different bytes. The variant
  also changed three non-target runtime functions (a tree destructor,
  `CalculateTransform`, and tree `erase`). Evidence is under
  `/tmp/codex-updateplane-direct.a_1ru157`; seal this spelling.

- Direct-codegen panel negative: for
  `0x10080be0 LegoCarRaceActor::CalculateSpline`, naming `&m_boundary` as a
  pointer-to-pointer and passing `*boundary` to `SwitchBoundary` did not
  produce the predicted one-byte shrink. The target stayed 779 bytes with body
  `bec627a70bbe7656fc91cb19ab94457f115b2d69d42b9d4543ddcbe0c91f77be`,
  retained the old 13 relocation seats and FPO/CodeView procedure extent, and
  grew from 23 to 24 line rows. It also changed four non-target runtime
  functions. Evidence is under `/tmp/codex-calcspline-pp.AlgZpD`; seal this
  pointer-to-pointer spelling.

- Direct-codegen panel negative: for
  `0x1004d330 TowTrack::HandlePathStruct`, caching `m_state->m_state` once and
  using that scalar in the two later `else if` conditions compiled cleanly and
  reduced the target residual from 11 bytes to 7, but did not reach retail.
  The target stayed 856 bytes/36 relocations with body
  `2a225a3c0bc97c4c7944dfd39069fb932f90c7866193802ab2ac9a13fe6ad6ec`
  and residual offsets `[123,129,147,151,157,305,400]`. A raw comparison
  initially flagged 15 other functions, but all were compiler-local `$L/$T`
  ordinal spelling changes: normalized bodies and semantic relocations prove
  zero meaningful non-target runtime collateral. Evidence is under
  `/tmp/codex-towtrack-cached.0qr5gva9`; seal this exact cached-state form.

- Direct-codegen panel negative: for
  `0x100ba2c0 MxStillPresenter::Clone`, caching `LoadedFirstFrame()` in a
  same-line `register BYTE` local did not flip the five packed-flag merges to
  retail's AL-first lowering. The target remained 577 bytes with body
  `c2ae44ab86c27e2c16a020906e265a76332360f17fd635640a8e8f3ba0c9be2d`
  instead of retail's 576 bytes; the long-lived ESI/EDI allocation changed but
  the CL-first flag chain and all 29 relocation seats remained. Normalized
  non-target runtime collateral was zero. Evidence is under
  `/tmp/codex-clone-register.TMZDji6S`; seal this exact register-BYTE form.

- Direct-codegen panel negative: for
  `0x10072ad0 Act3::TriggerHitSound`, adding a separate `MxS32 index` and using
  it in all five table loads while retaining `MxS32 objectId` was target-code
  inert. The authoritative build-lean control and variant both emitted the
  348-byte body
  `1e79a9f0f9883a7824c7d9723d187a0981607f50be1279edfb70285f82c9546a`
  with the same 11-byte retail residual and 16 semantic relocations. Two
  meaningful non-target runtime functions changed (`Act3List` removal and a
  list destructor). The initial stale-tree controls were setup/provenance
  stops; the conclusive current-tree evidence is under
  `/private/tmp/codex-ths-buildlean-run1`. Seal `ths_same_type_split_v1`.

- Direct-codegen panel negative: for
  `0x10084030 LegoCharacterManager::CreateActorROI`, the authenticated
  declaration-shape control plus two dead updates inside `Vector3(float*)`
  produced the desired constructor-relocation pattern V2,V3,V2,V3, but did not
  preserve the retail target. The target grew from 2,294 to 2,295 bytes with
  body
  `5f2e89471da8219c5a9bee10a2b9fb36850e85f258b672d7c96f5709a56c8064`,
  shifted later relocation seats, added COMDATs, and changed 13 non-target
  runtime bodies. Evidence is under
  `/private/tmp/codex-createactor-repeat2.lCLeWh`; seal this repeat-two header
  state and do not pursue an instruction-splice fallback under the current
  direct-codegen-first policy.

- Direct-state search sealed without a compiler panel for
  `0x100417c0 Act3Brickster::FUN_100417c0`. A 10,357-definition current-source
  carrier census (695 bodies), dense declaration/forward/extern grids, and a
  14-point split C1XX/C2 Vector3 inline-size sweep all leave independent stable
  clusters in the prologue, two LenSquared sites, selection stores, and loop
  scheduling. The best semantically admissible compiler state remains 66 bytes
  from retail; no single new clean source/compiler-state lever covers all
  clusters. Reopen only for authenticated historical owner source or a newly
  demonstrated whole-function compiler-state mechanism, not a bundle of
  instruction-tailoring edits.

- Direct-state search sealed without a compiler panel for
  `0x100720d0 Act3List::RemoveByObjectIdOrFirst`. Current and retail are both
  323 bytes with the same six relocations and 120 instructions; the sole seven
  differing bytes are an EAX/EDX caller-saved role exchange in one iterator
  setup block. Roughly 28,000 carrier states plus declaration swaps, statement
  orders, prefix increment, dereference spelling, initializer folding, loop
  spelling, include ordering and register probes never improve the nd7 floor.
  Reopen only for authenticated historical source/compiler provenance exposing
  a genuinely new scheduler state, not another local spelling or carrier.

- Fresh-eyes duplicate caught before compilation for
  `0x1002de10 LegoPathActor::SetTransformAndDestinationFromPoints`. Rewriting
  its failure-first `SetSpline(...) != SUCCESS` tail into the neighboring
  function's success-first idiom initially looked like a complete three-byte
  direct-codegen mechanism, but the exact spelling had already been compiled
  in `/tmp/codex-two-source-panels-run1/path/positive_direct` and is recorded
  in `docs/scheduling-residue.md`. Its rendered raw source SHA-256 is
  `9f97d748...`; it emitted a 696-byte target body `4dab3aa8...`, 16 rather than
  17 relocations, line count 36 rather than 35, masked distance 617, and 13
  non-target raw body changes. The new private control at
  `/tmp/codex-settd-success.Pzzgne` reproduced the current 746-byte target
  exactly; the duplicate variant was staged but stopped before CL. Seal this
  success-first spelling and include both the old panel and scheduling-residue
  ledger in future novelty checks.

- Direct-codegen panel negative: for `0x1006ed90 Infocenter::Create`, naming
  the exact `GameState()->GetState("InfocenterState")` result as an
  `InfocenterState*`, assigning it to `m_state`, and using the local only for
  the initial null/step tests and step store did not produce retail's
  381-byte lifetime/color schedule. The authenticated control was exact at
  380 bytes with body
  `8e421e5b0ff2d4eb840ab0f93640bb49412f1d3766ac69f1aeeaac417bf03fd6`;
  the sole variant remained 380 bytes with the known second-color body
  `f92579edc1ec29bcf3d00d11aff0d3a66db88f9aaab4470e00a656b1a4e0c616`
  and retained all current relocation seats. The optimizer erased the alias
  and never emitted retail's `mov ecx,eax`; it also changed four meaningful
  non-target code bodies (`Escape`, `PlayAction`, `ReadyWorld`, and a tree
  `erase`). Evidence is under `/tmp/codex-towtrack-cached.cdt48vn2`; seal this
  typed-local route and do not try a naming-only third cell.

- Direct-codegen/compiler-state cross negative: for
  `0x10054050 Act3Ammo::Animate`, an exhaustive 3,679-definition retained
  census (871 bodies, including 1,930 correct-length 2,666-byte bodies) has no
  retail-exact natural emitter; the closest correct-length state is still 95
  non-relocation bytes away across 33 runs. The sole genuinely new cross used
  a production-authentic declaration shape `(7,14)` plus the semantics-neutral
  `Mx3DPointFloat position = positionRef;` initializer fusion. Its control was
  exact for that state at 2,665 bytes/78 relocations/body `e1d3351b...`; the
  variant emitted 2,673 bytes/77 relocations/body `80e5e4ec...`, changed two
  non-target path-actor tree COMDATs, and therefore failed before any retail
  distance could be admitted. Historical `AaTail`/radius-hoist claims remain
  stale negatives. Evidence is
  `/tmp/act3ammo-shape-position.7si7ti/analysis.json`, SHA-256
  `090b47f7275ee220be5e200e07bb0328094c963eefb25cff60ba5f68b31088f8`.
  Reopen only for a genuinely new source mechanism, not another retained
  carrier or this initializer fusion.

- Fresh-eyes compiler-state replay negative: for
  `0x1004ebd0 LegoTexturePresenter::Read`, upstream entropy seed `834472970`
  was re-derived into an exact self-contained declaration-only `/FI` header
  (3 unused classes/6 unused methods, SHA-256 `f644ac85272e819cba6f188b8d574767b41b206e25a86d0dc59ef0afce27c96f`)
  and replayed for the first time against today's improved effective source.
  The fresh control reproduced the canonical 745-byte/40-relocation target,
  EH closure and all universes exactly. The sole state variant emitted 748
  bytes with body `e67e6e8c...`, not retail's 739-byte objectized body
  `7e3aaffc...`; it also changed five non-target map/tree functions (`find`,
  `_Lbound`, `insert`, `_Dec`, `_Insert`). No historical script/object was an
  input, no third cell ran, and no splice or generated-instruction work was
  attempted. Evidence is under
  `/private/tmp/codex-legotex-read-seed.o4ZSZC`. Seal this exact named seed on
  current source; other historical maxima require independent novelty and
  all-or-nothing replay rather than assuming entropy states compose.

- Fresh-eyes direct-source panel negative: for
  `0x10051ac0 LegoAct2::SpawnBricks`, replacing only SET3 occurrences zero,
  two and three with their three typed component assignments on the same
  physical line, while leaving occurrence one unchanged, was completely
  codegen-inert. A 2,613-source novelty census found no prior raw or
  significant function-state hit, so this was a genuine new experiment. The
  fresh control and sole variant both emitted the same 1,115-byte body
  `bbf0c73d1ba5db5fb7fdd0fa315cb79815c407b2a666708b629e98a88aba66bb`,
  the same 20 relocation seats, 81 line rows, FPO/CodeView closure and exact
  58-byte retail residual. Non-target runtime collateral was zero; the only
  whole-object changes were compiler timestamps. Evidence is
  `/private/tmp/codex-spawnbricks-set3.bosn5c15/seal.json`, SHA-256
  `391bfb6ad5e87421d07592146d99433c367ea9f470a3dbce37dfcbcf686e5a88`.
  Seal this three-site component spelling; do not broaden it to the already
  exact second SET3 or instruction-level manipulation.

- Fresh-eyes static seal: `0x100334b0 Act1State::Act1State` remains an
  843-byte/184-instruction/57-relocation pure schedule permutation with a
  strict masked distance of 20. An exhaustive filesystem census found 6,869
  symbol-bearing COFFs, 6,843 definitions and 19 unique bodies; none is exact,
  and 6,793 definitions sit at the same nd20 floor. All 122 checked-in
  `isle.cpp` revisions reduce to ten constructor texts: the eight Playlist-era
  forms are already covered by the sealed 720-permutation S44 space and the
  other two use an obsolete raw-field representation. Do not try direct member
  initialization: BETA10 `/Od` explicitly performs the early stores followed
  by a Playlist assignment call, and initializer construction changes that
  authenticated operation order. Reopen only for final-release source/PDB or
  compiler/PCH provenance that first demonstrates a new complete body, not
  another statement order, declaration carrier, temp/alias or expression
  trick.

- Fresh-eyes compiler-state negative: for
  `0x10055a60 LegoNavController::Notify`, the previously untested mixed
  declaration state `extern_run_pair(P=17,T=39,width=2)` was compiled once
  after an exact fresh control. It kept the natural target at 4,112 bytes,
  261 relocations and 229 line rows and reduced relocation-normalized retail
  distance from 80 to 51, but it was not exact; its relocation semantics also
  diverged and it changed non-target `UpdateLocation(char const*)` by nine
  normalized bytes. No third cell ran. Evidence is
  `/private/tmp/isle-legonav-notify-p17t39.VYg8dU/SEAL.json`, SHA-256
  `70ea94c94c9b2dc93f5e6947a2af5f42df0255e844f987477a94cc12bd064e84`.
  Seal this mixed coordinate rather than widening it into more carrier or
  instruction-level searches.

- Fresh-eyes duplicate seal: the historically attested two-step height local
  proposed for `0x100b24f0 MxVideoPresenter::AlphaMask::AlphaMask` was already
  compiled as `height_local.obj` in the retained six-cell panel
  `/private/tmp/codex-dissolve-alpha.xvVWH1/alphamask`. It is codegen-identical
  to the 346-byte control body `f8ee08e5...`, retains both semantic relocations
  and all five residual offsets `[24,28,31,34,44]`; therefore spend no new
  compiler cell on this source spelling.

- Fresh-eyes static seal: `0x1007b770 LegoVideoManager::Tickle` has a
  19-byte residue split across three independent register/scheduling windows
  (stopwatch roles, cursor-constructor evaluation, and the inlined DrawCursor
  receiver). The prior declaration swap is a literal code no-op. All 1,680
  retained extern objects reduce to four bodies at distances 19/21/35/37,
  and every body leaves all three retail-residual windows byte-identical to
  baseline; 52 implemented git snapshots across seven source texts preserve
  the same lifetime/evaluation topology. Do not spend a cell on another
  declaration carrier or local one-window rewrite. Reopen only for authentic
  final source/PDB evidence or a naturally compiled 1,089-byte/28-relocation
  whole-function state that changes all three windows together.

- Fresh-eyes direct-source negative: for
  `0x1004ebd0 LegoTexturePresenter::Read`, deleting the loop-local
  `LegoNamedTexture*` temporary and spelling the operation directly as
  `m_textures->Append(new LegoNamedTexture(textureName, texture))` is a
  compiler-significant no-op on the target. An exact fresh control and the
  sole variant both emit the same 745-byte/40-relocation body
  `393c0af2e1eee180ad4f2d36e6f3555baba8d1c421a92cccc62cecf8ab8ed356`;
  only two target line rows disappear. The variant also changes the previously
  exact 347-byte map `insert` COMDAT and changes `_Tree::_Insert` from 681 to
  678 bytes, while retail is 679. Do not land, splice, or broaden this source
  form. Evidence is
  `/private/tmp/codex-legotex-direct-append.9fQr7w/SEAL.json`, SHA-256
  `680c37b9a7915fa8ae6c32b7432a51f8c9c1ce9e947db30fcf7338cf5a6fe00d`.

- Post-`85861d11` retained-oracle refresh: a fresh pass rescored the existing
  389,288-object corpus plus 10,708 newer objects against all 54 remaining
  LEGO1 misses. No admissible natural `nd=0` emitter remains after excluding
  already-owned rows, documented negatives, wrong-supplier matches and the
  synthetic Act3Brickster object. The closest apparently new leads were the
  already-sealed `LegoOmni::Destroy` map-alias body at `nd=1` and the
  non-historical character-tree comparator body at `nd=3`. Do not repeat the
  broad retained-object scan without genuinely new artifacts; future work
  needs new source/PDB evidence or a newly demonstrated compiler-state axis.

- Fresh-eyes static seal: `0x1004c580 MxTransitionManager::SetupCopyRect`
  has no credible untested source-first cell. Its remaining one-byte/one-
  instruction shape residue is the allocator's `mov edx,eax` copy after
  `new`, not a missing source operation. Coverage includes 33 file revisions
  collapsing to eight function texts, all 5,040 local-order permutations, ten
  targeted source shapes, 86 dead-local/type states, 2,139 current-source
  carrier states and the full retained-object corpus. No state emits retail
  length/body; the prior `dst = new; m_copyBuffer = dst; if (!dst)` spelling
  emitted 411 bytes and regressed sharply. Reopen only for authentic source or
  PDB evidence, or a natural whole-function 412-byte emitter.

- Fresh-eyes direct-source/compiler-state negative: for
  `0x1003f540 WriteDefaultTexture`, the authenticated
  `extern_run_pair(h=24,p=90)` control reproduced the best 854-byte body
  `3cd3c0182328c788010538e7df701fa8859e78ca9cb40940b0c653d7c596d2c7`
  and its exact 12-byte palette-loop EAX/ECX residue. The sole novel variant
  declared destination-first block references for `paletteEntries[i]` and
  `entries[i]`; it emitted 851 bytes/body
  `00a22af1252cec791937775a10f0fe08d12f5196c0cc02fc92157cb0e7986581`,
  changed relocation/call semantics and linker payload, and changed
  non-target `LegoPathStructNotificationParam::Clone` and
  `LoadFromNamedTexture`. Seal this reference form and the h24/p90 source lane;
  no third cell ran. Evidence is
  `/private/tmp/codex-wdt-blockref-run2/result.json`, SHA-256
  `990546fe0141b09494c805e4698d2c89d4e7f91c3c939b64bf0d734d21cd7ea8`.

- Fresh-eyes direct-source negative: for
  `0x100998e0 LegoTextureContainer::GetCached`, ending the lexical lifetime of
  `DWORD width,height` after the cache-search loop was the only uncensused
  source mechanism for retail's four-byte smaller frame and reuse of the old
  width slot as `RECT.bottom`. The exact fresh control emitted 987 bytes/body
  `b68bb972f59874e51ccfcb9c80fe243889704719f69e15492b58860521f97c53`
  at `nd=57`; the sole variant stayed 987 bytes with the same `sub esp,0xfc`
  frame and regressed to `nd=59`, body
  `1c9e4a50c66e17586117cf813ceb23d5f91e0d5b29d9d7f97656b2de582ad608`.
  That output is byte-identical to the retained `cache_height_first` /
  `split_desc_newdesc` negative. Relocations, calls, EH/CodeView topology and
  all non-target runtime sections remained exact. Coverage now includes 13
  Git commits/five function texts, 1,138 retained source definitions/33 texts,
  1,079 retained object definitions/44 bodies and the prior seven-cell panel.
  Reopen only for authentic final source/PDB evidence or a natural object that
  first demonstrates retail's `0xf8` frame. Evidence is
  `/private/tmp/codex-getcached-lifetime-run1/result.json`, SHA-256
  `8916eed69cdbca9ac222702283650882f96468f27b8f6e215da27e25ddab8f70`.

- Reconciled retained panels seal
  `0x100b27b0 MxVideoPresenter::Destroy(MxBool)`. The canonical function is
  247 bytes/8 relocations with a 25-byte register/schedule residue. Both the
  commented historical compact spelling
  `MxRect32(m_location, MxSize32(GetWidth(), GetHeight()))` and its named-size
  variant were already compiled; each regressed to the same 250-byte body at
  `nd=114`. A later exact fresh control plus the only uncensused manager-local
  alias (`MxVideoManager* videoManager = MVideoManager()`) left all 247 target
  bytes, 8 relocations and `nd=25` unchanged, altering only target line data.
  Together with at least 6,149 current-source carrier states and the global
  no-exact retained-object refresh, this closes the natural source/state lane.
  Evidence is `/tmp/codex-highva-direct-source-run1/result.json`, SHA-256
  `3050559b24853f14e22dae3053c23a5d3d8f5f375fef1eb283b5c8fd3d15504f`,
  and `/private/tmp/mxvideo-destroy2.PGdJar/result.json`, SHA-256
  `3e94a22192a58dd2364be3606f4ea7acc90044b79ded5f6ffadd0dd871157fe8`.

- Fresh static seal: `0x10031820 Isle::Enable` is an isolated C2 allocator
  colour tie, not an open source/body-state lane. The best natural emitter is
  still `extern_run_pair(1,8,width2)`: 3,580 bytes/223 relocations with exactly
  11 non-relocated differences at offsets 2206..2233, all an EAX/ECX
  transposition in the first of two adjacent `LenSquared` inlines; the second
  inline is already exact. All 3,440 measured carrier states stop at that
  floor. A fresh census found 6,813 retained definitions/52 unique exact-shape
  bodies and no `nd=0` emitter; 142 objects tie at `nd=11`. Git and retained
  source history cover every plausible spelling, including explicit-base
  qualification and local-scope variants, with no target movement. Reopen only
  for authentic final-release source/PDB evidence or a newly identified
  allocator-provenance state that flips only the first inline while preserving
  the exact 3,580-byte/223-relocation body and zero collateral.

- Fresh static seal: `0x100b2a70 MxVideoPresenter::PutFrame` has no remaining
  authentic source-form lead. Current is 1,254 bytes/426 instructions; retail
  is 1,260/427. The complete residue is repeated ECX/EDX/EAX scratch-liveness
  selection in three inlined `PrepareRects` tails and the final argument tail;
  arithmetic, frame slots, 11 semantic relocations and the ordinary
  `.xdata$x`/`.debug$S` closure already agree. History contributes no unseen
  mechanism, and the prior 13-form source sweep covered declaration type/order,
  expression/operand/statement order, split conditions and comparisons.
  A new census found 9,829 retained definitions/1,102 bodies; all 777
  retail-length bodies remain nonexact with floor `nd=101`. Together with the
  6,149-state carrier ledger, this closes natural source/state search. Reopen
  only for authentic final-release source/PDB or a natural 1,260-byte,
  427-instruction same-symbol witness that changes all repeated clusters while
  preserving closure and zero collateral.

- Parked authenticated-control blocker for
  `0x100170e0 CarRace::HandlePathStruct`: the sole fresh source-first lead is
  to reuse existing `secondAnim` in the first score arm before assigning
  `m_secondFinishAnimation`. It is semantics-preserving and statically explains
  the complete EAX/common-tail scheduling residue, but it was deliberately not
  compiled because no fresh control could reproduce the authoritative
  1,391-byte body `b2102e3c...`. Plain source emitted `235eb3e2...` under both
  scratch and exact canonical paths; byte-exact retained `fwdE-72` source
  emitted `c449f18a...` under the canonical invocation. All controls retained
  62 relocations/86 lines and ordinary `.debug$F`/`.debug$S` closure. The
  retained `b210...` object is therefore bound to its complete historical
  sweep invocation (`s.cpp` cwd/path, prepended real-TU include and scratch
  Fo/Fd/PDB state), not its declaration recipe alone. Reopen only by replaying
  that invocation byte-for-byte and first obtaining a fresh exact `b210...`
  control; then test this one source change, with no broader rewrite.

- Fresh exhaustive seal: `0x10061010 LegoAnimationManager::FUN_10061010`
  has no intact source/build-state route. Current is 717 bytes/208
  instructions/frame `0x2c`, with an out-of-line `MxListEntry<LegoTranInfo*>`
  ctor; retail is 731/211/frame `0x38` and inlines the 12-byte node link while
  caching three additional lifetimes. Git/all-refs and 8,877 retained source
  copies add no uncensused authentic form. A 44,290-object scan found 8,831
  definitions/49 bodies and no frame `0x38`; the sole 731-byte body is the
  already-sealed manual-node/MxS32 probe at `nd=462`, wrong topology and 25
  non-target changes. Extensive inline, source, carrier and text×carrier grids
  can remove the ctor or move the frame separately, but never compose retail's
  731-byte/211-insn/16-call/35-reloc/frame-`0x38` state without collateral.
  Reopen only for authentic final-release source/PDB/object or a natural intact
  state demonstrating that complete combination; ctor disappearance or length
  alone is insufficient.

- Parked fresh-control blocker for
  `0x100a3840 TglImpl::MeshBuilderImpl::CreateMesh`. A genuinely novel source
  hypothesis remains: copy parameter `vertexCount` to one local and pass that
  identity through the existing inline call, which could induce retail's
  early EBX lifetime and remove exactly the current extra three-byte reload.
  It was not compiled because no exact fresh control could reproduce the
  authoritative 667-byte body `83a97d4c...`. Path-short and exact logical
  source/cwd/Fo/Fd controls both emitted `0a59467e...` with 49 non-relocation
  differences at +268..+362; even seeding the exact canonical object-local PDB
  (SHA `772e40d1...`) produced the same alternate state. All controls retained
  667 bytes/19 relocations/6 lines, 113 functions, 133 primary COMDAT
  identities and exact xdata, but differed in semantic relocation seating and
  CodeView. History/source census found no prior alias, while 9,602 retained
  definitions contain zero retail-length 664-byte emitters. Reopen only after
  a fresh invocation naturally reproduces `83a97d4c...`; then test this sole
  lifetime alias under the identical state and require zero collateral in all
  six header consumers.

- Fresh static seal: `0x100a12a0 TglImpl::TextureImpl::SetImage` is 83
  bytes/39 instructions on both sides. Its complete residue is an EBX/EBP role
  swap plus retail loading parameter `pImage` into EDI six bytes earlier; the
  sole callback relocation remains at +51. An exhaustive 9,643-definition
  census found six bodies and no exact emitter. The best 2,309 objects reach
  `nd=16` and already fix EBX/EBP, but every one retains the late parameter
  load. Git/BETA10 authenticate the current two-local source and explicit
  stack-parameter use; declaration/init variants and `register void* appData`
  are measured byte-inert even under the best carrier. A syntactically novel
  `register Image* pImage` lacks any authentic provenance and is not a valid
  source-first cell. Reopen only on authenticated source/PDB evidence for a
  different parameter lifetime or a natural exact 83-byte emitter with the
  same relocation and closure.

- Fresh exhaustive seal: `0x10073a90 Act3::Enable` has no authentic source or
  compiler-state lead beyond its six measured scheduler bodies. A reconciled
  corpus contains 8,745 authoritative states (8,621 ordinary carriers plus
  124 `a5` text×carrier cells), all sharing one 26-relocation sequence and
  only sizes 928/929/930; 2,360 states reach retail's 929-byte length, but the
  floor is `nd=105`. A broader 10,659-definition scan adds no body. The whole
  best-body residue is confined to +0x245..+0x2e0 and is three loop-setup
  operations scheduled/coloured differently across the pizza and donut loops;
  both sides have 253 instructions and no missing statement. Git and 10,658
  source artifacts retain one reused loop index and the same control/order.
  The known `a5` loop spelling and both 256-sample upstream entropy runs only
  revisit the same six-body orbit and introduce collateral. Reopen only for
  authenticated final source/PDB/object showing a different loop lifetime or
  a deterministic C2 dimension that first emits a seventh body with exact
  929-byte/26-relocation semantics and zero collateral.

- Fresh static seal: `0x100bd020 MxBitmap::BitBltTransparent` is pure
  allocator/scheduler colour. Current and retail are both 415 bytes/166
  instructions with one semantic call relocation at +0x4b and identical work;
  zero asymmetric frame traffic exists. Git/all refs yield five function texts,
  retained sources 4,902 definitions/two texts, and retained objects 4,871
  definitions/55 bodies, all with the same 415-byte/one-reloc/15-line shape;
  floor is `nd=60`, exact count zero. The historically causal source steps
  already landed the loop-body shape and stride order; wrapper/early-return,
  guard naming, counter/stride widths, all pointer/stride declaration orders
  and carrier/pad families were measured. Reopen only on contemporaneous
  source/PDB lifetime evidence for a genuinely new distinction or a natural
  normalized-exact object preserving the complete closure and zero collateral.

- Exact-name upstream entropy replay is negative and sealed for
  `0x1006e720` (hide-animation map `_Insert`). Seed `834471695` was rebuilt
  independently as the authentic 373-byte LF-only declaration header
  `a3ac2f6fff62451d5d36250601fd196336a2da2d2b670809ec1356f6f0763fe2`
  and force-included at its historical seat on current effective source
  `19f495a4...`; exhaustive current and legacy artifact scans proved that
  exact name/header state had not previously been replayed. The fresh control
  reproduced the canonical 686-byte target/body `929c2ea9...`. The sole seed
  cell stayed 686 bytes/body `5d991bc9...`, retained current relocation seats
  rather than retail's 689-byte closure, and changed 43 non-target runtime
  functions plus four xdata/linker records. Function/COMDAT identities stayed
  260/302, but the natural target and collateral gates both fail. No third
  cell, link or reccmp ran. Evidence is
  `/private/tmp/codex-hideinsert-seed.DDECKt/result.json`, SHA-256
  `0cae18b23bfcce995c27ef14ab297b9ef431c49f208262880b77765c92eee1ee`.
  Reopen only with materially different authenticated owner source or a
  current-source object proving the exact 689-byte body, relocation/closure
  topology and zero runtime collateral; repeating this seed is closed.

- Exact-name upstream entropy replay is also negative and sealed for
  `0x1004f9b0` (texture-info map `_Insert`). Seed `834471173` was independently
  reconstructed as the authentic 255-byte LF declaration header
  `b0e35f3c658f88f43305e121db4427dd9bcac76b1a130b0fa81f8f16a03b7af9`
  and replayed at the historical pre-SmartHeap `/FI` seat on current effective
  source `85cf2b74...`. The fresh control was fully canonical and had zero
  normalized runtime/linker drift: 681 bytes/body `6bb3fb8e...`, eight semantic
  relocations, 40 lines, 60 functions and 76 primary COMDATs. The sole seed
  cell remained 681 bytes/body `565d04e7...` rather than retail's 679-byte
  body, kept the current relocation seats, changed 26 non-target runtime
  functions and changed linker payload. Identity universes remained 60/76,
  but both target and collateral gates fail. No third cell, link or reccmp
  ran. Evidence is
  `/private/tmp/codex-legotex-insert-seed.FemstV/v1/result.json`, SHA-256
  `872d871d8e9fc1e4e3a951971e08338bf272ab4a46ce13cb7539bbc64573c55a`.
  Repeating this named header on the same source is closed.

- Exact-name upstream entropy replay is negative and sealed for
  `0x10083890` (character-map `_Insert`). Seed `834471431` was independently
  reconstructed as the authentic 841-byte LF declaration header
  `ff85bb75c3d6ba274e27445d9b1431df6b3c394664fb6b916bb9972dcea5c354`
  and replayed at the historical pre-SmartHeap `/FI` seat on current effective
  source `3ef8f161...`. A fresh paired control reproduced the canonical
  652-byte target/body `d33e9bee...`, its nine semantic relocations, 40 lines,
  ordinary debugF/debugS closure and the 132-function/152-COMDAT/36-linker
  identity universes. The control had five unrelated runtime-body changes
  versus the retained canonical object, so the sole seed cell was evaluated
  only as complete-target-donor evidence against that fresh control. It stayed
  652 bytes/body `5d71138b...` rather than retail's 653-byte body: one comparison
  byte moved toward retail, five new comparison mismatches appeared, and the
  terminal four-byte tie remained. Twenty-eight non-target bodies changed;
  no natural exact donor exists. No third cell, link or reccmp ran. Evidence is
  `/private/tmp/codex-character-insert-seed834471431.43q_lhru/paired-result.json`,
  SHA-256
  `dfafbceacadb9d311d73dbeb0fac5df8afa2022937b17dfadd742c57cb47ac0b`.
  Repeating this exact seed/current-source cross is closed.

- Exact-name upstream entropy replay is negative and sealed for
  `0x1006c200` (animation-substitution map `_Insert`). Seed `834471940` used
  the independently reconstructed authentic 1,401-byte LF declaration header
  `d9d75147c09e3eab1a32dc7a741e814f97f30926b0b12c7897e87ee514c064bc`
  at the historical pre-SmartHeap `/FI` seat on current effective source
  `19f495a4...`. The sole successful compiler cell stayed at 678 bytes/body
  `8b7106bd...`, with current relocation seats and coherent 678-byte
  CodeView/FPO closure, rather than entering retail's 682-byte body orbit.
  Function/COMDAT identities stayed 260/302, but 43 non-target runtime bodies,
  three linker payloads and 21 section-shape entries changed. The seed did
  move `BuildROIMap` naturally from 622 to retail length 617 at `nd=10`, and
  moved anim-structure `_Insert` from 686 to 689/690, so those effects remain
  useful state evidence but are not target donors. No third cell, link or
  reccmp ran. Evidence is
  `/private/tmp/codex-animsubst-seed834471940-fullruntime.n0d9c6fa/result.json`,
  SHA-256
  `efc6b30ebac680e5bfad72496f3625b288f19804d3b083fc8683fde010ea07d5`.
  Repeating this exact seed/current-source cross is closed.

- Exact-name upstream entropy replay is negative and sealed for
  `0x1006a7a0` (animation-structure map `_Insert`). Seed `834471941` used the
  independently reconstructed authentic 629-byte LF declaration header
  `1fed02faf90172f471a67866d2e7c8f7acdc2744ff1d652382d622743c4d239d`
  at the historical pre-SmartHeap `/FI` seat on the same current effective
  `legoanimpresenter.cpp`. The sole seed cell stayed 686 bytes/body
  `5d991bc9...`, with current relocation seats and coherent 686-byte CV/FPO
  closure, rather than retail's 690-byte body. It changed only six target
  bytes from the fresh control—the already-known six-byte hide-seed orbit—but
  changed 41 non-target runtime bodies and two linker payloads. Function,
  COMDAT and section identities remained 260/302/826. No third cell, link or
  reccmp ran. Evidence is
  `/private/tmp/codex-animstruct-seed834471941.p9jmefuv/result.json`, SHA-256
  `a92cddd12b974dffa9dcc6565e72903fa17664aa9f3a122e081107049b1b8f3e`.
  Repeating this exact seed/current-source cross is closed.

- Exact-name upstream entropy replay is negative and sealed for
  `0x10059dc0` (texture-info map `erase`). Seed `834469889` used the authentic
  583-byte LF declaration header
  `30bd40ed01079264f32b4d0f237d70a3b14e61dfecaf473de66ea0b33bd4ad99`
  (3 classes/14 methods, distributed `3,10,1`) at the historical pre-SmartHeap
  `/FI` seat on current effective `legomain.cpp` source `6aa2be8d...`. The
  upstream owning source was materially different (`88e295cf...`). A fresh
  control emitted the canonical 1,103-byte body `23ccda7e...`; the sole seed
  cell entered the already-known 1,114-byte orbit `36dc427f...`, not the
  required natural 1,102-byte retail body `851f0e9a...`. Its relocation tail
  moved to `599,737,832,938,1027,1084`, and coherent FPO/CV closure retained a
  26-byte prolog and 1,114-byte procedure size. Function/primary-COMDAT
  identities stayed 81/120, but ten non-target runtime COMDAT bodies changed,
  15 rdata COMDATs changed seats, and global/associative debug metadata moved.
  No third cell, link or reccmp ran. Evidence is
  `/private/tmp/texerase834469889v1xxxxxxxxxxxxx/result.json`, SHA-256
  `1ba4511b55850b86a4ee7274627d8fd1c4bbbeb435f6a43ee59112ff59fa08ef`.
  Repeating this exact seed/current-source cross is closed. The existing exact
  cross-TU instruction hybrid remains necessary unless a materially different
  authenticated current-source state naturally emits the entire retail COMDAT
  and same-TU closure without accepted-row loss.

- Accepted canonical gate: LEGO1 4880/4934, ISLE 172/172, CONFIG 111/111.
  The latest gain is `0x10040360 Act3Cop::FUN_10040360`. The checked-in
  source now expresses the fallback as a second `grec == NULL` guard and
  seats the existing `local100` declaration between the two fallback vectors.
  A fresh suffix-only 20-forward-declaration state emits the complete
  2,496-byte retail-exact function and its ordinary EH closure naturally;
  `equal_body_eh_reloc_layout` imports that intact compiler output. The same
  authenticated donor preserves the previously exact 100-byte
  `list<Act3Ammo*>::~list` COMDAT through `equal_body_strict`, and the
  current-source `extern_run_pair(13,60,width2)` redial restores the existing
  exact `Act3Brickster::Animate` donor. No inline assembly, opcode patch,
  instruction mosaic or manual instruction reordering is involved. The
  forced-fresh zero-loss gate held all prior rows and produced accepted-row
  identity
  `39d995fd0e635c7d26dec43b2f6c41202488e14c16585d6696859b9d34c257f2`;
  verification report SHA-256 is
  `bbdc9a4ce555f79c82bedeb7687cea28a756c48d3781f1770356ab86ae6d8476`
  and manifest SHA-256 is
  `4272f308d3f7ec4d8a4b288af82029e2d4ce19eb588a5c87d58a1336d8e3475d`.

  The preceding gain is
  `0x10046050 LegoPathController::PlaceActor`. The checked-in source now uses
  a `boundary != NULL` wrapper with separate loop-exhaustion and null-boundary
  `FAILURE` returns; this is distinct from the previously sealed one-return
  positive-nesting form. The ordinary source emits the 696-byte seed, while
  the freshly generated, declaration-only `extern_run_pair(1,16,width2)`
  state emits the complete retail-exact 703-byte function with all 13 retail
  relocation seats, ordinary FPO/CodeView closure, and body SHA-256
  `46d3ef30674c79bef277f86a09155ee24dd89a7bb39235ae2865629fa1df6a65`.
  Existing `same_slot_resize` imports that intact compiler-emitted COMDAT and
  closure into the seed; there is no inline assembly, instruction mosaic,
  manual instruction reordering, or synthesized opcode patch. The forced-fresh
  zero-loss gate held LEGO1 4879/4934, ISLE 172/172 and CONFIG 111/111. Its
  LEGO1 report SHA-256 is
  `6059bb9de588c24ffb9963facaea3c6143d7d357d179f1b8981d6814fbaddfdc`,
  accepted-row identity is
  `e636e71d5505ed20e54d2841225e45369b07de145cb4ae802507c302245efb5e`,
  verdict SHA-256 is
  `9acf2c57e60e3e0ac473d34a812002dfce37e1437ecc9e51bb7fcba368c41e84`,
  and manifest SHA-256 is
  `2d480d0485ba21158f64236ff026305dfdb51ca60f0e6ca0e5caddb6835ecf73`.

  The preceding gain is
  `0x100b26f0 MxVideoPresenter::AlphaMask::IsHit`. A fresh, declaration-only
  `extern_run_pair(100,8,width2)` carrier supplies the exact same 101-byte,
  relocation-free COMDAT through a closed ordinary-FPO self-permutation role.
  Raw, per-TU and manifest-wide checks require its sole primary use to be this
  composer and forbid ordinary, resize, source, instruction, variant,
  secondary or legacy reuse. The exact carrier descriptor is embedded in the
  same-function source identity, equals the donor recipe byte-for-byte and
  derives the same 108 generated identifiers for raw and normalized dispatch;
  every identifier must remain absent from effective source.

  Seed and donor bodies are
  `ec6893ea59a4fc048fb1970eed084894946845988b6aa42a61e6abbffabf80fb`
  and
  `4f5244c45248b468a140fad7af68adc877f09f6136f47eeca4640d72bcefc7d4`.
  A line-certified two-instruction sequence changes `[13,17)` from
  `3bc6734c` to `3bf0764c`. A typed bijection then commutes `xor edi,edi` and
  `mov edx,[esp+0x14]` across `[17,23)`, with a closed register/flag/memory
  effect proof. Exactly offsets 14, 15 and 17--22 change, producing literal
  retail body SHA-256
  `396edefeaa6433477d701b4f0ad053572ddffb7739f54dc4f8ffeb5444a06864`.
  The seed's FPO/CodeView closure, line table, empty relocation table,
  function/COMDAT/section/linker universe and every non-target byte remain
  authoritative. A same-body forward-declaration alternative is rejected by
  its changed local `.xdata$x` relocation, and the private donor is excluded.

  The first production dispatch stopped fail closed because it passed the raw
  function record to a composer initially proven with the normalized record.
  The product-neutral descriptor binding now derives identical carrier facts
  in both paths; mismatch, identifier leakage and role-reuse regressions cover
  the fix without changing any body or metadata pin.

  Discovery produced this sole gain with no loss; report SHA-256 is
  `6c50f613db341abb83d2df777e752c55d9d87e9c35fff70923d1ffa14e4c9fb8`
  and accepted-row identity is
  `4e99e0bdb2dda1aeb7003dc14d0db2b4c0517071583dfc13462a2432de263bcc`.
  Marker-removed forced-fresh confirmation held the same 4878 accepted set
  with zero delta and left ISLE and CONFIG complete. Discovery marker SHA-256
  is `6ad5c79528adf4d05166ff9660fa480ff87753a4048ef5d357210cde52cce39a`;
  confirmation marker SHA-256 is
  `6741e751373c2febdcbf064630a83481a955862a670e4d6708dd9d6c004c6e47`,
  LEGO1 report SHA-256 is
  `a1bd8943d36f2b9eb13f6aaf7328cb995e462ca9768d78989846ca206315a458`,
  verdict SHA-256 is
  `18d02e4256cff281e94765d1eb04e55c4e5a8e39daa7ebaf5ea5d610c1a07b9d`,
  and manifest SHA-256 is
  `6b64d791b57df930b95ec64c5e412d06f2a295ce2ccda7d62613a30289c65185`.

  The preceding gain is
  `0x1004bd10 MxTransitionManager::DissolveTransition`. A closed
  `fixed_array_shuffle_countdown` source generator replaces one exact indexed
  640-element shuffle with its equivalent typed pointer/countdown form. The
  inverse rendering reconstructs the checked-in loop byte-for-byte. Pinned
  include edges and declarations prove the array is `MxU16[640]`, the index
  and swap are `MxS32`, the pointer is fresh, every random draw and aliasing
  case retains its order, and the index is overwritten before its changed exit
  value can be read. Raw, per-TU and manifest-wide role gates restrict this
  source recipe to one primary source-FPO instruction mosaic and forbid every
  ordinary, variant, secondary, repeated or alternate-composer use.

  Seed and fresh donor are both 438 bytes at section 55/79 with eight semantic
  relocations and the exact two-child `.debug$F`/`.debug$S` closure. Their
  bodies are
  `9850d0b4a91610ecea9aacf0e0822b7fcd26e98f8ed7ceebf9a0ad031efc65b6`
  and
  `d8dcb9786d75ee60e3a18e12920ebc47cf8835c9fa9e9faf3572c8eec4bc61ac`.
  Six line-certified complete instructions at `[60,63)`, `[63,68)`,
  `[68,71)`, `[77,81)`, `[88,89)` and `[96,100)` make the target body
  retail-exact. The fail-closed decoder adds only the live `8d`, `e8`, `99`,
  `4b`, `4f`, and single `66`-prefixed `8b`/`89` forms. The source-FPO branch
  is mutually exclusive with the ordinary-FPO branch; it permits the pinned
  donor CodeView size change 206 to 221 while requiring identical procedure
  identity, parsed FPO, semantic child relocations and seed-authoritative
  output metadata. The donor and its three runtime collateral changes are
  excluded, and every non-target output byte remains the canonical seed's.

  The evidence donor used a long projected source path, while the canonical
  runner compiles production-relative `s.cpp`. That changes only `.file`
  auxiliary symbol bookkeeping (402 to 387 raw symbol records; target index
  297 to 282). Independent reconstruction proved the four runner-authentic
  changes are raw-index-only: donor line `0bec99cf...` to `a6c20283...`,
  debug-F relocation `b158bbd0...` to `f8769d95...`, debug-S relocation
  `d8e74b20...` to `07ef049c...`, and metadata `9f18ce0b...` to `427ca9c5...`.
  Bodies, post-sentinel line rows, semantic relocations, closure, FPO,
  CodeView and every function/COMDAT body stayed exact.

  Discovery produced this sole gain with no loss; its report SHA-256 is
  `94f2d6dd913a3ef7b26b2d88e4dd8abbc6c96f6db028826cf228d9da787d63de`.
  Marker-removed forced-fresh confirmation held the same 4877 accepted set
  with zero delta and left ISLE and CONFIG complete. Its marker SHA-256 is
  `d71343772e8432cbb113fc6bb416770027894e7bffb61412ba32059b0db077fd`,
  LEGO1 report SHA-256 is
  `496a060d0b3445c5e4961c45367590748485e64ea6ec5d2e6241332cc05fa15b`,
  verdict SHA-256 is
  `edac7b87b1b8a53c9c9aaf9b5a12dc2bb02d05c5e510e58a1985c263579524de`,
  and manifest SHA-256 is
  `a2d7eef5bbae0976eca2ea7c7fb973094c0d3e2fdbf9f08e4cb9cc52ed8a92f9`.

  The preceding gain is `0x100bb1d0 MxDisplaySurface::VTable0x30`. Its ordinary
  `declaration_shape(4,27)` donor is protected by an exact FPO-only role:
  raw, per-TU and manifest-wide gates require its sole use to be this one
  primary FPO-aware instruction mosaic and forbid secondary, source, variant
  or repeated use. The donor is freshly rebuilt from the current effective
  source and excluded from the archive/link.

  Seed and donor are both 811 bytes at section 51/88 with two relocations and
  44 line rows. Their bodies are
  `0e6db537fdd488dac53f74ca9d45e2060a52c637b7236305593aaa644b521630`
  and
  `86be2090dc2f9e3604436b8a7d343d6f598fef2decc878eb75114b85aef193c4`.
  Thirteen corrected half-open, same-offset instruction sequences produce
  retail-exact body SHA-256
  `9fba51eb1777b626f4ff595f7789292b9d2dfe17772f535a6acbaf6882b0594d`.
  The exact-function line sentinel and nearest compiler rows certify both
  endpoints and the declared instruction-length partitions in both fresh
  objects. The fail-closed decoder adds only the live `01`, `03`, `2b`,
  `0f af`, `41`, `43`, `45`, `74`, `7c`, `7d`, `7f`, `eb` and `f7 /3`
  forms. The complete seed-authoritative `.debug$F`/`.debug$S` closure is
  independently pinned and parsed: classic FPO `procSize` is 811, the
  CodeView procedure marker/ranges and child semantic relocations are exact,
  and the existing EH and new FPO branches cannot cross. Both retail code
  relocations, seed metadata and every non-target byte remain unchanged;
  donor-only collateral at 499, 506, 729 and 736 is excluded.

  Discovery produced the sole gain and no loss with report SHA-256
  `d57c52a00d76ec86de9b6fca065be39c9e25d60a1fdd00eb223775ead3996dce`.
  Marker-removed forced-fresh confirmation regenerated the eight-function
  composition and marker, held the identical 4876 set, and left ISLE and
  CONFIG complete. Its marker SHA-256 is
  `6fca23e5f3864bb247477997e6fb33019d9546d514413476d6c353c42522a963`,
  LEGO1 report SHA-256 is
  `4826fca34cc7d0529e189e714a0a66330a32ae7e7339ea51bc80f25ef95e7ead`,
  verdict SHA-256 is
  `62e74837bf86d0430cd1047af4b044db6aacd2532fb46c4d5d90e25ad09755c0`,
  and manifest SHA-256 is
  `ba5dca4ab7df9f4331fd973a28661f828f0ff2c95c9e820fec62b826ac2359ae`.

  The preceding gain is
  `0x100a66f0 ViewManager::ManageVisibilityAndDetailRecursively`. The checked-in
  and effective target function source is identical in both fresh donor
  states. A closed `prefix_forward_after_includes_extern` carrier renders a
  typed forward run at an authenticated byte-zero seat and a typed extern run
  at the authenticated after-includes seat. Both full renderings are pinned,
  every generated identifier is absent from the effective source, and the
  1,732-byte brace-balanced target window is byte/token identical in the seed
  and donors. Raw and normalized manifest gates bind the 34-forward target
  carrier exactly once as a primary donor and the 64-forward instruction
  carrier exactly once as the sole secondary donor; reuse in any ordinary,
  variant, repeated or unbound role is forbidden.

  The canonical pre-row target is 557 bytes. Both carriers produce a 561-byte
  target at section 116/250 with 11 relocations, 28 line rows, 80 functions,
  85 primary COMDATs and the same `.debug$F`/`.debug$S` closure. The target
  and instruction bodies are
  `b1271a13524dc400bf0305b25b45d49fc8b9cff06bf5f4376cbf5c4b7bb97f2b`
  and
  `a3e8fd96e27f02f4ede351f764216c2361969b3552d423b2a2fc3362f529321e`.
  One line-certified complete instruction at offsets 516--517 changes
  `3bc8` to `3bc1` and creates retail-exact hybrid body SHA-256
  `01949ffd3e0c851db40055f6a1c5978091144dea8b2de977502762fe061c76e8`.
  The donor's 576-byte linked span governs even though the old seed rounded to
  560. All 11 retail relocations, target-carrier metadata and every canonical
  non-target byte remain authoritative; both private donors are excluded.
  Scratch objects were evidence only and the canonical fresh objects matched
  every packet pin. Discovery produced the sole gain with report SHA-256
  `e9e6f5413e72eceeec406ce46eab04dafa2ab50223a217ea7d9562fec384c5b9`.
  Marker-removed confirmation regenerated the composition and held the same
  4875 set with report SHA-256
  `fda4683e20e1d7f4a03e8a080130f2d062720daeb905dd855cd590c7317042d1`
  and verdict SHA-256
  `32b792741c0bb1b7fe021b29c53e65aff7361d89992170ebfdb6a0b36765b9ea`.
  The manifest SHA-256 is
  `ca98ce3721d3cfd7e54787e47c1843ec69ab771a30ed16cf01f23fb7c4a80176`.
  The preceding gain is `0x10069b10 LegoAnimPresenter::BuildROIMap`. Its checked-in
  discarded postfix increment remains canonical because the direct prefix
  form changes 40 shared bodies and adds a COMDAT. A donor-private typed
  `discarded_postfix_increment_v1` rendering changes only `it++;` to `++it;`
  and replays the TU's canonical overlay. The semantic witness binds `it` to
  the project map alias and sealed VC4.2 iterator definitions, proves prefix
  and postfix each execute exactly one `_Inc()` transition, and excludes
  observable temporary copy/destructor state through the exact iterator
  inheritance, sole node-pointer member and special-member census. The source
  recipe is rejected from the shipped overlay and is inventoried directly at
  raw-manifest preflight; it has exactly one instruction-only binding and no
  primary, variant, repeated or unbound use.

  The 622-byte canonical seed is resized through a 617-byte declaration-only
  carrier. The typed source donor is also 617 bytes. Eleven same-offset
  complete instructions create hybrid body SHA-256
  `43e4ef651a4d79561d766737b64ff6597055163640bd6bd3484f2df8979d0373`;
  the adjacent offset-416 change is truthfully split into three-byte and
  one-byte instructions. The line-row-anchored closed decoder proves every
  endpoint in both fresh objects, all 23 relocations are retail authenticated,
  carrier metadata and the canonical seed's non-target bytes remain
  authoritative, and both donors are excluded. The scratch packet's longer
  build root created 28 extra `.file` auxiliary records, so only raw symbol
  indices differed; canonical metadata pins are
  `9162966902f2e893b7eedc7fb26a7d09d2eb90d4dbe42f208a97f1d38d5305ea` and
  `62b0b69aead015aa21df70e097ac8184af66572c85b6aa7988bf77789dcbe630`,
  with every body and semantic metadata fact unchanged.
  Discovery produced the sole gain and no loss with report SHA-256
  `e7b9ca57fc3e8dbf9a2326cecf6c551bc6d58b632e00b790bb611c59dc859909`.
  Marker-removed confirmation held the same 4874 set with report SHA-256
  `616b87401af356edb31b9d320f17482480a2eb0b10017169d5aa7df87ed972fe`
  and verdict SHA-256
  `407a0dfcdb5e99a8915e50566d216960b5f8c95f2277c712cb9b528cfcd3b623`.
  The preceding gain is `0x100ba7f0 MxDisplaySurface::Create`. Its checked-in
  inclusive-width accessor assignment remains canonical because the direct
  logic-equivalent source form perturbs six other function bodies. A
  donor-private `inclusive_extent_assignment_v1` rendering computes a typed
  right-minus-left value, increments it, crosses the one closed guarded empty
  MSVC/i386 assembly barrier and assigns it. The algebraic identity is tied to
  a unique three-header include chain, whole-file and declaration pins, and a
  full 530-byte concrete-class pin; all three witness headers are forbidden
  from the effective overlay and the concrete class may not shadow any of the
  three inherited accessors. The canonical seed and fresh donor are both 660
  bytes with three equivalent semantic relocations. Replacing only the
  complete 12-byte sequence at offsets 489--500 changes the seed's `[11, 1]`
  instruction partition to the donor's `[1, 11]` partition and produces the
  retail-exact body SHA-256
  `966cdf3a4b96d872beb6b04c4b9568ba19767cc7975e17bcb77fa3bbf687b11b`.
  The composed object retains the seed's 57-row line table, complete
  `.debug$F`/`.debug$S` closure and every non-target byte; the 58-row donor is
  excluded from the link. A marker-removed forced-fresh confirmation produced
  exactly this gain with zero losses; its report SHA-256 is
  `ddd69d4874d8eb6e1fdfd86fa9cff69d32a639adab338bb795ea4c8ea0a4fc94`
  and verdict SHA-256 is
  `4ec52e11080e022e4332459ea5d32434cb5b04be586a21e3101032b032120016`.
  The preceding gain is `0x10017af0 PizzeriaState::PizzeriaState`. The checked-in
  whole-array `memset` remains the canonical source because landing its
  logic-equivalent typed loop directly perturbs the already-exact `Serialize`
  row. A donor-private `fixed_array_fill_loop_v1` rendering emits exactly
  `for (MxS32 i = 0; i < 5; i++) m_states[i] = -1;`; its literal bound is
  structurally tied to the SHA-pinned `MxS32 m_states[5]` member declaration
  in the uniquely identified header that the target translation unit directly
  includes. Exact decorated-owner binding, an unshadowed-member census, a
  fresh index and a closed integral index-type set prevent the generic recipe
  from weakening that equivalence proof. The donor also has exactly one
  manifest-wide primary use, which is its source-aware binding; all secondary
  roles are forbidden. The canonical seed and fresh donor
  bodies are both 264 bytes with 17 equivalent semantic relocations; three
  complete instruction sequences at offsets 186--197, 202--209 and 211--219
  produce the retail-exact body SHA-256
  `12d517ae112fa47477a5f6e35e0361641ad502c057ef64df08aeef8160da48d6`.
  The final object retains the seed's nine-row line table, complete metadata
  closure and every non-target byte; the eight-row donor is excluded from the
  link. The forced-fresh confirmation produced exactly this gain with zero
  losses; its report SHA-256 is
  `38755b55e8f7ce764653e59ac74a2c7a1bf01f9305a730ab64708fe527ba7c9d`
  and verdict SHA-256 is
  `9ef9117b4bcbcf637d9163255f09e0dc2cbf9760f53d3c101d9a034cd3cdb43c`.
  The preceding gain is `0x10059dc0 _Tree<LegoTextureInfo*>::erase`. The canonical
  1,103-byte `legomain.cpp` seed is resized through a fresh 1,102-byte
  declaration-only target donor with body SHA-256
  `c600bf89a868f041db33c3ca1c2b1ee9718c8a1a1be0c1bf1ac893e85ddd46ca`.
  A different, unmodified current-source translation unit, compiled through
  its own pinned command, emits the exact same mangled COMDAT with a 1,104-byte
  body SHA-256 of
  `18aa8de3a8bd6ef6fdfa9e7393066ea40d0c2e01cd53522aa4c4b77b751ccd14`.
  Its complete instruction `394c2410` at offset 145 replaces `3b4c2410` at
  target offset 151; neither range overlaps a relocation. The 1,102-byte
  hybrid body SHA-256 is
  `851f0e9a57984afaf02ecf6d1e52c5ad0daae945e12b8cd820e58759e2c6787a`
  and is retail-exact under all 16 authenticated relocations. The final object
  retains the target donor's relocation/line/FPO/debug metadata and the
  canonical seed's non-target contents, and both donors are excluded. A
  forced-fresh confirmation produced exactly this gain with zero losses; its
  report SHA-256 is
  `49092e6cb77ee1a515f741d908f161ae36562e39f9f8f58c3125c418b100b2aa`
  and verdict SHA-256 is
  `cb4bbefaa46f9b1130dc789fcacc8dca54e288bea07d76f57e8690b4f7cdacfd`.
  The preceding gain is `0x100c6fa0 MxDSBuffer::FUN_100c6fa0`. A closed,
  manifest-declared five-fragment source permutation of the exact same
  mangled function snapshots the volatile cursor and routes its unequal-case
  return through a tail label. The freshly compiled donor is 225 bytes while
  the canonical seed remains 234 bytes; only the donor's two complete
  four-byte instructions at seed offsets 161--168 are imported. The final
  seed-length body SHA-256 is
  `689e0a7113d9d96a3b3c3fd7c00b35ea0800efb5d0fa363f8b12e62f10ed647c`
  and is literally equal to retail. The target has no relocations, and the
  seed line/FPO/debug tables, function set and every non-target byte remain
  authoritative. The zero-loss confirmation report SHA-256 is
  `fbadb68a85514633a7adc42735e822496a39eeb455fcf0133bd695c37fa03942`;
  verdict SHA-256 is
  `236589b7232cf3d25bf0a8fc8dc363ec177e7bfd053b7bb60312381c6e644752`.
  The preceding gain is `0x100586e0 LegoPathBoundary::RemovePresenter`. The
  authentic for-initializer spelling perturbs another already-exact COMDAT
  when landed directly, so checked-in source retains the standalone iterator.
  Two manifest-declared current-source variants of the exact same 314-byte
  mangled COMDAT supply seven disjoint complete-instruction sequences. The
  composed body SHA-256 is
  `acd459bf93ab369ef7e9e28b9d19ece17981614a7e3f472f9755172f1577d8c0`;
  all six seed relocations, line/FPO/debug metadata and non-target bytes remain
  authoritative, and both donors are excluded from the link. The zero-loss
  confirmation report SHA-256 is
  `ce43e5279fbf69279c109f178172838b9941ef2012c739bc629e5307656b493b`;
  verdict SHA-256 is
  `34c8aae9fae7498ae967865d643a4946abf00f4df1ae6aad4a1bd5912e21a68d`.
  The preceding gain is `0x1007ca30 LegoPartPresenter::Read`. A freshly generated
  declaration-only donor of the exact same 2,633-byte mangled COMDAT supplies
  four complete instructions; the composed body is retail-exact under all 111
  authenticated relocations. Two imported instructions fully contain their
  unchanged `_Nil` DIR32 operands, which is admissible only because the donor
  and seed operands, relocation records and semantic targets are identical.
  The seed relocation/line/debug/EH tables and every non-target byte remain
  authoritative. The zero-loss confirmation report SHA-256 is
  `05161395eeb7320cb0c41c519095c4e31e7116ab280575c396cb30373dc3c573`;
  verdict SHA-256 is
  `ce643a9564ef7701468d3ffd4429e490d1463d62a24246b31eb8d9514c9acee3`.
  The preceding gain is `0x100a4420 OrientableROI::OrientableROI`, extracted
  from a freshly generated, donor-private source permutation of the exact
  same mangled COMDAT. The checked-in target source is unchanged; the donor
  renders two typed header permutations, through an explicitly declared
  path-preserving private source projection, and emits the retail-exact
  514-byte body with all 23 retail relocation targets. The composed object
  retains every seed non-target section/function, appends only the strict
  undefined `Vector3(float*)` symbol required by the retail call, and excludes
  the donor object. The zero-loss confirmation report SHA-256 is
  `abf77b69e313375a56f8ce914d36f0acc989e2661488dcaf469938a11b91ac82`.
  The preceding two gains are strict same-function instruction mosaics for
  `0x1009a8c0 LegoWEGEdge::LinkEdgesAndFaces` and
  `0x100c3750 MxRegion::AddRect`. Both seed and donor objects are freshly
  generated from the current checked-in source plus declaration-only manifest
  carriers; only pinned complete instructions at the same offsets are copied,
  relocation operands are excluded, seed/donor relocation semantics and
  debug/EH closure are equal, all seed metadata/non-target bytes are retained,
  and the composed bodies are retail-exact. The zero-loss confirmation gate
  completed in 13.6 seconds with LEGO1 report SHA-256
  `1d6385d1b4ce58579a312c4b0915d376089959873840ece9f82615d35d43aea7`.
  Removing exactly those two rows from the 4866 accepted set reproduces the
  prior 4864 identity SHA-256 `60f9ebfa9c16b88b53222703597aee7b544c95993ccd5c520a39ea3814841126`.
  The preceding authentic direct-source `0x100d0d80 ReadData` gain remains
  retail-exact at 424 bytes, and the source-generated Class-C substitution for
  `0x1001d890` remains independently proved by a frozen 4862/4863/4862 A/B/A2
  link sequence.
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
- The historical Act3Ammo `AaTail` exact claim is stale for the current tree.
  Fresh A/A2 testing, including reversal of the earlier `radius` hoist, kept
  the target at 2665 bytes with masked distances 934--959 rather than retail's
  2666-byte body.  Relocation and call semantics stayed stable, but no literal
  exact donor exists in that lane; do not repeat it without a new mechanism.
- WriteDefaultTexture's authentic historical `surface`-before-`bits`
  declaration order is also negative on the current tree (854 bytes, masked
  distance 42 versus the current 33).  The reproduced `extern_run_pair`
  h24/p90 state remains a useful same-function lead at distance 12, but the
  tested palette-alias source forms changed length and relocation/call state
  and are not admissible.
- `0x100998e0 LegoTextureContainer::GetCached`: moving `newDesc` to its first
  use and comparing height before width is a direct, logic-neutral source
  refactor. It changes only the target code COMDAT, preserves all 18 relocation
  semantics and 12 direct calls, reduces the object residue from 61 to 57
  bytes, and raises canonical raw matching from about 0.86965 to
  `0.878698224852071`. The complete 4862 accepted-row gate passed with no loss;
  it is committed in `14e2ff22`.

## Upstream entropy-aggregation oracle (2026-08-16)

The public `isledecomp/isle` accuracy page is the aggregate of 256 deterministic
entropy builds, not one binary. At upstream commit
`31bd20de79df0a2d2d26b63f734e155ddd17e8ae`, workflow run `31911463768`
generates 16 jobs x 16 headers with `tools/entropy.py`. The seed is
`(int(commit[:8], 16) & 0xffff0000) + (matrix << 8) + build_index`; each header
contains only unused classes and unused inline empty methods. The aggregate
constructs rows independently across those samples, so `recomp: "various"` is
expected. Its published choice is not always the literal raw maximum: the
historical sort key ties all `effective:true` rows, allowing stable input order
to hide a higher raw non-effective sample. Always scan all 256 raw reports and
maximize the numeric `matching` field directly.

The GitHub sample JSONs, old source tree, old `entropy.py`, and their
binaries/objects are evidence and search oracles only. They must not become
build dependencies: do not check out a historical commit from the identity
runner, execute or pin the historical entropy script, or admit downloaded
artifacts. Delta-reduce an exact historical state into a self-contained recipe
over today's checked-in source. The final compiler-state declaration shape and
every alternate source spelling belong explicitly in the entropy manifest,
then pass the normal full-body, semantic-relocation, object-conservation, and
zero-loss link gates.

The aggregate's `0x100c6fa0 MxDSBuffer::FUN_100c6fa0` row was only an effective
match: both it and the then-current local build had raw
`0.9882352941176471`, with the same adjacent `cmp`/`mov` schedule
transposition. That residue is now solved literally through the closed
same-function source-permutation mosaic recorded in the live checkpoint; the
aggregate artifact itself was never an input.

Thirty-seven latest-run sample maxima have a strictly higher raw score than our
4862 report. Only `0x100586e0 RemovePresenter` reaches literal raw 1.0. The only
older still-downloadable 256-sample run (`30217987205`, commit `bb7130c2`) adds
no exact row that the latest run lacks and no additional cross-run improvement
above the latest envelope. Use the other 36 rows only as mechanism/reachability
evidence, not as destinations. The most important measured targets are:

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

The other strict improvements include `0x10062e20`, `0x1004ebd0`, `0x100a3840`,
`0x100a7960`, `0x100bb1d0`, `0x10069b10`, `0x10084030`, `0x10048310`,
`0x10073a90`, `0x100a66f0`, `0x1006b140`, `0x10029d50`, `0x10072ad0`,
`0x1003d170`, `0x10085500`, `0x100417c0`, `0x100a46b0`, `0x10054050`,
`0x1009a8c0`, `0x100aa510`, `0x100bd020`, `0x1002a1b0`, `0x100b26f0`,
`0x10057180`, `0x100166a0`, `0x100c3750`, and `0x1007ca30`. They are not
landing candidates until a source/dial path reaches raw 1.0.

The historical exact `RemovePresenter` sample was used only as an oracle. Its
state has now been delta-reduced into two explicit current-source manifest
recipes and accepted through the generic same-COMDAT multi-donor mosaic above;
no historical source, generator, header, report or object is a build input.

- Fresh-eyes cross-TU whole-COMDAT census: EMPTY beyond the separately owned
  `0x1002bff0` path-tree `erase` landing. Intersecting the 54 current misses
  with the all-symbol retained-object screens leaves one other masked `nd=0`
  body, `0x10084030 LegoCharacterManager::CreateActorROI`, but it is a proven
  relocation false positive: object offsets 101 and 1220 call
  `Vector2::Vector2` while retail calls `Vector3::Vector3` (the other 79 of 81
  relocations agree). The only unused strict-retail whole-COMDAT state is
  `0x1006b140 LegoAnimPresenter::CopyTransform` (948 bytes, 20 relocations,
  `.debug$S` plus `.xdata$x`, body `2d69ac14...`), whose 944-to-960-byte linked
  span adds an uncompensated 16 bytes; no unused exact -16 state remains, so it
  cannot land without address losses. Current-build alternate definers and the
  389,288-object corpus plus 10,708-object refresh expose no further natural
  exact emitter. Static evidence: `/private/tmp/codex-mosaic-cover-results.json`
  SHA-256 `c18947ce...`, S109 nonzero-span census `690a30e0...`, and S110
  semantic near-donor census `7fc32983...`. Do not repeat this cross-TU census
  without genuinely new artifacts.
