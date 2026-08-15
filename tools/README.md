# LEGO Island Decompilation Tools

Accuracy to the game's original code is the main goal of this project. To facilitate the decompilation effort and maintain overall quality, we have devised a set of annotations, to be embedded in the source code, which allow us to automatically verify the accuracy of re-compiled functions' assembly, virtual tables, variable offsets and more.

The tooling we have developed has been moved to the [reccmp](https://github.com/isledecomp/reccmp) repo to facilitate its use in other decompilation projects.

* See the [README](https://github.com/isledecomp/reccmp?tab=readme-ov-file#getting-started) on how to get started.
* Familiarize yourself with the available [annotations](https://github.com/isledecomp/reccmp/blob/master/docs/annotations.md) and the [best practices](https://github.com/isledecomp/reccmp/blob/master/docs/recommendations.md) we have established.

The following scripts are specific to LEGO Island and have thus remained here:

* [`patch_c2.py`](/tools/patch_c2.py): Patches `C2.EXE` (part of MSVC 4.20) to get rid of a bugged warning.
* [`patch_smartheap_331.py`](/tools/patch_smartheap_331.py): Regenerates `3rdparty/smartheap/SHLW32MT.LIB` (SmartHeap 3.31, as linked by the original binaries) from the 3.30 lib in git history plus the original `ISLE.EXE`.
* [`gen_smacker_lib.py`](/tools/gen_smacker_lib.py): Regenerates `3rdparty/smacker/smackw32.lib` by carving the original Win32 Smacker contribution out of the original `LEGO1.DLL`.

## Byte-identical builds: `isle_build.py`

The byte-identity build is driven by `tools/isle_build.py`. It renders the
typed entropy manifest into an effective source view, builds it with the
pinned MSVC 4.2 toolchain through the ordinary CMake graph, applies the
manifest's COMDAT compositions, scores the result with the pinned reccmp,
and enforces the row/MD5 gates:

```bash
export ISLE_BYTE_IDENTITY_RECCMP_EXECUTABLE=/absolute/path/to/reccmp-reccmp
python3 tools/isle_build.py \
  --build-dir /absolute/path/outside/the/tree \
  --compiler /absolute/path/to/msvc420/wine/x86/cl        # or a native CL wrapper
```

Authenticity is carried by pins and outputs, not by environment modeling:
the compiler/linker binaries, the manifest and rendered sources, the reccmp
verifier, and the produced objects/image/report are all hash-checked; a
misbehaving host can only fail the gates, never fake a pass. Iteration runs
are incremental (an unchanged cycle takes ~10 seconds; a full build a few
minutes) and print named row gains/losses against the pinned accepted set.
`--terminal` additionally requires 4933/4933 and the retail LEGO1.DLL MD5.

The current pinned source-true baseline is 4769/4933. The historical 4816
accepted set additionally contained retained-corpus donor objects whose
source recipes are not yet in the manifest; that 47-row delta plus the
remaining open rows form the queue toward 4933/4933.

## Legacy resident framework (deprecated)

`ISLE_BYTE_IDENTICAL` with `tools/byte_identity.py drive-cmake` is the
previous resident-authority framework. It is superseded by `isle_build.py`
and scheduled for removal; only the manifest validator/renderer, the COFF
composer, and the reccmp gates from `byte_identity.py` remain load-bearing.

The checked source tree is the clean decompilation view. Byte-identical mode
reconstructs its private effective source view from the single checked
manifest: 173 outputs and 414 typed operations, located by unique structural
and significant-token context anchors. Missing or ambiguous anchors are fatal.
Every generated fragment and effective output is hash-, size-, line-, and
token-pinned; literal/static insertion, free-form templates, fragment assets,
and raw-text escape hatches are forbidden. The remaining declaration-shape
compiler-state donor is explicitly `synthetic_baseline_only` and non-emitting.

The manifest owns only artificial compiler/linker-state constructs. Anything
the original developers plausibly wrote stays ordinary checked source even
when it is dead code, provided independent structural evidence exists: the
CONFIG `dsound` link plus `Detect3DSound` (retail CONFIG.EXE carries a
zero-function DSOUND.dll import descriptor), the `LegoTestTimer` console
control (its getch.obj/initcon.obj CRT data survives in retail LEGO1.DLL),
and `FlushFrameBuffers` (decompiled from Beta 9.0 at 0x100a1880; retail
retains its orphaned dxguid GUID). Purely synthetic stand-ins whose bodies
have no provenance (record carriers, pad TUs, suppliers, emission probes, the
`IsleUnusedArrayHelper` vector-destructor stand-in) remain manifest-owned.

The ordinary CMake graph contains only clean ordinary sources. When the typed
overlay is enabled, its graph recipe adds exactly 20 generated-only C++ logical
paths at their pinned source-list seats. Those paths remain absent from
the checkout: CMake emits configure metadata and compile-database commands,
then the resident materializes their authenticated effective bytes inside the
held execution projection. No prebuilt generated source artifact is trusted.

Select the physical host seats explicitly. These values may live anywhere,
but each path must be absolute, canonical, and match the file or complete-tree
identities pinned in the manifest:

```bash
export ISLE_BYTE_IDENTITY_WINE_BUNDLE=/absolute/path/to/Wine.app
export ISLE_BYTE_IDENTITY_WINE_PREFIX_TEMPLATE=/absolute/path/to/pinned-prefix
export ISLE_BYTE_IDENTITY_RECCMP_EXECUTABLE=/absolute/path/to/reccmp-reccmp
export ISLE_BYTE_IDENTITY_PYTHON_RUNTIME_ROOT=/absolute/path/to/python/3.12
export ISLE_BYTE_IDENTITY_HOMEBREW_PREFIX=/absolute/path/to/homebrew-prefix
export ISLE_BYTE_IDENTITY_HOMEBREW_CELLAR=/absolute/path/to/homebrew-cellar
export ISLE_BYTE_IDENTITY_RECCMP_PACKAGE_ROOT=/absolute/path/to/reccmp-package
export ISLE_BYTE_IDENTITY_RECCMP_SITE_PACKAGES=/absolute/path/to/site-packages
```

`ISLE_BYTE_IDENTITY_WINE_PREFIX_TEMPLATE` must name the dedicated immutable
template root, not `~/.wine`, an active `WINEPREFIX`, or any prefix Wine has
ever been allowed to update. Its root mode is exactly `0555`; its complete
membership is the four regular `0444` leaves `.update-timestamp`, `system.reg`,
`user.reg`, and `userdef.reg` with the manifest-pinned hashes. Extra entries,
aliases, writable modes, or a redirected root are fatal. One
transaction-scoped writable prefix is initialized from only those four seed
files. Producer leases are serial; every child ends with a mandatory
prefix-scoped Wine-server drain and identity proof. The prefix is content- and
metadata-rescanned once at terminal finalization, then removed with the
transaction projection. Native reccmp retains its separate private prefix.

Use an absolute build directory outside the source tree, the same pinned CMake
executable for every invocation, and the absolute pinned VC4.2 compiler wrapper.
The driver fixes the generator to `Unix Makefiles`; do not pass `-G`:

```bash
python3 -I -B tools/byte_identity.py drive-cmake \
  --source-dir "$PWD" --build-dir /absolute/path/to/build-identical \
  --cmake /absolute/path/to/cmake \
  --compiler /absolute/path/to/wine/x86/cl \
  --mode configure --
python3 -I -B tools/byte_identity.py drive-cmake \
  --source-dir "$PWD" --build-dir /absolute/path/to/build-identical \
  --cmake /absolute/path/to/cmake \
  --compiler /absolute/path/to/wine/x86/cl \
  --mode iterate --
```

Configure mode supplies sealed VC4.2 compiler facts and absolute CXX, RC, LIB,
and LINK seats, so CMake performs no compiler-ID, ABI, resource, archive, or
link probe. It publishes only configure metadata and does not copy the Wine
toolchain, strict runtime, command snapshot, or native reccmp runtime. In
iteration and terminal modes CMake also remains a configure-only plan producer.
The resident independently rederives that metadata, materializes and holds the
toolchain and command inputs exactly once, copies the closed recipes into a
held private namespace, then directly executes every compile, RC, LIB, LINK,
and reccmp stage. The private Python/reccmp runtime remains lazy until every
LINK producer has succeeded. The driver never invokes `cmake --build` and
never accepts a child CMake build output or child-authored producer receipt.

The compiler-side logical `Z:` input view is materialized once per resident
transaction by merging the authenticated toolchain and command snapshots and
copying each identical immutable leaf only once. Producer invocations lease a
single private writable build seat inside that view; each lease must leave the
seat empty before the next one. Immutable inputs are scanned once when the
projection is created and once immediately before it is removed, prior to the
verification epoch and verdict publication. They are not recopied or rehashed
per translation unit. Dependency discovery uses one `/P` invocation per C/C++
unit and resolves every reported path against that preauthenticated immutable
record map before the `/c` invocation. A direct CMake producer or verification
target therefore intentionally refuses outside the resident process: durable
audit JSON is diagnostic evidence, not a substitute for the resident's
in-memory causal receipts. After each private Wine-server preflight and at the
last cut point before `Popen`, the resident again proves the exact writable
topology, output absence, generated-input bytes and modes, and projected
producer tool/support hashes. Thus a file inserted or replaced during the
preflight interval cannot be grandfathered as producer output or linker input.

Compiler execution maps the generator-authenticated external wrapper spelling
to the exact held wrapper seat in the projection; its environment scripts,
compiler data files, RC DLL/CRT dependency, and LINK/LIB helper executables and
message files are manifest-pinned support leaves. The strict host runtime also
pins every wrapper utility, including `grep`; ambient `PATH` tools are not
admitted. The current single shared projection exposes the complete trusted
support union to all producer roles. Role-specific expected-support audits and
exact executed-tool mapping still reject unpinned consumption, but a future
hardening commit should provide per-role projection overlays/epochs for least
visibility. This limitation is not native-Windows policy and must not be
carried into that adapter by default.

The Wine compiler/RC/LIB/LINK snapshot and the host-Python reccmp snapshot are
separate authorities. Python, reccmp, its relocated runtime, and package
closure never enter the compiler fake `Z:` tree or a common producer receipt;
they are copied into a distinct held namespace only for the reccmp stage.
The manifest selects separate backend-keyed toolchain and reccmp transport
profiles before resolving any physical host root. The common analysis audit
records the selected backend and transport schema; Darwin/Wine details live
only inside that backend's `details` record.
Because reccmp invokes its pinned `cvdump.exe`, that namespace exposes only a
run-private `wine`/`winepath` projection and prefix backed by the already-held
Wine runtime snapshot. Its server is drained before and after the analysis
child, and Python/Wine loaded-image evidence must remain within the private
closures or Darwin system roots. The large Wine host closure is scanned once
per resident transaction, with one bounded terminal rescan closing the run.
Wine may create its unavoidable inode-derived
`/tmp/.wine-<uid>/server-<device>-<inode>` seat outside the private prefix. The
resident derives that one exact seat from the held prefix, rejects a socket,
live server, or any membership beyond Wine's zero-byte `0600` lock, and never
deletes lock directories belonging to stale or foreign prefixes.

The already-running outer driver is the bootstrap trust root for one session.
Its exact installed CMake executable/resource tree and Python
executable/stdlib/runtime image closure, plus the nonce-scoped controller copy,
are hash-pinned before and after each CMake invocation. Persistent mutation is
fatal. At most the one controller snapshot named by the authenticated completed
session is retained; starting the next inactive session retires that exact old
snapshot, while active and unrelated sibling namespaces are never broadly
deleted. A same-UID attacker transiently replacing, executing, and restoring that
trusted controller closure between those checks is explicitly outside the
current threat model. This exception does not extend to source/toolchain
snapshots, compiler outputs, archives, build namespaces, audits, LINK/MAP/PDB
evidence, reccmp output, or the final image: those remain inside the fd-rooted,
fail-closed authority and the resident driver independently recomputes their
entire chain before it alone publishes a verdict.

Immediately after the terminal cold rescan and result verification, the
resident closes every held descriptor and removes the exact strict-runtime,
toolchain, command, native-reccmp, and execution-projection roots. Verdict
publication consumes an in-memory-bound compact finalization/removal receipt;
it never preserves those large copied seats as disk authority. Failure cleanup
attempts every exact root independently and preserves unrelated sibling
namespaces.

The production compiler/composer path currently implements the exact
Darwin/Wine reference backend pinned above. A native-Windows adapter seam
defines logical `Z:`, held no-reparse handles, and kill-on-close Job Objects,
but its toolchain and reccmp profiles are explicitly deferred and untested;
selecting them does not validate Darwin, Homebrew, or Wine host paths.
CMake deliberately refuses a Windows byte-identical production build until
that authority is wired through the complete manifest/compiler/verifier path.
Windows support must not be reported as working in this baseline.

The manifest's retail-payload exception is limited to the named SmartHeap and
Smacker reconstructed third-party archives; it never applies to first-party
code, data, CRT members, padding, or linker-generated payload. The
configure-time imported targets describe only the logical graph and expected
occurrence order. During iteration or terminal production, the resident copies
each pinned archive into its held build-authority seat, records its causal
receipt and exact audit, and rederives the closed link sequence before invoking
LINK directly. A source/archive mutation invalidates the resident copy, audit,
and framework verdict.

Iteration mode executes the full resident producer chain and publishes only a
typed `FINAL_GATES_INCOMPLETE` result. It requires the fixed 4933-row universe,
exactly the pinned set of 4816 rows whose raw floating-point score is `1.0`,
and zero accepted-row losses. It records the current image, PDB, MAP, report,
LINK-audit, and reccmp-audit hashes. It neither requires nor claims retail
image SHA-256/MD5 identity or 4933/4933 completion.

Terminal mode alone requests the byte-identity verdict:

```bash
python3 -I -B tools/byte_identity.py drive-cmake \
  --source-dir "$PWD" --build-dir /absolute/path/to/build-identical \
  --cmake /absolute/path/to/cmake \
  --compiler /absolute/path/to/wine/x86/cl \
  --mode build --
```

That mode runs the framework-owned, nonce-bound release LINK, diagnostic
`/DEBUG` LINK (for PDB/MAP), and reccmp producer chain. A copied retail DLL,
manually written report, stale MAP/PDB, or synthetic audit cannot satisfy the
gate. `BYTE_IDENTITY_COMPLETE` is published only when the fixed row universe has
exactly 4933 entries, every raw score is exactly floating-point `1.0`, every
recompiled address equals its retail address, and `LEGO1.DLL` is byte-for-byte
identical to the pinned original (SHA-256 and MD5).

The terminal Wine link requires `/MAP` plus `/VERBOSE:LIB` evidence that the
authorized `smackw32.lib(smackw32.obj)` is consumed and, independently, that
`omni.lib(mxutilities.cpp.obj)` resolves `_strstr` from the unmodified
`libcmt.lib(strstr.obj)` at `0x100d21f0`. Smacker does not cause that CRT pull;
both facts are separate consequences of the authenticated expanded link input
order. A custom CRT mutation is forbidden.

## Modules

The following is a list of all the modules found in the annotations (e.g. `// FUNCTION: [module] [address]`) and which binaries they refer to. See also [this list of all known versions of the game](https://www.legoisland.org/wiki/LEGO_Island#Download).

### Retail v1.1.0.0 (v1.1)

* `LEGO1` -> `LEGO1.DLL`
* `CONFIG`-> `CONFIG.EXE`
* `ISLE` -> `ISLE.EXE`

These modules are the most important ones and refer to the English retail version 1.1.0.0 (often shortened to v1.1), which is the most widely released one. These are the ones we attempt to decompile and match as best as possible.

### BETA v1.0

* `BETA10` -> `LEGO1D.DLL`
* `CONFIGD` -> `CONFIG.EXE`

The Beta 1.0 version contains a debug build of the game. While it does not have debug symbols, it still has a number of benefits:

* It is built with less or no optimisation, leading to better decompilations in Ghidra
* Far fewer functions are inlined by the compiler, so it can be used to recognise inlined functions
* It contains assertions that tell us original variable names and code file paths

It is therefore advisable to search for the corresponding function in `BETA10` when decompiling a function in `LEGO1`. Finding the correct function can be tricky, but is usually worth it, especially for longer functions.

Unfortunately, some code has been changed after this beta version was created. Therefore, we are not aiming for a perfect binary match of `BETA10`. In case of discrepancies, `LEGO1` (as defined above) is our "gold standard" for matching.

The beta version of the `CONFIG` application has provided some help with matching [MFC handler functions](https://en.wikipedia.org/wiki/Microsoft_Foundation_Class_Library) that are similar to the final version.

### Pre-Alpha

* `ALPHA` -> `LEGO1D.DLL`

This debug build is hardly used since it has little benefit over `BETA10`.

## Re-compiling a beta build

If you want to match the code against `BETA10`, use the following `cmake` setup to create a debug build:

```bash
cmake <path-to-source> -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_BUILD_TYPE=Debug -DISLE_USE_SMARTHEAP=OFF -DISLE_BUILD_BETA10=ON -DISLE_BUILD_LEGO1=OFF
```

If you can figure out how to make a debug build with SmartHeap enabled, please add it here.

If you want to run scripts to compare your debug build to `BETA10` (e.g. `reccmp-reccmp`), it is advisable to add a copy of `LEGO1D.DLL` from Beta 1.0 to `/legobin` and rename it to `BETA10.DLL`. Analogously, you can add `LEGO1D.DLL` from the Pre-Alpha and rename it to `ALPHA.DLL`.

## Finding matching functions

This is not a recipe, but rather a list of things you can try.

* If you are working on a virtual function in a class, try to find the class' vtable. Many (but not all) classes implement `ClassName()`. These functions are usually easy to find by searching the memory for the string consisting of the class name. Keep in mind that not all child classes overwrite this function, so if the function you found is used in multiple vtables (or if you found multiple `ClassName()`-like functions), make sure you actually have the parent's vtable.
* If that does not help, you can try to walk up the call tree and try to locate a function that calls the function you are interested in.
* Assertions can also help you - most `.cpp` file names have already been matched based on `BETA10`, so you can search for the name of your `.cpp` file and check all the assertions in that file. While that does not find all functions in a given source file, it usually finds the more complex ones.
* _If you have found any other strategies, please add them here._
