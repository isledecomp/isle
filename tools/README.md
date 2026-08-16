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
and enforces the row/literal-byte gates:

```bash
export ISLE_BYTE_IDENTITY_WINE_BUNDLE="/Applications/Wine Stable.app"
export ISLE_BYTE_IDENTITY_WINE_PREFIX_TEMPLATE=/absolute/path/to/prefix-template
export ISLE_BYTE_IDENTITY_RECCMP_EXECUTABLE=/absolute/path/to/reccmp-reccmp
export ISLE_BYTE_IDENTITY_PYTHON_RUNTIME_ROOT=/absolute/path/to/python-3.12-runtime
export ISLE_BYTE_IDENTITY_HOMEBREW_PREFIX=/absolute/path/to/homebrew
export ISLE_BYTE_IDENTITY_HOMEBREW_CELLAR=/absolute/path/to/homebrew/Cellar
export ISLE_BYTE_IDENTITY_RECCMP_PACKAGE_ROOT=/absolute/path/to/reccmp/package
export ISLE_BYTE_IDENTITY_RECCMP_SITE_PACKAGES=/absolute/path/to/site-packages
python3 tools/isle_build.py \
  --build-dir /absolute/path/outside/the/tree \
  --compiler /absolute/path/to/msvc420/wine/x86/cl \
  --baseline-report /absolute/path/to/current-accepted-LEGO1-report.json
```

The runner fully validates the manifest and its pinned compiler/linker,
runtime, source-overlay, archive, original-image, and reccmp inputs before it
builds. Iteration runs are incremental (an unchanged cycle takes seconds; a
full build a few minutes) and print named row gains/losses against the required
explicit baseline report. Manifest-declared compiler/link and reccmp deadlines
bound direct producer/reccmp work; the aggregate CMake driver has a separate
bounded anti-wedge ceiling. All launched jobs use runner-owned POSIX process
groups so a timed-out wrapper tree is cancelled as one unit.

The current pinned source-true baseline is 4866/4934. `--terminal` requires all
4934 LEGO1 rows, all 172 ISLE rows, and all 111 CONFIG rows to be raw-exact,
then requires each stamped no-/debug image to be literally byte-identical to
its retail oracle (with both SHA-256 and MD5 pins checked). Diagnostic-build
addresses are reported but terminal address/layout identity comes from the
byte-identical no-/debug image.

Reccmp's separate `Implemented` denominator includes known-but-unmatched CRT and
library entries (three in LEGO1 and five in ISLE). ISLE is already terminal-byte
identical despite those five diagnostic-PDB misses. They are recorded rather
than hidden or papered over: the function gate is raw 1.0 for every comparable
row and Accuracy 100.00%; literal terminal identity proves the remaining runtime
bytes and is the stronger final condition.
