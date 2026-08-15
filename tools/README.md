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
