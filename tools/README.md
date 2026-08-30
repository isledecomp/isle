# LEGO Island Decompilation Tools

Accuracy to the game's original code is the main goal of this project. To facilitate the decompilation effort and maintain overall quality, we have devised a set of annotations, to be embedded in the source code, which allow us to automatically verify the accuracy of re-compiled functions' assembly, virtual tables, variable offsets and more.

The tooling we have developed has been moved to the [reccmp](https://github.com/isledecomp/reccmp) repo to facilitate its use in other decompilation projects.

* See the [README](https://github.com/isledecomp/reccmp?tab=readme-ov-file#getting-started) on how to get started.
* Familiarize yourself with the available [annotations](https://github.com/isledecomp/reccmp/blob/master/docs/annotations.md) and the [best practices](https://github.com/isledecomp/reccmp/blob/master/docs/recommendations.md) we have established.

The following scripts are specific to LEGO Island and have thus remained here:

* [`patch_c2.py`](/tools/patch_c2.py): Patches `C2.EXE` (part of MSVC 4.20) to get rid of a bugged warning.
* [`patch_smartheap_331.py`](/tools/patch_smartheap_331.py): Regenerates `3rdparty/smartheap/SHLW32MT.LIB` (SmartHeap 3.31, as linked by the original binaries) from the 3.30 lib in git history plus the original `ISLE.EXE`.
* [`gen_smacker_lib.py`](/tools/gen_smacker_lib.py): Regenerates `3rdparty/smacker/smackw32.lib` by carving the original Win32 Smacker contribution out of the original `LEGO1.DLL`.
