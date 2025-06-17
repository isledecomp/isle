# LEGO Island Decompilation Tools

Accuracy to the game's original code is the main goal of this project. To facilitate the decompilation effort and maintain overall quality, we have devised a set of annotations, to be embedded in the source code, which allow us to automatically verify the accuracy of re-compiled functions' assembly, virtual tables, variable offsets and more.

The tooling we have developed has been moved to the [reccmp](https://github.com/isledecomp/reccmp) repo to facilitate its use in other decompilation projects.
* See the [README](https://github.com/isledecomp/reccmp?tab=readme-ov-file#getting-started) on how to get started.
* Familiarize yourself with the available [annotations](https://github.com/isledecomp/reccmp/blob/master/docs/annotations.md) and the [best practices](https://github.com/isledecomp/reccmp/blob/master/docs/recommendations.md) we have established.

The following scripts are specific to LEGO Island and have thus remained here:
* [`patch_c2.py`](/tools/patch_c2.py): Patches `C2.EXE` (part of MSVC 4.20) to get rid of a bugged warning.

# Modules
The following is a list of all the modules found in the annotations (e.g. `// FUNCTION: [module] [address]`) and which binaries they refer to. See also [this list of all known versions of the game](https://www.legoisland.org/wiki/LEGO_Island#Download).

## Retail v1.1.0.0 (v1.1)
* `LEGO1` -> `LEGO1.DLL`
* `CONFIG`-> `CONFIG.EXE`
* `ISLE` -> `ISLE.EXE`

These modules are the most important ones and refer to the English retail version 1.1.0.0 (often shortened to v1.1), which is the most widely released one. These are the ones we attempt to decompile and match as best as possible.

## BETA v1.0

* `BETA10` -> `LEGO1D.DLL`

The Beta 1.0 version contains a debug build of the game. While it does not have debug symbols, it still has a number of benefits:
* It is built with less or no optimisation, leading to better decompilations in Ghidra
* Far fewer functions are inlined by the compiler, so it can be used to recognise inlined functions
* It contains assertions that tell us original variable names and code file paths

It is therefore advisable to search for the corresponding function in `BETA10` when decompiling a function in `LEGO1`. Finding the correct function can be tricky, but is usually worth it, especially for longer functions.

Unfortunately, some code has been changed after this beta version was created. Therefore, we are not aiming for a perfect binary match of `BETA10`. In case of discrepancies, `LEGO1` (as defined above) is our "gold standard" for matching.

## Pre-Alpha

* `ALPHA` -> `LEGO1D.DLL`

This debug build is hardly used since it has little benefit over `BETA10`.


# Re-compiling a beta build

If you want to match the code against `BETA10`, use the following `cmake` setup to create a debug build:
```
cmake <path-to-source> -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_BUILD_TYPE=Debug -DISLE_USE_SMARTHEAP=OFF -DISLE_BUILD_BETA10=ON -DISLE_BUILD_LEGO1=OFF
```

If you can figure out how to make a debug build with SmartHeap enabled, please add it here.

If you want to run scripts to compare your debug build to `BETA10` (e.g. `reccmp-reccmp`), it is advisable to add a copy of `LEGO1D.DLL` from Beta 1.0 to `/legobin` and rename it to `BETA10.DLL`. Analogously, you can add `LEGO1D.DLL` from the Pre-Alpha and rename it to `ALPHA.DLL`.

# Finding matching functions

This is not a recipe, but rather a list of things you can try.
* If you are working on a virtual function in a class, try to find the class' vtable. Many (but not all) classes implement `ClassName()`. These functions are usually easy to find by searching the memory for the string consisting of the class name. Keep in mind that not all child classes overwrite this function, so if the function you found is used in multiple vtables (or if you found multiple `ClassName()`-like functions), make sure you actually have the parent's vtable.
* If that does not help, you can try to walk up the call tree and try to locate a function that calls the function you are interested in.
* Assertions can also help you - most `.cpp` file names have already been matched based on `BETA10`, so you can search for the name of your `.cpp` file and check all the assertions in that file. While that does not find all functions in a given source file, it usually finds the more complex ones.
* _If you have found any other strategies, please add them here._
