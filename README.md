# LEGO Island Decompilation

[Development Vlog](https://www.youtube.com/playlist?list=PLbpl-gZkNl2COf_bB6cfgTapD5WduAfPz) | [Matrix](https://matrix.to/#/#isledecomp:matrix.org) | [Forums](https://forum.mattkc.com/viewforum.php?f=1) | [Patreon](https://www.patreon.com/mattkc)
  
This is a **work-in-progress** decompilation of LEGO Island version 1.1. It aims to be relatively faithful, but not byte accurate. The goal is to provide a workable codebase that can be modified, improved, and ported to other platforms later on.

## Status

*TODO: A progress bar showing the percentage progress of this decompilation.*

Currently `ISLE.EXE` is completely decompiled, however there are some known inaccuracies. It should work if you pair it with the original game's `LEGO1.DLL` (and other files), however small things may not work correctly yet. Work on decompiling `LEGO1.DLL` has only just started and currently it is too incomplete to be usable.

## Building

LEGO Island was compiled with Microsoft Visual C++ 4.20, so that's what this decompilation targets. However, building with newer versions of Visual C++ using CMake should also work.

### Assembling Kit

Pick a directory without spaces to use as the root of your kit. Set this as the `ISLE_KIT_ROOT` in your preferred shell (on Windows' CMD for instance, `set ISLE_KIT_ROOT=X:/path/to/kit`).

Clone [MSVC420](https://github.com/itsmattkc/msvc420) to [kit root]/msvc420.

Install the DirectX 5 SDK, changing the location to [kit root]/dx5sdk.

### Configuring CMake

`cmake -Bbuild --toolchain cmake/Toolchain/msvc42.cmake -DCMAKE_BUILD_TYPE=Release`

On Linux, you need to use `scripts/cm420` to configure the build.

## Usage

Simply place the compiled `ISLE.EXE` into LEGO Island's install folder (usually `C:\Program Files\LEGO Island` or `C:\Program Files (x86)\LEGO Island`). Unless you're a developer, disregard the compiled `LEGO1.DLL` for now as it is too incomplete to be usable. Alternatively, LEGO Island can run from any directory as long as `ISLE.EXE` and `LEGO1.DLL` are in the same directory, and the registry keys point to the correct location for the asset files.

Ideally, this decompilation should be paired with version 1.1. It may work on 1.0 too, however this is not guaranteed.

## Additional Information

### Which version of LEGO Island do I have?

Right click on `LEGO1.DLL`, select `Properties`, and switch to the `Details` tab. Under `Version` you should either see `1.0.0.0` (1.0) or `1.1.0.0` (1.1). Additionally, you can look at the game disc files; 1.0's files will all say August 8, 1997, and 1.1's files will all say September 8, 1997. Version 1.1 is by far the most common, especially if you're not using the English or Japanese versions, so that's most likely the version you have.

### SmartHeap

Both `ISLE.EXE` and `LEGO1.DLL` were originally statically linked with [SmartHeap](http://www.microquill.com/smartheap/sh_tspec.htm), a drop-in replacement for malloc/free that presumably provides better heap memory management on the old low-memory (16MB) systems this game was designed for. Unfortunately, acquiring SmartHeap legally is expensive, and the chances of acquiring the exact same version used by Mindscape in the late 90s is very low. Since it's a drop-in binary-compatible replacement, this decomp can just stick with the standard malloc/free functions while still achieving matching assembly on a per-function level, however the resulting binaries will never be byte accurate as a result of this. If you notice significant size disparities, particularly in ISLE.EXE, the lack of statically linked SmartHeap libraries is why.
