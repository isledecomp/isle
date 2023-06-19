# LEGO Island Decompilation

[Development Vlog](https://www.youtube.com/playlist?list=PLbpl-gZkNl2COf_bB6cfgTapD5WduAfPz) | [Contributing](https://github.com/isledecomp/isle/blob/master/CONTRIBUTING.md) | [Matrix](https://matrix.to/#/#isledecomp:matrix.org) | [Forums](https://forum.mattkc.com/viewforum.php?f=1) | [Patreon](https://www.patreon.com/mattkc)
  
This is a **work-in-progress** decompilation of LEGO Island version 1.1. It aims to be relatively faithful, but not byte accurate. The goal is to provide a workable codebase that can be modified, improved, and ported to other platforms later on.

## Status

*TODO: A progress bar showing the percentage progress of this decompilation.*

Currently `ISLE.EXE` is completely decompiled, however there are some known inaccuracies. It should work if you pair it with the original game's `LEGO1.DLL` (and other files), however small things may not work correctly yet. Work on decompiling `LEGO1.DLL` has only just started and currently it is too incomplete to be usable.

## Building

LEGO Island was compiled with Microsoft Visual C++ 4.20, so that's what this decompilation targets. However it should compile with NMAKE on newer versions of Visual Studio too.

### Recommended Instructions

These instructions use the development IDE from Visual C++ 4.20. By modern standards, it can be a little clunky to use, especially on newer versions of Windows, however it's still relatively straightforward. If you prefer a command line process that can fit into a modern workflow/IDE, see the instructions below.

1. Install Microsoft Visual C++ 4.20. This can be found on many abandonware sites, but the installer can be a little iffy on modern versions of Windows. For convenience, I made a [portable version](https://github.com/itsmattkc/msvc420) that can be downloaded and used quickly instead.
2. Download and install the DirectX 5 SDK. Similarly, this can be found on many abandonware sites.
3. Open "Microsoft Developer Studio" (`BIN/MSDEV.EXE` for those using the portable).
4. `File` > `Open Workspace`
5. Select `ISLE.MDP` from this repository.
6. Select a build configuration. `ISLE - Win32 Release` is recommended because, at this point in time, you'll almost certainly be pairing it with the retail `LEGO1.DLL`, which is also a release build.
7. `Build` > `Build ISLE.EXE`. This will build `ISLE.EXE` in a folder called `Release`. It will also build `LEGO1.DLL` since it's listed as a dependency, however the `LEGO1.DLL` produced is too incomplete to be usable at this time.

### Command Line Instructions

For some users, this may be preferable to using an obsolete graphical IDE. Any modern IDE should support custom command line build steps, making this potentially easier to fit into a familiar contemporary workflow. This guide assumes a general familiarity with the Windows command prompt.

1. Acquire Visual Studio/Visual C++. Any version after 4.20 should work here, but 4.20 is the only one guaranteed to work. If you wish to use 4.20, it can be found on many abandonware sites, but the installer can be a little iffy on modern versions of Windows. For convenience, I made a [portable version](https://github.com/itsmattkc/msvc420) that can be downloaded and used quickly instead.
2. Download and install the DirectX 5 SDK. Similarly, this can be found on many abandonware sites, but later versions of Visual Studio include the DirectX SDK by default, so this step may be skippable (you definitely need it for MSVC 4.20).
3. Open an x86/32-bit developer command prompt. Depending on the version of VS you're using, you may have a start menu item for it already (e.g. `x86 Native Tools Command Prompt`). Alternatively, you can start a normal command prompt (`cmd`) and run `vcvars32.bat` from the Visual Studio folder (run `BIN/VCVARS32.BAT x86` if you're using the portable 4.20).
4. `cd` to the folder you cloned this repository to.
5. `mkdir Release` if the folder doesn't already exist. Some versions of NMAKE may make this folder by itself, but some don't.
6. Run `nmake /f isle.mak CFG="ISLE - Win32 Release"`. This will build `ISLE.EXE` in the `Release` folder you just made. It will also build `LEGO1.DLL` since it's listed as a dependency, however the `LEGO1.DLL` produced is too incomplete to be usable at this time.

## Usage

Simply place the compiled `ISLE.EXE` into LEGO Island's install folder (usually `C:\Program Files\LEGO Island` or `C:\Program Files (x86)\LEGO Island`). Unless you're a developer, disregard the compiled `LEGO1.DLL` for now as it is too incomplete to be usable. Alternatively, LEGO Island can run from any directory as long as `ISLE.EXE` and `LEGO1.DLL` are in the same directory, and the registry keys point to the correct location for the asset files.

Ideally, this decompilation should be paired with version 1.1. It may work on 1.0 too, however this is not guaranteed.

## Contributing

If you're interested in helping/contributing to this project, check out the [CONTRIBUTING](https://github.com/isledecomp/isle/blob/master/CONTRIBUTING.md) page.

## Additional Information

### Which version of LEGO Island do I have?

Right click on `LEGO1.DLL`, select `Properties`, and switch to the `Details` tab. Under `Version` you should either see `1.0.0.0` (1.0) or `1.1.0.0` (1.1). Additionally, you can look at the game disc files; 1.0's files will all say August 8, 1997, and 1.1's files will all say September 8, 1997. Version 1.1 is by far the most common, especially if you're not using the English or Japanese versions, so that's most likely the version you have.

### SmartHeap

Both `ISLE.EXE` and `LEGO1.DLL` were originally statically linked with [SmartHeap](http://www.microquill.com/smartheap/sh_tspec.htm), a drop-in replacement for malloc/free that presumably provides better heap memory management on the old low-memory (16MB) systems this game was designed for. Unfortunately, acquiring SmartHeap legally is expensive, and the chances of acquiring the exact same version used by Mindscape in the late 90s is very low. Since it's a drop-in binary-compatible replacement, this decomp can just stick with the standard malloc/free functions while still achieving matching assembly on a per-function level, however the resulting binaries will never be byte accurate as a result of this. If you notice significant size disparities, particularly in ISLE.EXE, the lack of statically linked SmartHeap libraries is why.
