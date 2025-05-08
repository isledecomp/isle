# LEGO Island Decompilation

[Development Vlog](https://www.youtube.com/playlist?list=PLbpl-gZkNl2Db4xcAsT_xOfOwRk-2DPHL) | [Contributing](/CONTRIBUTING.md) | [Matrix](https://matrix.to/#/#isledecomp:matrix.org) | [Forums](https://forum.mattkc.com/viewforum.php?f=1) | [Patreon](https://www.patreon.com/mattkc)
  
This is a **work-in-progress** decompilation of LEGO Island version 1.1. It aims to be as accurate as possible, matching the recompiled instructions to the original machine code as much as possible. The goal is to provide a workable codebase that can be modified, improved, and ported to other platforms later on.

## Status

<img src="https://legoisland.org/progress/ISLEPROGRESS.SVG" width="50%"><img src="https://legoisland.org/progress/LEGO1PROGRESS.SVG" width="50%">

Currently `ISLE.EXE` is completely decompiled and behaves identically to the original. A handful of stubborn instructions are not yet matching, however we anticipate they will as more of the overall codebase is implemented.

`LEGO1.DLL` is still very much incomplete and cannot be used at this time. Instead, if you want to test this, it is recommended to pair the recompiled `ISLE.EXE` with the `LEGO1.DLL` from the original game.

## Building

This projects uses the [CMake](https://cmake.org/) build system, which allows for a high degree of versatility regarding compilers and development environments. For the most accurate results, it is recommended to use Microsoft Visual C++ 4.20 (the same compiler used to build the original game). Since we're trying to match this to the original executable as closely as possible, all contributions will be graded with the output of this compiler.


These instructions will outline how to compile this repository into an accurate instruction-matching binary with Visual C++ 4.2. If you wish, you can try using other compilers, but this is at your own risk and won't be covered in this guide.

#### Prerequisites

You will need the following software installed:

- Microsoft Visual C++ 4.2. This can be found on many abandonware sites, but the installer can be a little iffy on modern versions of Windows. For convenience, I made a [portable version](https://github.com/itsmattkc/msvc420) that can be downloaded and used quickly instead.
- [CMake](https://cmake.org/). A copy is often included with the "Desktop development with C++" workload in newer versions of Visual Studio, however it can also be installed as a standalone app.

#### Compiling

1. Open a Command Prompt (`cmd`).
1. From Visual C++ 4.2, run `BIN/VCVARS32.BAT x86` to populate the path and other environment variables for compiling with MSVC.
1. Make a folder for compiled objects to go, such as a `build` folder inside the source repository (the folder you cloned/downloaded to).
1. In your Command Prompt, `cd` to the build folder.
1. Configure the project with CMake by running:
```
cmake <path-to-source> -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo
```
  - **Visual C++ 4.2 has issues with paths containing spaces**. If you get configure or build errors, make sure neither CMake, the repository, nor Visual C++ 4.2 is in a path that contains spaces.
  - Replace `<path-to-source>` with the source repository. Can be `..` if your build folder is inside the source repository.
  - `RelWithDebInfo` is recommended because it will produce debug symbols useful for further decompilation work. However, you can change this to `Release` if you don't need them. `Debug` builds are not recommended because they are unlikely to be compatible with the retail `LEGO1.DLL`, which is currently the only way to really use this decomp.
  - `NMake Makefiles` is most recommended because it will be immediately compatible with Visual C++ 4.2. For faster builds, you can use `Ninja` (if you have it installed), however due to limitations in Visual C++ 4.2, you can only build `Release` builds this way (debug symbols cannot be generated with `Ninja`).
1. Build the project by running `nmake` or `cmake --build <build-folder>`
1. When this is done, there should a recompiled `ISLE.EXE` and `LEGO1.DLL` in the build folder.

If you have a CMake-compatible IDE, it should be pretty straightforward to use this repository, as long as you can use `VCVARS32.BAT` and set the generator to `NMake Makefiles`.

## Usage

Simply place the compiled `ISLE.EXE` into LEGO Island's install folder (usually `C:\Program Files\LEGO Island` or `C:\Program Files (x86)\LEGO Island`). Unless you're a developer, disregard the compiled `LEGO1.DLL` for now as it is too incomplete to be usable. Alternatively, LEGO Island can run from any directory as long as `ISLE.EXE` and `LEGO1.DLL` are in the same directory, and the registry keys point to the correct location for the asset files.

## Contributing

If you're interested in helping/contributing to this project, check out the [CONTRIBUTING](/CONTRIBUTING.md) page.

## Additional Information

### Which version of LEGO Island do I have?

Right click on `LEGO1.DLL`, select `Properties`, and switch to the `Details` tab. Under `Version` you should either see `1.0.0.0` (1.0) or `1.1.0.0` (1.1). Additionally, you can look at the game disc files; 1.0's files will all say August 8, 1997, and 1.1's files will all say September 8, 1997. Version 1.1 is by far the most common, especially if you're not using the English or Japanese versions, so that's most likely the version you have.
