# LEGO Island Decompilation

[Development Vlog](https://www.youtube.com/playlist?list=PLbpl-gZkNl2Db4xcAsT_xOfOwRk-2DPHL) | [Contributing](/CONTRIBUTING.md) | [Matrix](https://matrix.to/#/#isledecomp:matrix.org) | [Forums](https://forum.mattkc.com/viewforum.php?f=1) | [Patreon](https://www.patreon.com/mattkc)
  
This is a complete decompilation of LEGO Island (Version 1.1, English). It aims to be as accurate as possible, matching the recompiled instructions to the original machine code as much as possible. The goal is to provide a workable codebase that can be modified, improved, and ported to other platforms later on.

> **Note:** This repository is for decompilation only and its code is true to the original release. It will not compile for targets other than 32-bit Windows. For a modern adaptation of the LEGO Island codebase with native compatibility for all major platforms and the Web, see [isle-portable](https://github.com/isledecomp/isle-portable) instead.

## Status

<a href="https://isledecomp.github.io/isle/ISLEPROGRESS.HTML"><img src="https://isledecomp.github.io/isle/ISLEPROGRESS.SVG" width="50%"></a><a href="https://isledecomp.github.io/isle/LEGO1PROGRESS.HTML"><img src="https://isledecomp.github.io/isle/LEGO1PROGRESS.SVG" width="50%"></a>

`CONFIG.EXE`, `ISLE.EXE`, and `LEGO1.DLL` are completely decompiled. The
project's reviewed [ReproBit](https://github.com/isledecomp/reprobit) build uses
the original Microsoft Visual C++ 4.2 toolchain and reproduces all three retail
binaries byte for byte. Work continues on naming, documentation, and source
clarity without changing those results.

## Building

There are two build paths:

- ReproBit produces and certifies the exact release binaries.
- The ordinary CMake build is useful for day-to-day development, but its
  outputs are not release-certified.

### Reproduce the retail binaries exactly

Start with a fresh checkout and install Python 3.11 or newer, Git, and
[ReproBit](https://github.com/isledecomp/reprobit#install-and-set-up-the-pre-release).
macOS and Linux also need Wine. Place your English 1.1 retail files at
`legobin/CONFIG.EXE`, `legobin/ISLE.EXE`, and `legobin/LEGO1.DLL`, then run these
commands from the repository root:

```console
rbit setup .
rbit verify .
```

`setup` obtains and checks the original compiler. `verify` builds everything
from scratch and checks every byte against the retail files. A successful run
writes `build/CONFIG.EXE`, `build/ISLE.EXE`, and `build/LEGO1.DLL`; open
`.reprobit-state/reports/report.html` to review the result.
Use `rbit build .` for faster incremental builds while editing, then run
`rbit verify .` before sharing a result.

GitHub Actions uses the same verification for the continuous release, which
includes the exact binaries, reccmp progress files, and ReproBit's readable
`report.html` plus its full `report.json` record. The ordinary CMake
instructions below remain useful for development builds, but only ReproBit
certifies byte-for-byte release outputs.

### Ordinary developer build

This project uses the [CMake](https://cmake.org/) build system with several
compilers and development environments. Microsoft Visual C++ 4.20 is the
original game's compiler and remains the most representative choice. ReproBit's
byte-for-byte verification is the authoritative result for contributions and
releases.

These instructions build useful local binaries with Visual C++ 4.2. They do
not replace ReproBit's exact verification. Other compilers may work for
experimentation, but are not covered here.

#### Prerequisites

You will need the following software installed:

- Microsoft Visual C++ 4.2. This can be found on many abandonware sites, but the installer can be a little iffy on modern versions of Windows. For convenience, a [portable version](https://github.com/itsmattkc/msvc420) is available that can be downloaded and used quickly instead.
- [CMake](https://cmake.org/). A copy is often included with the "Desktop development with C++" workload in newer versions of Visual Studio; however, it can also be installed as a standalone app.

#### Compiling

1. Open a Command Prompt (`cmd`).
1. From Visual C++ 4.2, run `BIN/VCVARS32.BAT x86` to populate the path and other environment variables for compiling with MSVC.
1. Make a folder for compiled objects to go, such as a `build` folder inside the source repository (the folder you cloned/downloaded to).
1. In your Command Prompt, `cd` to the build folder.
1. Configure the project with CMake by running:
```console
cmake <path-to-source> -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo
```
  - **Visual C++ 4.2 has issues with paths containing spaces**. If you get configure or build errors, make sure neither CMake, the repository, nor Visual C++ 4.2 is in a path that contains spaces.
  - Be aware that long file paths (e.g., `C:\Users\LongUserName\LongerFolderName\isle`) may be truncated by `make`, resulting in “File not found” errors.
  - Replace `<path-to-source>` with the source repository. This can be `..` if your build folder is inside the source repository.
  - `RelWithDebInfo` is recommended because it will produce debug symbols useful for further decompilation work. However, you can change this to `Release` if you don't need them. While `Debug` builds can be compiled and used, they are not recommended as the primary goal is to match the code to the original binary. This is because the retail binaries were compiled as `Release` builds.
  - `NMake Makefiles` is most recommended because it will be immediately compatible with Visual C++ 4.2. For faster builds, you can use `Ninja` (if you have it installed), however due to limitations in Visual C++ 4.2, you can only build `Release` builds this way (debug symbols cannot be generated with `Ninja`).
1. Build the project by running `nmake` or `cmake --build <build-folder>`
1. When this is done, there should be recompiled `CONFIG.EXE`, `ISLE.EXE`, and `LEGO1.DLL` files in the build folder.
1. Note that `nmake` must be run twice under certain conditions, so it is advisable to always (re-)compile using `nmake && nmake`.

If you have a CMake-compatible IDE, it should be pretty straightforward to use this repository, as long as you can use `VCVARS32.BAT` and set the generator to `NMake Makefiles`.

### Docker

Alternatively, we support Docker as a method of compilation. This is ideal for users on Linux and macOS who do not wish to manually configure a Wine environment for compiling this project.

Compilation should be as simple as configuring and running the following command:

```console
docker run -d \
	-e CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=RelWithDebInfo" \
	-v <path-to-source>:/isle:rw \
	-v <build-folder>:/build:rw \
	ghcr.io/isledecomp/isle:latest
```

`<path-to-source>` should be replaced with the path to the source code directory (ie: the root of this repository).
`<build-folder>` should be replaced with the path to the build folder you'd like CMake to use during compilation.

You can pass as many CMake flags as you'd like in the `CMAKE_FLAGS` environment variable, but the default configuration provided in the command is already ideal for building highly-accurate binaries.

## Usage

The simplest way to use the recompiled binaries is to swap the original executables (`ISLE.EXE`, `LEGO1.DLL`, and `CONFIG.EXE`) in LEGO Island's installation directory for the ones that you've built from this source code. By default, LEGO Island is installed to `C:\Program Files\LEGO Island` on 32-bit operating systems and `C:\Program Files (x86)\LEGO Island` on 64-bit operating systems.

For advanced users, you can get LEGO Island to run from anywhere as long as `ISLE.EXE` and `LEGO1.DLL` are in the same directory and the `cdpath` and `diskpath` registry keys (usually found in `HKEY_LOCAL_MACHINE\Software\Mindscape\LEGO Island` on 32-bit operating systems and `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Mindscape\LEGO Island` on 64-bit operating systems) point to the correct location for the asset files (the directory that contains the `LEGO` folder).

If you see an error about `d3drm.dll`, you will need to acquire a copy and place it in the same directory as the game executables, as it has not shipped with Windows since Windows XP. We have published a [known good copy here](https://legoisland.org/download/d3drm.zip) that works with LEGO Island.

## Contributing

If you're interested in helping or contributing to this project, check out the [CONTRIBUTING](/CONTRIBUTING.md) page.

## Additional Information

### Which version of LEGO Island do I have?

Right click on `LEGO1.DLL`, select `Properties`, and switch to the `Details` tab. Under `Version` you should either see `1.0.0.0` (1.0) or `1.1.0.0` (1.1). Additionally, you can look at the game disc files; 1.0's files will all say August 8, 1997, and 1.1's files will all say September 8, 1997. Version 1.1 is by far the most common, especially if you're not using the English or Japanese versions, so that's most likely the version you have.

Please note that some localized versions of LEGO Island were recompiled with small changes despite maintaining a version number parallel with other versions; this decompilation specifically targets the English release of version 1.1 of LEGO Island. You can verify you have the correct version using the checksums below:

* ISLE.EXE `md5: f6da12249e03eed1c74810cd23beb9f5`
* LEGO1.DLL `md5: 4e2f6d969ea2ef8655ba3fc221a0c8fe`
* CONFIG.EXE `md5: 92d958a64a273662c591c88b09100f4a`
