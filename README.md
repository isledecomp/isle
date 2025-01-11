# LEGO Island: The Modder's Arrival

## [Original LEGO Island decomp](https://github.com/isledecomp/isle)

## Building

This project uses the [CMake](https://cmake.org/) build system, which allows for a high degree of versatility regarding compilers and development environments. For the most accurate results, Microsoft Visual C++ 4.20 (the same compiler used to build the original game) is recommended. Since we're trying to match the output of this code to the original executables as closely as possible, all contributions will be graded with the output of this compiler.


These instructions will outline how to compile this repository using Visual C++ 4.2 into highly-accurate binaries where the majority of functions are instruction-matching with retail. If you wish, you can try using other compilers, but this is at your own risk and won't be covered in this guide.

#### Prerequisites

You will need the following software installed:

- Microsoft Visual C++ 4.2. This can be found on many abandonware sites, but the installer can be a little iffy on modern versions of Windows. For convenience, a [portable version](https://github.com/itsmattkc/msvc420) is available that can be downloaded and used quickly instead.
- [CMake](https://cmake.org/). A copy is often included with the "Desktop development with C++" workload in newer versions of Visual Studio; however, it can also be installed as a standalone app.

#### Compiling

1. Open a Command Prompt (`cmd`).
1. From Visual C++ 4.2, run `BIN/VCVARS32.BAT x86` to populate the path and other environment variables for compiling with MSVC.
1. Run "reconfigureCMake.bat" to configure CMake for building

  - **Visual C++ 4.2 has issues with paths containing spaces**. If you get configure or build errors, make sure neither CMake, the repository, nor Visual C++ 4.2 is in a path that contains spaces.
  - Replace `<path-to-source>` with the source repository. This can be `..` if your build folder is inside the source repository.
  - `RelWithDebInfo` is recommended because it will produce debug symbols useful for further decompilation work. However, you can change this to `Release` if you don't need them. While `Debug` builds can be compiled and used, they are not recommended as the primary goal is to match the code to the original binary. This is because the retail binaries were compiled as `Release` builds.
  - `NMake Makefiles` is most recommended because it will be immediately compatible with Visual C++ 4.2. For faster builds, you can use `Ninja` (if you have it installed), however due to limitations in Visual C++ 4.2, you can only build `Release` builds this way (debug symbols cannot be generated with `Ninja`).
1. Build the project by running `nmake` or `cmake --build <build-folder>` or by running "compile.bat"
1. When this is done, there should be a compiled `TMA_LAUNCHER.EXE` and `B_TMA.DLL` in the build folder.
1. Note that `nmake` must be run twice under certain conditions, so it is advisable to always (re-)compile using `nmake && nmake`.

If you have a CMake-compatible IDE, it should be pretty straightforward to use this repository, as long as you can use `VCVARS32.BAT` and set the generator to `NMake Makefiles`.

### Docker

Alternatively, we support Docker as a method of compilation. This is ideal for users on Linux and macOS who do not wish to manually configure a Wine environment for compiling this project.

Compilation should be as simple as configuring and running the following command:

```
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

In order to run TMA, you must first configure the `diskpath` environment variable (`usage of cdpath has been disabled entirely`). This is necessary since, currently, nothing creates this environment variable, or populates it.

The registry keys can be created in (usually found in `HKEY_LOCAL_MACHINE\Software\ActionSoft\LEGO Island TMA` on 32-bit operating systems and `HKEY_LOCAL_MACHINE\Software\Wow6432Node\ActionSoft\LEGO Island TMA` on 64-bit operating systems), and should point to the location where the `TMA_LAUNCHER.EXE`, `B_TMA.DLL`, and LEGO files/folders are stored (by default, this is the build folder). As long as you

The build folder contains a copy of `d3drm.dll`, `D3D8.dll`, `D3DImm.dll`, `DDraw.dll`, and `dgVoodoo.conf` files, DO NOT REMOVE ANY OF THEM.

NOTE: Due to Github size limitations, and the fact this is a repo just for me to keep mirrored across devices, this repo does not include anything within the Lego folder. For the time being, access to the Lego folder cannot be requested, but may be able to in the future.

### What does what?

`TMA_LAUNCHER.EXE` - The wrapper for `B_TMA.DLL`, launches the game - the equivalant to `ISLE.EXE`

`B_TMA.DLL` - The primary dll, containing all game logic - the equivalant to `LEGO1.DLL`

`CONFIGURE.EXE` - Primary configuration application, contains some options - the equivalant to `CONFIG.EXE`
                For more advanced configurations, you will need to acquire `dgVoodooSetup.exe`, and place it in the same folder as `dgVoodoo.conf`