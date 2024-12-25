# LEGO Island Decompilation

[Development Vlog](https://www.youtube.com/playlist?list=PLbpl-gZkNl2COf_bB6cfgTapD5WduAfPz) | [Contributing](/CONTRIBUTING.md) | [Matrix](https://matrix.to/#/#isledecomp:matrix.org) | [Forums](https://forum.mattkc.com/viewforum.php?f=1) | [Patreon](https://www.patreon.com/mattkc)

This is a functionally complete decompilation of **LEGO Island** (Version 1.1, English). The aim is to match the recompiled instructions closely to the original machine code. The goal is to provide a workable codebase that can be modified, improved, and ported to other platforms in the future.

## Status

<img src="https://legoisland.org/progress/ISLEPROGRESS.SVG" width="50%"><img src="https://legoisland.org/progress/LEGO1PROGRESS.SVG" width="50%">

Both `ISLE.EXE` and `LEGO1.DLL` are fully decompiled and are functionally identical to the original executables, as far as we know. However, there is ongoing work to improve the accuracy, naming, documentation, and structure of the source code. The game should be fully playable with the binaries derived from this source code, though some unresolved bugs may still exist.

Due to complications with the compiler, the binaries are not a byte-for-byte match of the original executables, but we are hopeful that this will be resolved in the future.

## Building

This project uses the [CMake](https://cmake.org/) build system, allowing compatibility with various compilers and development environments. For the most accurate results, **Microsoft Visual C++ 4.20** (the compiler used to build the original game) is recommended. All contributions will be evaluated based on the output from this compiler to maintain accuracy.

These instructions describe how to compile the repository using Visual C++ 4.2 to generate highly-accurate binaries that match the original retail functions. While other compilers may be used, doing so is at your own risk, and is not covered in this guide.

### Prerequisites

You will need the following software installed:

- **Microsoft Visual C++ 4.2**: Available from many abandonware sites. A [portable version](https://github.com/itsmattkc/msvc420) is also available for easier setup.
- **[CMake](https://cmake.org/)**: CMake is typically bundled with the "Desktop development with C++" workload in newer versions of Visual Studio but can also be installed separately.

### Compiling

1. Open a **Command Prompt** (`cmd`).
2. From Visual C++ 4.2, run `BIN/VCVARS32.BAT x86` to set up the environment variables needed for compiling with MSVC.
3. Create a folder for the compiled objects, e.g., a `build` folder inside the source repository (the folder you cloned/downloaded).
4. In the Command Prompt, `cd` into the build folder.
5. Configure the project with CMake by running:

   ```bash
   cmake <path-to-source> -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo
   ```

   - **Note**: Visual C++ 4.2 has issues with paths containing spaces. If you experience configure or build errors, ensure that CMake, the repository, and Visual C++ 4.2 are not located in a directory with spaces.
   - Replace `<path-to-source>` with the path to your source repository (you can use `..` if the build folder is inside the source repository).
   - `RelWithDebInfo` is recommended as it includes debug symbols useful for further decompilation. You can switch to `Release` if you do not need debug symbols. Avoid using `Debug` builds as they may not be compatible with the retail `LEGO1.DLL`.
   - `NMake Makefiles` is preferred for compatibility with Visual C++ 4.2. You can use `Ninja` for faster builds, but it limits you to only `Release` builds and will not generate debug symbols.

6. Build the project by running either `nmake` or `cmake --build <build-folder>`.
7. After the build process completes, `ISLE.EXE` and `LEGO1.DLL` will be available in the build folder.
8. **Important**: Run `nmake && nmake` twice under certain conditions to ensure proper recompilation.

If you have a CMake-compatible IDE, using it should be straightforward as long as you can execute `VCVARS32.BAT` and set the generator to `NMake Makefiles`.

## Usage

To use the compiled executables:

1. Place the compiled `ISLE.EXE` and `LEGO1.DLL` into LEGO Island's installation folder (typically found at `C:\Program Files\LEGO Island` or `C:\Program Files (x86)\LEGO Island`).
2. Alternatively, LEGO Island can run from any directory, provided both `ISLE.EXE` and `LEGO1.DLL` are in the same directory, and the registry keys (usually located at `HKEY_LOCAL_MACHINE\Software\Mindscape\LEGO Island` or `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Mindscape\LEGO Island`) point to the correct asset file location.

## Contributing

If you're interested in contributing to this project, please refer to the [CONTRIBUTING](/CONTRIBUTING.md) page.

## Additional Information

### Which version of LEGO Island do I have?

To check your version of LEGO Island:

1. Right-click on `LEGO1.DLL`, select **Properties**, and go to the **Details** tab. You should see either:
   - `1.0.0.0` (for version 1.0), or
   - `1.1.0.0` (for version 1.1).
   
2. You can also check the game disc files:
   - Version 1.0 files will be dated **August 8, 1997**.
   - Version 1.1 files will be dated **September 8, 1997**.

Version 1.1 is the most common, especially if you're not using the English or Japanese versions.

Please note, some localized versions of LEGO Island were recompiled with small changes, even though they share the same version number. This decompilation targets the **English release of version 1.1** of LEGO Island. 

You can verify that you have the correct version by checking the following checksums:

- **ISLE.EXE**: `md5: f6da12249e03eed1c74810cd23beb9f5`
- **LEGO1.DLL**: `md5: 4e2f6d969ea2ef8655ba3fc221a0c8fe`
- **CONFIG.EXE**: `md5: 92d958a64a273662c591c88b09100f4a`
