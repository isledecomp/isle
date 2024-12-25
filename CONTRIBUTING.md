# Contributing

## Important Note

We are thrilled about the interest in reverse engineering LEGO Island and welcome contributions from anyone eager to advance the project. However, proposed changes must meet a certain standard of engineering quality. While our established contributors are happy to provide code reviews and constructive feedback, they cannot teach contributors C++ or decompilation fundamentals. 

This project depends on contributors' free time, a resource often in short supply. Poorly constructed contributions, though well-intentioned, can hinder progress in the long term. If you're not confident in your decompilation abilities, we recommend returning once you have a stronger grasp of the process.

Decompilation is an advanced skill. Depending on your proficiency in C/C++ and x86 assembly, it might take months or even years to develop the necessary skills. For beginners, [Part 1 of the decompilation vlog](https://youtu.be/MToTEqoVv3I) provides an excellent introduction. Please familiarize yourself with this process before contributing code.

## Ghidra Server

We use [Ghidra](https://ghidra-sre.org/) (free and open source) to document the original binaries and generate pseudocode for decompilation. Collaboration is facilitated through a shared Ghidra repository. You are welcome to explore it locally, but push access requires permission to prevent sabotage. Contact us in the Matrix room to request access.

Repository details:
- **Address:** `server.mattkc.com`
- **Port:** `13100`

> **Note:** Much of the information on the Ghidra server is outdated. The source code in this repository is the most accurate "source of truth" and should be referenced whenever possible.

## General Guidelines

If you're ready to contribute, feel free to create a pull request (PR). We will review and merge it—or provide feedback—as soon as possible.

### Pull Request Tips:
- Keep PRs small and understandable to facilitate collaboration and reduce errors.
- Large PRs (modifying more than ~10 files) increase the likelihood of merge conflicts and errors.
- Aim to focus on one class per PR. Interlinked classes may require exceptions but proceed cautiously.

### Project Goals:
This repository's sole objective is **accuracy to the original executables**. 
- We prioritize byte/instruction matching the original compiler (MSVC 4.20).
- Modernizations or bug fixes will likely be rejected for now.

## Overview

- **[`3rdparty`](/3rdparty):** Libraries from third parties (excluding Mindscape). These are public domain or freely available files. Our style guide does not apply here.
- **[`CONFIG`](/CONFIG):** Decompilation of `CONFIG.EXE`, dependent on `LEGO1` code.
- **[`ISLE`](/ISLE):** Decompilation of `ISLE.EXE`, dependent on `LEGO1` code.
- **[`LEGO1`](/LEGO1):** Decompilation of `LEGO1.DLL`, containing:
  - **Omni:** Mindscape's custom in-house engine (`mx*` files).
  - **LEGO-specific code:** Extensions and game-specific libraries (`lego*` files).
  - **Utility libraries** developed by Mindscape.
- **[`tools`](/tools):** Aiding tools for decompilation.
- **[`util`](/util):** Utility headers supporting the effort.

## Tooling

Refer to the [tooling and annotations guide](/tools/README.md). Familiarity with these tools is essential for contributing.

## Notes on MSVC 4.20

As outlined in the [`README`](/README.md), we use Microsoft Visual C++ 4.20 to compile the game.

### Compiler Randomness
- The compiler's code generation can behave erratically, introducing "compiler randomness" or entropy.
- Changes in headers, even unrelated ones (e.g., adding an unused inline function), may alter unrelated function outputs.
- This issue affects ~5% of decompiled functions, complicating efforts to achieve 100% matching binaries.

If you have insights into this phenomenon, please contact us.

## Code Style

### Formatting
We use:
- [clang-format](https://clang.llvm.org/docs/ClangFormat.html) and [clang-tidy](https://clang.llvm.org/extra/clang-tidy/) with configuration files replicating the original formatting.
- Required `clang` version: `18.x`.

### Naming Conventions
We use a customized version of [ncc](https://github.com/nithinn/ncc) to replicate original naming conventions. 
- Required `clang` version: `16.x`.
- Refer to the [ncc tool guide](/tools/ncc) and [GitHub action](/.github/workflows/naming.yml) for details.

## Questions?

For further questions, reach out via:
- [Matrix chatroom](https://matrix.to/#/#isledecomp:matrix.org)
- [Forum](https://forum.mattkc.com/viewforum.php?f=1)
