# Contributing

## Learning Decompilation

Generally, decompilation is a fairly advanced skill. If you aren't already familiar with it, it will likely take you months, or even years, to learn the skills necessary to do it (depending on your current proficiency with C/C++ and x86 assembly). If you're still interested, [part 1 of the decompilation vlog](https://www.youtube.com/watch?v=MToTEqoVv3I) covers the overall process and should give you a starting point that you can dive in from.

## Ghidra Server

For documenting the original binaries and generating pseudocode that we decompile with, we primarily use [Ghidra](https://ghidra-sre.org/) (it's free and open source). To help with collaboration, we have a shared Ghidra repository with all of our current work. You are free to check it out and mess around with it locally, however to prevent sabotage, you will need to request permission before you can push your changes back to the server (ask in the Matrix room).

To access the Ghidra repository, use the following details:

- Address: `server.mattkc.com`
- Port: `13100`

## General Guidelines

If you have contributions, feel free to create a pull request! Someone will review and merge it (or provide feedback) as soon as possible.

Please keep your pull requests small and understandable; you may be able to shoot ahead and make a lot of progress in a short amount of time, but this is a collaborative project, so you must allow others to catch up and follow along. Large pull requests become significantly more unwieldy to review, and as such make it exponentially more likely for a mistake or error to go undetected. They also make it harder to merge other pull requests because the more files you modify, the more likely it is for a merge conflict to occur. A general guideline is to keep submissions limited to one class at a time. Sometimes two or more classes may be too interlinked for this to be feasible, so this is not a hard rule, however if your PR is starting to modify more than 10 or so files, it's probably getting too big.

This repository currently has only one goal: accuracy to the original executables. We are byte/instruction matching as much as possible, which means the priority is making the original compiler (MSVC 4.20) produce code that matches the original game. As such, modernizations and bug fixes will probably be rejected for the time being.

## Overview

* [`3rdparty`](/3rdparty): Contains code obtained from third parties, not including Mindscape. Generally, these are libraries that have been placed in the public domain or are freely available on the web. As these are unaltered files, our style guide (see below) does not apply.
* [`ISLE`](/ISLE): Decompilation of `ISLE.EXE`. It depends on some code in `LEGO1`.
* [`LEGO1`](/LEGO1): Decompilation of `LEGO1.DLL`. This folder contains code from Mindscape's custom in-house engine called **Omni** (file pattern: `mx*`), the LEGO Island-specific extensions for Omni and the game's code (file pattern: `lego*`) as well as several utility libraries developed by Mindscape.
* [`tools`](/tools): A set of tools aiding in the decompilation effort.
* [`util`](/util): Utility headers aiding in the decompilation effort.

## Tooling

Please make yourself familiar with the [available tooling and annotations](/tools/README.md).

## Code Style

In general, we're not exhaustively strict about coding style, but there are some preferable guidelines to follow that have been adopted from what we know about the original codebase:

### Formatting

We are currently using [clang-format](https://clang.llvm.org/docs/ClangFormat.html) with a configuration file that aims to replicate the code formatting employed by the original developers. There are [integrations](https://clang.llvm.org/docs/ClangFormat.html#vim-integration) available for most editors and IDEs. The required `clang-format` version is `17.x`.

### Naming conventions

We are currently using a customized version of [ncc](https://github.com/nithinn/ncc) with a configuration file that aims to replicate the naming conventions employed by the original developers. `ncc` requires Clang 16; please refer to the [tool](/tools/ncc) and the (GitHub action)[/.github/workflows/naming.yml] for guidance.

## Questions?

For any further questions, feel free to ask in either the [Matrix chatroom](https://matrix.to/#/#isledecomp:matrix.org) or on the [forum](https://forum.mattkc.com/viewforum.php?f=1).
