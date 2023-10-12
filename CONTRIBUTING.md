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

## Code Style

In general, we're not exhaustively strict about coding style, but there are some preferable guidelines to follow that have been adopted from what we know about the original codebase:

- Indent: 2 spaces
- `PascalCase` for classes, function names, and enumerations.
- `m_camelCase` for member variables.
- `g_camelCase` for global variables.
- `p_camelCase` for function parameters.
- Instead of C++ primitives (e.g. `int`, `long`, etc.), use types in `mxtypes.h` instead. This will help us ensure that variables will be the correct size regardless of the underlying compiler/platform/architecture.

## Questions?

For any further questions, feel free to ask in either the [Matrix chatroom](https://matrix.to/#/#isledecomp:matrix.org) or on the [forum](https://forum.mattkc.com/viewforum.php?f=1).
