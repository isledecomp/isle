# Contributing

## Learning Decompilation

Generally, decompilation is a fairly advanced skill. If you aren't already familiar with it, it will likely take you months, or even years, to learn the skills necessary to do it (depending on your current proficiency with C/C++ and x86 assembly). If you're still interested, [part 1 of the decompilation vlog](https://www.youtube.com/watch?v=MToTEqoVv3I) covers the overall process and should give you a starting point that you can dive in from.

## Ghidra Server

For documenting the original binaries and generating pseudocode that we decompile with, we primarily use [Ghidra](https://ghidra-sre.org/) (it's free and open source). To help with collaboration, we have a shared Ghidra repository with all of our current work. You are free to check it out and mess around with it locally, however to prevent sabotage, you will need to request permission before you can push back to the server (ask in the Matrix room).

To access the Ghidra repository, use the following details:

- Address: `server.mattkc.com`
- Port: `13100`

## Code Style

In general, we're not exhaustively strict about coding style, but there are some preferable guidelines to follow that have been adopted from what we know about the original codebase:

- Indent: 2 spaces
- `PascalCase` for classes and function names.
- `m_camelCase` for member variables.
- `g_camelCase` for global variables.
- `p_camelCase` for function parameters.

## Kinds of Contributions

This repository has only one goal: accuracy to the original executables. As such, we are not likely to accept pull requests that attempt to modernize the code, or improve compatibility in a newer compiler that ends up reducing compatibility in MSVC 4.20. Essentially, accuracy is king, everything else is secondary. For modernizations and enhancements, it's recommended to create a fork downstream from this one instead.

## Questions?

For any further questions, feel free to ask in either the [Matrix chatroom](https://matrix.to/#/#isledecomp:matrix.org) or on the [forum](https://forum.mattkc.com/viewforum.php?f=1).
