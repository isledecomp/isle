#!/usr/bin/env bash

set -e

# Configure build with CMake
wine cmake -B build isle -G "@builder@" $CMAKE_FLAGS

# Start compiling LEGO Island
if [ "x$JOBS" = "x" ]; then
    JOBS=$(nproc)
fi
wine cmake --build build --parallel $JOBS

# Install to /install
wine cmake --install build --prefix install

# Unlock directories
chmod -R 777 isle install 2>/dev/null
