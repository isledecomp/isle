#!/usr/bin/env bash

set -euxo pipefail

# two `cd`'s so Git can find the root dir even if this script is called from
# outside the repo
cd $(dirname "${BASH_SOURCE[0]}")
cd $(git rev-parse --show-toplevel)

declare OCI_CMD

if [ "x${OCI_CMD:-}" = "x" ]; then
    if whereis docker >/dev/null; then
        OCI_CMD=docker
    elif whereis podman >/dev/null; then
        OCI_CMD=podman
    else
        echo "No container engine (docker/podman) found!"
        exit 2
    fi
fi

# on docker, --tmpfs doesn't work correctly with the old MSVC
if [ "$OCI_CMD" = "docker" ]; then
    BUILDDIR="$(mktemp -d /tmp/isle-build.XXXXXX)"
fi

# nix-store is way quicker at copying these files and only needs to do it once
# if the source doesn't change
if whereis nix-store >/dev/null; then
    SRCDIR="$(nix-store --add $PWD)"
else
    SRCDIR="$(mktemp -d /tmp/isle-src.XXXXXX)"
    git ls-files -z | xargs -0I{} install -D {} "$SRCDIR/{}"
fi

cleanup () {
    if ! [ "x${BUILDDIR:-}" = "x" ]; then
        rm -rf "$BUILDDIR" 2>/dev/null
    fi
    rm -rf "$SRCDIR" 2>/dev/null
}

trap cleanup EXIT

"$OCI_CMD" build -t isle "$SRCDIR/docker"

mkdir -p result
rm -rf result/*

if [ "x${JOBS:-}" = "x" ]; then
    JOBS=$(nproc)
fi

if ! [ "x${BUILDDIR:-}" = "x" ]; then
    MOUNT_BUILDDIR=(-v "$BUILDDIR":/build)
else
    MOUNT_BUILDDIR=(--tmpfs /build)
fi

"$OCI_CMD" run -it \
    -e CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=RelWithDebInfo" \
    ${MOUNT_BUILDDIR[@]} \
    -v "$SRCDIR":/isle \
    -v ./result:/install \
    -e JOBS="$JOBS" \
    isle

