#!/usr/bin/env bash

set -euxo pipefail

# two `cd`'s so Git can find the root dir even if this script is called from
# outside the repo
cd $(dirname "${BASH_SOURCE[0]}")
cd $(git rev-parse --show-toplevel)

# nix-store is way quicker at copying these files and only needs to do it once
# if the source doesn't change
if whereis nix-store >/dev/null; then
    SRCDIR="$(nix-store --add $PWD)"
else
    SRCDIR="$(mktemp -d /tmp/isle-src.XXXXXX)"
    git ls-files -z | xargs -0I{} install -D {} "$SRCDIR/{}"
fi

cleanup () {
    rm -rf "$SRCDIR" 2>/dev/null
}

trap cleanup EXIT

declare oci_cmd

if whereis podman >/dev/null; then
    oci_cmd=podman
elif whereis docker >/dev/null; then
    oci_cmd=docker
else
    echo "No container engine (docker/podman) found!"
    exit 2
fi

"$oci_cmd" build -t isle "$SRCDIR/docker"

mkdir -p result
rm -rf result/*

if [[ "x${JOBS:-}" == "x" ]]; then
    JOBS=$(nproc)
fi

"$oci_cmd" run -it \
    -e CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=RelWithDebInfo" \
    -v "$SRCDIR":/isle:rw \
    -e JOBS="$JOBS" \
    --tmpfs /build \
    -v ./result:/install \
    isle

