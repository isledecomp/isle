FROM scratch AS zipdeps

ARG CMAKE_VERSION=3.26.6
ARG NINJA_VERSION=1.12.1

ADD --checksum=sha256:7947618912e2c2f48f987631e29e318e56ccda551a7b65364c8a3f743e719ac5 \
    https://github.com/itsmattkc/MSVC420/archive/df2c13aad74c094988c6c7e784234c2e778a0e91.zip \
    msvc.zip
ADD --checksum=sha256:dc3f535d880d1ffa7cfa86a0eefdc1fc9bf8b9ede59d1deb7a2bb41f0a58d2d4 \
    https://github.com/Kitware/CMake/releases/download/v$CMAKE_VERSION/cmake-$CMAKE_VERSION-windows-i386.zip \
    cmake.zip
ADD --checksum=sha256:f550fec705b6d6ff58f2db3c374c2277a37691678d6aba463adcbb129108467a \
    https://github.com/ninja-build/ninja/releases/download/v$NINJA_VERSION/ninja-win.zip \
    ninja.zip

################################################################################

FROM debian:stable-slim

# Gather dependencies
RUN <<EOF
dpkg --add-architecture i386
apt-get update -y
apt-get install -y --no-install-recommends \
    libarchive-tools \
    wine \
    wine32 \
    wine64
EOF

# Silence debug warnings in wine (creates noise during compile)
ARG WINEDEBUG=-all
ARG WINEPREFIX=/root/.wine
RUN wine wineboot

# extract everything
RUN --mount=from=zipdeps,target=/zipdeps <<EOF
extract() {
    p="$WINEPREFIX/drive_c/$1"
    dep="/zipdeps/$1.zip"
    shift

    mkdir -p "$p" && bsdtar -oxvf "$dep" -C "$p" $@
}

extract cmake --strip-components 1
extract msvc --strip-components 1
extract ninja
EOF

# remove clutter
RUN <<EOF
apt-get remove --purge libarchive-tools
apt-get clean
rm -rf /var/lib/apt/lists/*
EOF

# Populate the Windows path inside of the wineprefix
RUN <<EOF
setenv() {
    wine reg ADD 'HKCU\Environment' /v "$1" /d "$2" /f
    # wine doesn't set it synchronously, server gets cut off by docker if you
    # don't give it enough time
    sleep 0.5
}
setenv PATH 'C:\msvc\bin;C:\msvc\bin\winnt;C:\cmake\bin;C:\windows\system32;C:\ninja'
setenv INCLUDE 'C:\msvc\include;C:\msvc\mfc\include'
setenv LIB 'C:\msvc\lib;C:\msvc\mfc\lib'
setenv TMP 'Z:\build'
setenv TEMP 'Z:\build'
EOF

# Set up entrypoint script to perform the build
COPY entrypoint.sh entrypoint.sh
RUN chmod +x entrypoint.sh
ENTRYPOINT [ "./entrypoint.sh" ]
