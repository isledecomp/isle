{
  fetchzip,
  fetchFromGitHub,
  dockerTools,
  runCommand,
  winePackages,
  wineWowPackages,
  bashInteractive,
  lib,

  withNinja ? false,
}:
let
  cmake-windows = fetchzip rec {
    pname = "cmake-windows";
    version = "3.26.6";
    url = "https://github.com/Kitware/CMake/releases/download/v${version}/cmake-${version}-windows-i386.zip";
    hash = "sha256-nRARroW7KOKkf2orpk0RuB6Bdm7lJandKnW8el15mhE=";
  };
  msvc420 = fetchFromGitHub {
    owner = "itsmattkc";
    repo = "MSVC420";
    rev = "df2c13aad74c094988c6c7e784234c2e778a0e91";
    hash = "sha256-y9j9yRryXuTVCQrhokqMzfo4DGVGG9dE3I+Sqb/tGhY=";
  };
  ninja-win = fetchzip rec {
    pname = "ninja-win";
    version = "1.12.1";
    url = "https://github.com/ninja-build/ninja/releases/download/v${version}/ninja-win.zip";
    hash = "sha256-8iRfRUPWesU9/itcr5xAON4Ed3AUcXGP5pz350tE3r4=";
    stripRoot = false;
    postFetch = ''
      mkdir -p $out/bin
      mv $out/ninja.exe $out/bin
    '';
  };

  wine = if withNinja then wineWowPackages.minimal else winePackages.minimal;
  simpleWinePrefix =
    runCommand "simple-wine-prefix"
      {
        nativeBuildInputs = [ wine ];
      }
      ''
        export WINEPREFIX=$out/root/.wine
        mkdir -p $WINEPREFIX
        wineboot

        setenv() {
          wine reg ADD 'HKCU\Environment' /v "$1" /d "$2" /f
          # wine doesn't set it synchronously, server gets cut off by docker if you
          # don't give it enough time
          sleep 0.5
        }
        setenv PATH 'C:\bin;C:\windows\system32'
        setenv INCLUDE 'C:\include;C:\msvc\mfc\include'
        setenv LIB 'C:\msvc\lib;C:\msvc\mfc\lib'
        setenv TMP 'Z:\build'
        setenv TEMP 'Z:\build'

        ln -s /bin $WINEPREFIX/drive_c/bin
        ln -s /include $WINEPREFIX/drive_c/include
        ln -s ${msvc420} $WINEPREFIX/drive_c/msvc
      '';

  entrypoint = runCommand "isle-entrypoint" { } ''
    mkdir -p $out
    builder="${if withNinja then "Ninja" else "NMake Makefiles"}"
    substituteAll ${../docker/entrypoint.sh} $out/entrypoint.sh
  '';
in
dockerTools.streamLayeredImage {
  name = "isle-builder";
  contents = [
    bashInteractive
    entrypoint

    cmake-windows
    msvc420
    simpleWinePrefix
    wine
  ] ++ lib.optional withNinja ninja-win;

  tag = "isle";

  config.ENTRYPOINT = [ "./entrypoint.sh" ];
}
