{
  sources ? import ./npins,
  nixpkgs ? sources.nixpkgs,
  system ? builtins.currentSystem,
  pkgs ? import nixpkgs { inherit system; },
}: pkgs.callPackage ./docker.nix {}
