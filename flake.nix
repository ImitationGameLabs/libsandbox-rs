{
  description = "libsandbox — Linux-first sandbox runtime for interactive agent sessions";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    crane.url = "github:ipetkov/crane";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs =
    inputs@{ self, flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      # Linux-first: the crate `compile_error!`s off-Linux, so only Linux
      # systems are meaningful here.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      perSystem =
        { system, lib, ... }:
        let
          pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ (import inputs.rust-overlay) ];
          };

          root = ./.;

          common = import ./nix/common.nix {
            inherit
              pkgs
              lib
              inputs
              root
              ;
          };

          checks = import ./nix/checks.nix {
            inherit pkgs common;
            inherit (inputs) advisory-db;
          };

          inherit (common) craneLib;
        in
        {
          inherit checks;

          devShells.default = craneLib.devShell {
            inherit checks;

            # Extra inputs can be added here; cargo and rustc are provided by default.
            packages = with pkgs; [
              # Rust
              rust-analyzer

              # Nix
              nil
              nixfmt
              statix

              # TOML toolkit (linter, formatter)
              taplo
            ];
          };
        };
    };
}
