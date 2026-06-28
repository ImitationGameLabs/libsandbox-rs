{
  pkgs,
  common,
  advisory-db,
}:
let
  inherit (common)
    craneLib
    src
    commonArgs
    cargoArtifacts
    ;

  project = "libsandbox";
in
{
  # Run clippy (and deny all warnings) on the workspace source
  "${project}-clippy" = craneLib.cargoClippy (
    commonArgs
    // {
      inherit cargoArtifacts;
      cargoClippyExtraArgs = "--all-targets -- --deny warnings";
    }
  );

  # Build docs
  "${project}-doc" = craneLib.cargoDoc (
    commonArgs
    // {
      inherit cargoArtifacts;
      env.RUSTDOCFLAGS = "--deny warnings";
    }
  );

  # Check formatting
  "${project}-fmt" = craneLib.cargoFmt {
    inherit src;
  };

  # TOML formatting
  "${project}-toml-fmt" = craneLib.taploFmt {
    src = pkgs.lib.sources.sourceFilesBySuffices src [ ".toml" ];
  };

  # Audit dependencies for security issues
  "${project}-audit" = craneLib.cargoAudit {
    inherit src advisory-db;
  };

  # Audit licenses (and bans/sources) via deny.toml
  "${project}-deny" = craneLib.cargoDeny {
    inherit src;
  };

  # TODO: Re-enable once tests are split into a unit/integration boundary that
  # doesn't require privileges. The sandboxing primitives exercised here
  # (namespaces, mount, seccomp) need capabilities that the Nix build sandbox
  # does not grant, so cargoNextest is not viable as-is.
  #
  # "${project}-nextest" = craneLib.cargoNextest (
  #   commonArgs
  #   // {
  #     inherit cargoArtifacts;
  #     partitions = 1;
  #     partitionType = "count";
  #     cargoNextestPartitionsExtraArgs = "--no-tests=pass";
  #   }
  # );
}
