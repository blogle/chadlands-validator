{
  description = "chadlands-validator";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, crane, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ rust-overlay.overlays.default ];
        pkgs = import nixpkgs { inherit system overlays; };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        src = ./.;

        # Common arguments for crane builds
        commonArgs = {
          inherit src;
          strictDeps = true;
          buildInputs = with pkgs; [
            # System libraries needed by notify crate (inotify on Linux)
          ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.libiconv
            pkgs.darwin.apple_sdk.frameworks.CoreServices
          ];
          nativeBuildInputs = with pkgs; [
            pkg-config
          ];
        };

        # Build only dependencies (for caching)
        cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
          pname = "chadlands-validator-deps";
        });

        # Build the validator
        chadlands-validator = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          pname = "chadlands-validator";
          version = "0.1.0";
        });

        # Run clippy
        clippy = craneLib.cargoClippy (commonArgs // {
          inherit cargoArtifacts;
          cargoClippyExtraArgs = "--all-targets -- --deny warnings";
        });

        # Run tests
        tests = craneLib.cargoTest (commonArgs // {
          inherit cargoArtifacts;
        });
      in
      {
        packages = {
          default = chadlands-validator;
          chadlands-validator = chadlands-validator;
        };

        checks = {
          inherit chadlands-validator clippy tests;
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ chadlands-validator ];
          buildInputs = [
            rustToolchain
            pkgs.cargo-watch
            pkgs.cargo-nextest
          ];

          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";

          shellHook = ''
            echo "chadlands-validator dev shell"
            echo "  rustc: $(rustc --version)"
            echo "  cargo: $(cargo --version)"
            echo ""
            echo "Commands:"
            echo "  cargo build          — compile"
            echo "  cargo test           — run unit + integration tests"
            echo "  cargo nextest run    — faster test runner"
            echo "  cargo watch -x test  — recompile + test on change"
            echo "  nix build            — reproducible build via crane"
            echo "  nix flake check      — run clippy + tests"
          '';
        };
      }
    );
}
