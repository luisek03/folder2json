{
  description = "Lossless folder archiving into self-contained, AI-optimized JSON";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "folder-into-json";
          version = "1.2.0";

          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          buildInputs = with pkgs; [
            zstd
          ];

          # Aktiviert das Feature aus deiner Cargo.toml für den Nix-Build
          buildFeatures = [ "system-zstd" ];
          ZSTD_SYS_USE_PKG_CONFIG = "1";

          meta = with pkgs.lib; {
            description = "CLI tool to archive directories losslessly into AI-optimized JSON";
            homepage = "https://github.com/luisek03/folder-into-json";
            license = licenses.mit;
            mainProgram = "folder-into-json";
          };
        };

        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            cargo
            rustc
            pkg-config
          ];
          buildInputs = with pkgs; [
            zstd
          ];
          ZSTD_SYS_USE_PKG_CONFIG = "1";
        };
      }
    );
}
