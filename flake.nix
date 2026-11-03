{
  description = "folder2json - All-in-One Build Tool (Static)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        # 1. Native Linux Toolchain
        pkgs = import nixpkgs { inherit system; };

        # 2. Windows Cross-Compilation Toolchain (MinGW-w64)
        pkgsWindows = import nixpkgs {
          inherit system;
          crossSystem.config = "x86_64-w64-mingw32";
        };

        # 3. Paket-Definition für Linux (Statisch)
        linuxPkg = pkgs.rustPlatform.buildRustPackage {
          pname = "folder2json";
          version = "1.2.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          meta = with pkgs.lib; {
            description = "Lossless folder archiving CLI";
            mainProgram = "folder2json";
          };
        };

        # 4. Paket-Definition für Windows (Cross-Compiled Statisch)
        windowsPkg = pkgsWindows.rustPlatform.buildRustPackage {
          pname = "folder2json-windows";
          version = "1.2.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          meta = with pkgs.lib; {
            description = "Lossless folder archiving CLI (Windows)";
            mainProgram = "folder2json.exe";
          };
        };

      in
      {
        # ==========================================
        # BUILD-ZIELE (Nix Sandbox)
        # ==========================================
        packages = {
          default = linuxPkg;
          linux = linuxPkg;
          windows = windowsPkg;
        };

        # ==========================================
        # APPS (Lokale Ausführung für schnelles Caching)
        # ==========================================
        apps = {
          # nix run .#build-fast
          build-fast = {
            type = "app";
            program = toString (pkgs.writeShellScript "build-fast" ''
              echo "Baue lokal mit Cargo (inkl. target/ Caching, rein statisch) ..."
              cargo build --release

              echo -e "\n✅ Fertig! Schnelles, lokal gecachtes Binary liegt in:"
              echo "   ./target/release/folder2json"
            '');
          };
        };

        # ==========================================
        # ENTWICKLUNGSUMGEBUNG (nix develop)
        # ==========================================
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            cargo
            rustc
          ];
        };
      }
    );
}
