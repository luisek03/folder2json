{
  description = "folder2json - All-in-One Build & Release Tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Windows Cross-Toolchain via MinGW-w64
        pkgsWindows = import nixpkgs {
          inherit system;
          crossSystem.config = "x86_64-w64-mingw32";
        };

        # 1. Linux Binary
        linuxPkg = pkgs.rustPlatform.buildRustPackage {
          pname = "folder2json";
          version = "1.2.1";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          meta = with pkgs.lib; {
            description = "folder2json CLI (Linux)";
            mainProgram = "folder2json";
          };
        };

        # 2. Windows Binary (.exe)
        windowsPkg = pkgsWindows.rustPlatform.buildRustPackage {
          pname = "folder2json-windows";
          version = "1.2.1";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          # Stellt sicher, dass das Binary mit .exe-Endung im Store landet
          postInstall = ''
            if [ -f "$out/bin/folder2json" ] && [ ! -f "$out/bin/folder2json.exe" ]; then
              mv "$out/bin/folder2json" "$out/bin/folder2json.exe"
            fi
          '';

          meta = with pkgs.lib; {
            description = "folder2json CLI (Windows)";
            mainProgram = "folder2json.exe";
          };
        };

        # 3. Gemeinsames Release-Paket (beide OS in einem Output)
        releasePkg = pkgs.symlinkJoin {
          name = "folder2json-all-releases";
          paths = [ linuxPkg windowsPkg ];
        };

      in
      {
        packages = {
          default = linuxPkg;
          linux = linuxPkg;
          windows = windowsPkg;
          release = releasePkg;
        };

        apps = {
          # Kopiert die fertigen Binaries als ECHTE Dateien (keine Store-Symlinks, kein root)
          # in den Ordner ./dist-release/
          export-release = {
            type = "app";
            program = toString (pkgs.writeShellScript "export-release" ''
              set -e
              TARGET_DIR="./dist-release"
              echo "📦 Kopiere Binaries aus dem Nix-Store nach $TARGET_DIR ..."
              mkdir -p "$TARGET_DIR"

              cp -f "${linuxPkg}/bin/folder2json" "$TARGET_DIR/folder2json-linux-x86_64"
              chmod 755 "$TARGET_DIR/folder2json-linux-x86_64"

              cp -f "${windowsPkg}/bin/folder2json.exe" "$TARGET_DIR/folder2json-windows-x86_64.exe"
              chmod 755 "$TARGET_DIR/folder2json-windows-x86_64.exe"

              echo -e "\n✅ Fertig! Echte Binaries liegen bereit in $TARGET_DIR:"
              ls -lh "$TARGET_DIR"
            '');
          };
        };
      }
    );
}
