{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  name = "folder-into-json-rust";

  packages = with pkgs; [
    rustc
    cargo
    jq
  ];

  shellHook = ''
    echo "folder-into-json Rust dev shell"
    echo "  rustc $(rustc --version)"
    echo "  cargo $(cargo --version)"
    echo "  jq    $(jq --version)"
    echo ""
    echo "Kompilieren:"
    echo "  cargo build --release"
    echo ""
    echo "Fertige Binärdatei liegt danach unter:"
    echo "  ./target/release/folder-into-json"
  '';
}
