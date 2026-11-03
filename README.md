# folder2json

A high-performance CLI utility written in Rust to pack folder structures (file contents, POSIX file permissions, and symbolic links) into a single, self-contained JSON file (`pack`) and restore them bit-exact (`unpack`).

Designed for **LLM context injection**, Unix shell pipelines (Stdin/Stdout), and source code archiving with SHA-256 integrity checks and hardened extraction security.

---

## Project Structure

```text
folder2json/
├── Cargo.lock          # Locked Rust dependencies
├── Cargo.toml          # Package manifest & optional features (system-zstd)
├── flake.lock          # Pinned Nixpkgs flake inputs (nixos-26.05)
├── flake.nix           # Reproducible Flake package definition & devShell
└── src/
    ├── main.rs         # CLI entry point & result summary
    ├── cli.rs          # Clap command & argument definitions
    ├── constants.rs    # Constants, archive structs & AI metadata headers
    ├── glob.rs         # Iterative O(N*M) glob matcher (ReDoS-safe)
    ├── security.rs     # Path traversal, symlink graph & secret checks
    ├── stream.rs       # Streaming Base64/Zstd readers & writers
    ├── pack.rs         # Directory traversal & JSON streaming packer
    └── unpack.rs       # Multi-pass, atomic archive extractor
```

---

## Key Features & Design Scope

* **File-Level Archiving:** Preserves exact file byte contents, POSIX file modes (`mode & 0o777`), relative file paths, and symbolic links. *(Note: Empty directories, directory permissions, and file timestamps are intentionally omitted to keep JSON output minimal and deterministic).*
* **Smart Binary Compression Pipeline:** Binary files are compressed on the fly using **Zstandard (zstd level 3)** prior to Base64 encoding (`["zstd", "base64"]`), while pre-compressed formats (`.zip`, `.gz`, `.xz`, `.zst`, etc.) automatically skip re-compression.
* **Streaming Architecture:**
  * `pack` streams both plaintext (`1 MiB` chunks) and binary payloads (`48 KiB` Base64 triplets) in $O(1)$ RAM without loading full files into memory.
  * `unpack` parses the JSON document (bounded by `--max-archive-mib`, default `2048 MiB`) and streams decoded binary payloads in `64 KiB` chunks directly into temporary files on disk.
* **Hardened Unpack Security:**
  * **Path Traversal Protection:** Rejects `..`, leading `/`, `~`, backslashes, and null bytes.
  * **Chained Symlink-Graph Validation:** Simulates symlink resolution across both archive symlinks and pre-existing symlinks in the destination directory (with a 40-hop `ELOOP` cap) to block multi-stage symlink escapes.
  * **Per-File Decompression-Bomb Protection:** Enforces a configurable per-file output limit (`--max-size-mib`, default `512 MiB`) during streaming decompression.
  * **Atomic `0600` Temp Writes & Overwrite Protection:** Extracts files into locked-down temporary files (`0600`), verifies checksums prior to atomic rename, strips SUID/SGID/Sticky bits, and refuses to overwrite existing files unless `-f` / `--force` is passed.
* **Data Integrity Checksums:** Every file entry carries a 16-character truncated SHA-256 hash verified before moving the file into place. *(Note: This hash is an integrity checksum against accidental corruption or truncation, not a cryptographic signature against untrusted archive creators).*
* **Content Deduplication:** Identical files are stored once; duplicates are referenced via lightweight `type: "link"` entries.

---

## Installation & Building

### Via Nix Flakes (Recommended)

```bash
# Run directly without installing
nix run github:luisek03/folder2json -- --help

# Build the reproducible derivation (./result/bin/folder2json)
nix build

# Enter development shell
nix develop
```

### Standard Cargo Build

```bash
# Static zstd build
cargo build --release

# Dynamic build against system libzstd.so via pkg-config
cargo build --release --features system-zstd
```

---

## Usage Examples

### Packing

```bash
# Pack a project directory into an archive
folder2json pack ./my-project archive.json -v

# Pack including hidden files, excluding build artifacts
folder2json pack ./src output.json -a -e target -e "*.log"

# Pack to stdout and pipe directly into xz
folder2json pack ./my-project - | xz > archive.json.xz
```

### Unpacking

```bash
# Unpack JSON into a folder (verifies hashes, blocks overwrites by default)
folder2json unpack archive.json ./restored -v

# Unpack and overwrite existing files
folder2json unpack archive.json ./restored --force

# Unpack from a compressed stream via Stdin with custom per-file limit
xz -dc archive.json.xz | folder2json unpack - ./restored --max-size-mib 1024
```

---

## Security Notes for LLM Usage

When feeding JSON archives of untrusted third-party repositories into Large Language Models, keep in mind that plaintext source files inside `"content"` are untrusted data and may contain prompt-injection strings.
