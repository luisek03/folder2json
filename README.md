# folder2json

A high-performance CLI utility written in Rust to pack entire folder structures (including contents, Unix permissions, and symlinks) into a single, self-contained JSON file (`pack`) and restore them bit-exact (`unpack`).

Optimized specifically for **LLM context injection**, shell pipelines (Stdin/Stdout), and bit-exact source code archiving with cryptographic SHA-256 integrity verification.

---

## Project Structure

```text
folder2json/
├── Cargo.lock      # Locked Rust dependencies
├── Cargo.toml      # Package manifest & optional features (system-zstd)
├── flake.lock      # Pinned Nixpkgs flake inputs (nixos-26.05)
├── flake.nix       # Reproducible Flake package definition & devShell
└── src/
    └── main.rs     # Core CLI implementation, streaming, compression & hashing
```

---

## Key Features

* **Lossless Archiving:** Preserves POSIX file modes (`chmod`), directory trees, and symbolic links.
* **Smart Binary Compression Pipeline:** Binary files are compressed using high-speed **Zstandard (zstd level 3)** prior to Base64 encoding (`["zstd", "base64"]`), eliminating repeated sequences and cutting down token overhead.
* **Pre-Compressed File Detection:** Archive formats that are already compressed (`.zip`, `.gz`, `.xz`, `.zst`, etc.) automatically skip re-compression, while compressible structures like `.tar`, databases (`.db`), and raw binaries are compressed.
* **AI & LLM Optimized:** Includes standard metadata headers (`ai_instructions`, `schema_description`, `python_reference`) guiding language models to parse plaintext directly while skipping binary bloat without runtime tools.
* **Cryptographic Integrity:** Every entry carries a truncated 16-character SHA-256 hash verified automatically upon unpack.
* **Content Deduplication:** Identical files are stored only once; duplicates are mapped as lightweight links (`type: "link"`).
* **Memory-Efficient Streaming:** Streams text and binary payloads in chunks (1 MiB to 3 MiB) to maintain minimal RAM usage even on large files.
* **Stdin / Stdout Support (`-`):** Integrates directly into Unix pipes (e.g. `xz`, `gzip`, `zstd`).

---

## Installation & Building

### Via Nix Flakes (Recommended)

Run directly without installing:

```bash
nix run github:luisek03/folder2json -- --help
```

Build the reproducible derivation:

```bash
nix build
# Binary is available at ./result/bin/folder2json
```

Enter development shell:

```bash
nix develop
```

Install into your user profile:

```bash
nix profile install .#default
```

### In NixOS Configuration (`flake.nix`)

Add `folder2json` as an input:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    folder2json.url = "github:luisek03/folder2json";
  };

  outputs = { self, nixpkgs, folder2json, ... }@inputs: {
    nixosConfigurations.<hostname> = nixpkgs.lib.nixosSystem {
      modules = [
        ({ pkgs, ... }: {
          environment.systemPackages = [
            folder2json.packages.${pkgs.system}.default
          ];
        })
      ];
    };
  };
}
```

### Standard Cargo Build

```bash
cargo build --release
# Binary is available at ./target/release/folder2json
```

To build dynamically against the system's `libzstd.so` using `pkg-config`:

```bash
cargo build --release --features system-zstd
```

---

## Usage Examples

### Packing

```bash
# Pack a project directory into an archive
folder2json pack ./my-project archive.json -v

# Pack including hidden files, but excluding build artifacts
folder2json pack ./src output.json -a -e target -e "*.log"

# Pack to stdout and pipe directly into xz compression
folder2json pack ./my-project - | xz > archive.json.xz

# Pack with binary compression disabled (plain Base64)
folder2json pack ./my-project archive.json --no-compress
```

### Unpacking

```bash
# Unpack JSON back into a folder with integrity verification
folder2json unpack archive.json ./restored -v

# Unpack directly from a compressed stream via Stdin
xz -dc archive.json.xz | folder2json unpack - ./restored

# Unpack skipping SHA-256 integrity verification
folder2json unpack archive.json ./restored --no-verify
```

---

## Standalone Python Extraction

Archives contain a built-in Python decoder in `python_reference`. You can unpack files programmatically without installing the Rust binary:

```python
import json, base64, hashlib
import zstandard as zstd

def extract_file(json_path, rel_path):
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    files_map = {e['path']: e for e in data['files']}
    curr = files_map.get(rel_path)
    while curr and curr.get('type') == 'link':
        curr = files_map[curr['content']]
    if not curr:
        return None
    
    if curr['type'] == 'text':
        payload = curr.get('content', '').encode('utf-8')
    else:
        payload = curr.get('content', '').encode('ascii')
        for enc in reversed(curr.get('encoding', ['base64'])):
            if enc == 'base64':
                payload = base64.b64decode(payload)
            elif enc == 'zstd':
                payload = zstd.ZstdDecompressor().decompress(payload)
    
    digest = hashlib.sha256(payload).hexdigest()[:16]
    assert digest == curr.get('hash'), "Integrity check failed"
    return payload
```
