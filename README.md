# folder2json

A high-performance CLI utility written in Rust to pack entire folder structures (including contents, Unix permissions, and symlinks) into a single, self-contained JSON file (`pack`) and restore them bit-exact (`unpack`).

Optimized specifically for **LLM context injection**, shell pipelines (Stdin/Stdout), and bit-exact source code archiving with SHA-256 integrity verification, O(1) RAM streaming, and hardened extraction security.

## Project Structure

```text
folder2json/
├── Cargo.lock      # Locked Rust dependencies
├── Cargo.toml      # Package manifest
├── flake.lock      # Pinned Nixpkgs flake inputs
├── flake.nix       # Reproducible Flake package definition (Linux & Windows)
└── src/
    ├── main.rs     # CLI entry point
    ├── cli.rs      # Clap command definitions
    ├── ...         # Core modules (pack, unpack, stream, security)
```

## Key Features & Design Scope

* **File-Level Archiving:** Preserves exact file byte contents, POSIX file modes (`mode & 0o777`), relative file paths, and symbolic links. *(Note: Empty directories, directory permissions, and file timestamps are intentionally omitted).*
* **Smart Binary Compression Pipeline:** Binary files are compressed on the fly using **Zstandard (zstd level 3)** prior to Base64 encoding (`["zstd", "base64"]`). Pre-compressed formats (`.zip`, `.gz`, `.xz`, etc.) automatically skip re-compression.
* **Streaming Architecture:** Streams text and binary payloads in constant $O(1)$ RAM without loading full files into memory, bounded by customizable safety limits.
* **Hardened Unpack Security:**
  * **Path Traversal Protection:** Rejects `..`, leading `/`, `~`, backslashes, and null bytes.
  * **Chained Symlink-Graph Validation:** Blocks multi-stage symlink escapes using simulated resolution against both archive and disk symlinks (capped at 40 hops).
  * **Per-File Decompression-Bomb Protection:** Enforces a per-file output limit (`--max-size-mib`) during streaming decompression.
  * **Atomic `0600` Temp Writes:** Extracts files into locked-down temporary files, verifies checksums prior to atomic rename, strips SUID/SGID bits, and refuses overwrites without `--force`.
* **Data Integrity Checksums:** Every file entry carries a 16-character truncated SHA-256 hash verified before moving the file into place.
* **Content Deduplication:** Identical files are stored once; duplicates are referenced via lightweight `type: "link"` entries.

## Installation & Building

This project utilizes a statically linked architecture (including Zstd) for maximum portability and minimal footprint. It acts as an "All-in-One Build Tool" via Nix Flakes.

### Via Nix Flakes (Recommended)

Nix guarantees reproducible builds in isolated sandboxes. You can build natively for Linux or cross-compile for Windows seamlessly.

**1. Build for Linux (Sandboxed):**
```bash
nix build
# or explicitly:
nix build .#linux
# The binary will be available at ./result/bin/folder2json
```

**2. Cross-Compile for Windows (Sandboxed):**
```bash
nix build .#windows
# Nix automatically handles the MinGW-w64 toolchain.
# The binary will be available at ./result/bin/folder2json.exe
```

**3. Fast Local Build (Target Caching):**
If you are developing and want to use Cargo's incremental `target/` caching while still utilizing the Nix environment:
```bash
nix run .#build-fast
# The binary will be available at ./target/release/folder2json
```

**4. Run / Install without building manually:**
```bash
# Run directly from GitHub
nix run github:luisek03/folder2json -- --help

# Install into your user profile
nix profile install github:luisek03/folder2json
```

### Standard Cargo Build (Without Nix)

If you have Rust and Cargo installed globally on your system, you can build it standardly. Zstd will be compiled statically from C-sources automatically.

```bash
cargo build --release
# The binary will be available at ./target/release/folder2json
```

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

## Standalone Python Extraction

Archives contain a built-in Python decoder in `python_reference`. You can unpack files programmatically without installing the Rust binary:

```python
import json, base64, hashlib
import zstandard as zstd

def extract_file(json_path, rel_path):
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    files_map = {e['path']: e for e in data.get('files', [])}
    curr = files_map.get(rel_path)
    seen = set()
    while curr and curr.get('type') == 'link':
        p = curr['path']
        if p in seen: raise RuntimeError("Cyclic link")
        seen.add(p)
        curr = files_map.get(curr.get('content'))
    
    if not curr: return None
    
    if curr['type'] == 'text':
        payload = curr.get('content', '').encode('utf-8')
    else:
        payload = curr.get('content', '').encode('ascii')
        for enc in reversed(curr.get('encoding', ['base64'])):
            if enc == 'base64':
                payload = base64.b64decode(payload)
            elif enc == 'zstd':
                payload = zstd.ZstdDecompressor().decompress(payload, max_output_size=536870912)
    
    digest = hashlib.sha256(payload).hexdigest()[:16]
    assert digest == curr.get('hash'), "Integrity check failed"
    return payload
```

## Security Notes for LLM Usage

When feeding JSON archives of untrusted third-party repositories into Large Language Models, keep in mind that plaintext source files inside `"content"` are untrusted data and may contain prompt-injection strings.
