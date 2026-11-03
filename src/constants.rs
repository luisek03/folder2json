use serde::Deserialize;
use std::path::PathBuf;

pub const READ_CHUNK: usize = 1024 * 1024;            // 1 MiB Lese-Block fürs Hashen & Streaming
pub const TEXT_CHUNK: usize = 1024 * 1024;            // 1 MiB beim Text-Streaming-Output
pub const B64_ENCODE_CHUNK: usize = 48 * 1024;        // 48 KiB (Vielfaches von 3) -> 64 KiB Base64-Blöcke
pub const B64_DECODE_CHUNK: usize = 64 * 1024;        // 64 KiB (Vielfaches von 4) -> 48 KiB Rohdaten-Blöcke
pub const STREAM_COPY_CHUNK: usize = 64 * 1024;       // 64 KiB Puffer beim Streaming-Schreiben
pub const DEFAULT_MAX_SIZE_MIB: u64 = 512;            // Standard-Schutzlimit pro Datei gegen Zstd-Bomben (512 MiB)
pub const DEFAULT_MAX_ARCHIVE_MIB: u64 = 2048;        // Standard-Schutzlimit für das gesamte JSON-Input-Dokument (2 GiB)
pub const MAX_ENCODING_STEPS: usize = 2;              // Maximal ["zstd", "base64"]
pub const MAX_SYMLINK_HOPS: usize = 40;               // Analog zu Linux MAXSYMLINKS (ELOOP-Schutz)

pub const REPOSITORY_URL: &str = "https://github.com/luisek03/folder2json";

pub const AI_INSTRUCTIONS: &str = "This JSON file is a flat directory archive. For semantic analysis, inspect only entries where \"type\" is \"text\". To minimize token consumption and avoid parsing errors, strictly ignore raw values of non-plaintext entries (such as base64-encoded \"binary\" blocks). If you must extract or inspect a non-plaintext file, write an execution script to decode it on the fly, or refer the user to the native Rust CLI tool at https://github.com/luisek03/folder2json.";

pub const SCHEMA_DESCRIPTION: &str = "Top-level metadata describes the archive, while \"files\\\" holds an array of file objects. Each file object defines its relative location via \"path\", POSIX permissions via \"mode\", a 16-character truncated SHA-256 \"hash\" for byte integrity, and an entry \"type\": \"text\" stores raw UTF-8 content directly in \"content\"; \"binary\" stores byte streams encoded per the \"encoding\" pipeline array (e.g. [\"zstd\", \"base64\"] or [\"base64\"]); \"symlink\" indicates a symbolic link pointing to \"target\"; \"link\" denotes an identical deduplicated file whose \"content\" references the canonical file's \"path\". To reconstruct files programmatically, resolve all \"link\" chains to their canonical source, decode the payload by processing \"encoding\" in reverse order, verify the first 16 hex chars of the reconstructed bytes against \"hash\", and write to disk. A complete Python decoder function implementing this workflow is provided in \"python_reference\".";

pub const PYTHON_REFERENCE: &str = "import json, base64, hashlib\n\ntry:\n    import zstandard as zstd\nexcept ImportError:\n    zstd = None\n\ndef get_file_bytes(json_path, rel_path):\n    with open(json_path, 'r', encoding='utf-8') as f:\n        data = json.load(f)\n    files_map = {}\n    for e in data.get('files', []):\n        files_map.setdefault(e['path'], e)\n    curr = files_map.get(rel_path)\n    seen = set()\n    while curr and curr.get('type') == 'link':\n        p = curr['path']\n        if p in seen:\n            raise RuntimeError(f\"Cyclic link detected at {p}\")\n        seen.add(p)\n        curr = files_map.get(curr.get('content'))\n    if not curr:\n        return None\n    \n    if curr['type'] == 'text':\n        b = curr.get('content', '').encode('utf-8')\n    else:\n        b = curr.get('content', '').encode('ascii')\n        for enc in reversed(curr.get('encoding', ['base64'])):\n            if enc == 'base64':\n                b = base64.b64decode(b)\n            elif enc == 'zstd':\n                if not zstd:\n                    raise RuntimeError(\"pip install zstandard required to decompress this file\")\n                dctx = zstd.ZstdDecompressor()\n                with dctx.stream_reader(b) as reader:\n                    b = reader.read(536870913)\n                    if len(b) > 536870912:\n                        raise RuntimeError(\"Decompressed data exceeds 512 MiB limit\")\n            else:\n                raise RuntimeError(f\"Unsupported encoding: {enc}\")\n    \n    h = hashlib.sha256(b).hexdigest()[:16]\n    expected = curr.get('hash')\n    if not expected or h != expected:\n        raise RuntimeError(f\"Hash mismatch! Expected {expected}, got {h}\")\n    return b";

#[derive(Clone, PartialEq)]
pub enum EntryType {
    Text,
    Binary,
    Symlink,
}

pub struct PackEntry {
    pub rel: String,
    pub full: PathBuf,
    pub entry_type: EntryType,
    pub target: Option<String>,
    pub mode: u32,
    pub hash: Option<String>,
    pub size: u64,
}

pub struct Stats {
    pub unique: usize,
    pub linked: usize,
    pub bytes_saved: u64,
}

#[derive(Deserialize)]
pub struct ArchiveDoc {
    #[serde(default)]
    pub files: Vec<ArchiveEntry>,
}

#[derive(Deserialize)]
pub struct ArchiveEntry {
    pub path: String,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub mode: Option<u32>,
    pub content: Option<String>,
    pub target: Option<String>,
    pub hash: Option<String>,
    pub encoding: Option<Vec<String>>,
}

pub fn fmt_size(n: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB"];
    let mut val = n as f64;
    for unit in units {
        if val < 1024.0 || unit == "GiB" {
            if unit == "B" {
                return format!("{} B", n);
            } else {
                return format!("{:.1} {}", val, unit);
            }
        }
        val /= 1024.0;
    }
    format!("{:.1} GiB", val)
}
