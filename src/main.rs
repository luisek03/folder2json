use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use clap::{Parser, Subcommand};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, Permissions};
use std::io::{self, BufWriter, Read, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process;

const READ_CHUNK: usize = 1024 * 1024;            // 1 MiB Lese-Block fürs Hashen & UTF-8 Check
const TEXT_CHUNK: usize = 1024 * 1024;            // 1 MiB beim Streaming-Output
const B64_CHUNK: usize = 3 * 1024 * 1024;         // Vielfaches von 3 -> kein Padding-Drift
const DEFAULT_MAX_SIZE_MIB: u64 = 512;            // Standard-Schutzlimit gegen Zstd-Bomben (512 MiB)
const MAX_ENCODING_STEPS: usize = 2;              // Maximal ["zstd", "base64"]

const REPOSITORY_URL: &str = "https://github.com/luisek03/folder2json";

const AI_INSTRUCTIONS: &str = "This JSON file is a flat directory archive. For semantic analysis, inspect only entries where \"type\" is \"text\". To minimize token consumption and avoid parsing errors, strictly ignore raw values of non-plaintext entries (such as base64-encoded \"binary\" blocks). If you must extract or inspect a non-plaintext file, write an execution script to decode it on the fly, or refer the user to the native Rust CLI tool at https://github.com/luisek03/folder2json.";

const SCHEMA_DESCRIPTION: &str = "Top-level metadata describes the archive, while \"files\" holds an array of file objects. Each file object defines its relative location via \"path\", POSIX permissions via \"mode\", a 16-character truncated SHA-256 \"hash\" for byte integrity, and an entry \"type\": \"text\" stores raw UTF-8 content directly in \"content\"; \"binary\" stores byte streams encoded per the \"encoding\" pipeline array (e.g. [\"zstd\", \"base64\"] or [\"base64\"]); \"symlink\" indicates a symbolic link pointing to \"target\"; \"link\" denotes an identical deduplicated file whose \"content\" references the canonical file's \"path\". To reconstruct files programmatically, resolve all \"link\" chains to their canonical source, decode the payload by processing \"encoding\" in reverse order, verify the first 16 hex chars of the reconstructed bytes against \"hash\", and write to disk. A complete Python decoder function implementing this workflow is provided in \"python_reference\".";

const PYTHON_REFERENCE: &str = "import json, base64, hashlib\n\ntry:\n    import zstandard as zstd\nexcept ImportError:\n    zstd = None\n\ndef get_file_bytes(json_path, rel_path):\n    with open(json_path, 'r', encoding='utf-8') as f:\n        data = json.load(f)\n    files_map = {e['path']: e for e in data['files']}\n    curr = files_map.get(rel_path)\n    seen = set()\n    while curr and curr.get('type') == 'link':\n        p = curr['path']\n        if p in seen:\n            raise RuntimeError(f\"Cyclic link detected at {p}\")\n        seen.add(p)\n        curr = files_map.get(curr.get('content'))\n    if not curr:\n        return None\n    \n    if curr['type'] == 'text':\n        b = curr.get('content', '').encode('utf-8')\n    else:\n        b = curr.get('content', '').encode('ascii')\n        for enc in reversed(curr.get('encoding', ['base64'])):\n            if enc == 'base64':\n                b = base64.b64decode(b)\n            elif enc == 'zstd':\n                if not zstd:\n                    raise RuntimeError(\"pip install zstandard required to decompress this file\")\n                dctx = zstd.ZstdDecompressor()\n                b = dctx.decompress(b, max_output_size=536870912)\n            else:\n                raise RuntimeError(f\"Unsupported encoding: {enc}\")\n    \n    h = hashlib.sha256(b).hexdigest()[:16]\n    expected = curr.get('hash')\n    if not expected or h != expected:\n        raise RuntimeError(f\"Hash mismatch! Expected {expected}, got {h}\")\n    return b";

#[derive(Parser)]
#[command(
name = "folder2json",
author = "Luis",
version,
about = "Lossless folder archiving into self-contained, AI-optimized JSON.",
long_about = "A high-performance CLI utility to pack and unpack directory trees into JSON format.\n\
Designed for LLM context injection, shell pipelines (Stdin/Stdout), and bit-exact\n\
source code archiving with cryptographic SHA-256 integrity verification and\n\
strict path-traversal / decompression-bomb protection."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Pack a folder into a JSON archive (use '-' for stdout)
    #[command(
    long_about = "Packs all files, metadata, and permissions of a directory tree into a single JSON file.\n\
Outputs raw UTF-8 for plaintext files, and encoded byte streams for binary files.\n\
Supports deduplication, automatic integrity hashing, and UNIX permission retention.\n\n\
EXAMPLES:\n  \
folder2json pack ./my-project archive.json\n  \
folder2json pack ./my-project - | xz > archive.json.xz\n  \
folder2json pack ./src output.json -a -e target -e '*.log'"
    )]
    Pack {
        /// Source directory to pack
        src: PathBuf,

        /// Destination JSON archive path, or '-' to stream directly to stdout
        out: String,

        /// Include hidden files and hidden directories (.*) (ignored by default)
        #[arg(short = 'a', long = "all")]
        all: bool,

        /// Exclude patterns (can be repeated, e.g. -e "*.log" -e ".git" -e "target")
        #[arg(short = 'e', long = "exclude")]
        exclude: Vec<String>,

        /// Disable file deduplication (content is still hashed with SHA-256 for integrity)
        #[arg(long = "no-dedup")]
        no_dedup: bool,

        /// Disable binary payload compression in the encoding pipeline (forces plain base64)
        #[arg(long = "no-compress")]
        no_compress: bool,

        /// Verbose output showing each processed entry and deduplication links
        #[arg(short = 'v', long = "verbose")]
        verbose: bool,
    },

    /// Unpack a JSON archive back into a folder (use '-' for stdin)
    #[command(
    long_about = "Restores a directory tree from a JSON archive created by this tool.\n\
Reconstructs file hierarchy, decodes payloads, recreates symlinks,\n\
restores exact POSIX permissions, and validates 16-character SHA-256 hashes.\n\
Enforces strict scope validation against path traversal (../, ~/, /) and symlink escapes.\n\n\
EXAMPLES:\n  \
folder2json unpack archive.json ./restored\n  \
xz -dc archive.json.xz | folder2json unpack - ./restored\n  \
folder2json unpack archive.json ./restored --no-verify"
    )]
    Unpack {
        /// Input JSON archive path, or '-' to read directly from stdin
        in_json: String,

        /// Target folder where files should be extracted
        dst: PathBuf,

        /// Skip 16-char SHA-256 cryptographic integrity checks
        #[arg(long = "no-verify")]
        no_verify: bool,

        /// Allow symlinks whose target points outside the destination directory (blocked by default)
        #[arg(long = "allow-external-symlinks")]
        allow_external_symlinks: bool,

        /// Maximum allowed decompressed size per binary file in MiB (protects against zstd bombs)
        #[arg(long = "max-size-mib", default_value_t = DEFAULT_MAX_SIZE_MIB)]
        max_size_mib: u64,

        /// Verbose output showing each extracted or linked file
        #[arg(short = 'v', long = "verbose")]
        verbose: bool,
    },
}

#[derive(Clone, PartialEq)]
enum EntryType {
    Text,
    Binary,
    Symlink,
}

struct PackEntry {
    rel: String,
    full: PathBuf,
    entry_type: EntryType,
    target: Option<String>,
    mode: u32,
    hash: Option<String>,
    size: u64,
}

struct Stats {
    unique: usize,
    linked: usize,
    bytes_saved: u64,
}

#[derive(Deserialize)]
struct ArchiveDoc {
    #[serde(default)]
    files: Vec<ArchiveEntry>,
}

#[derive(Deserialize)]
struct ArchiveEntry {
    path: String,
    #[serde(rename = "type")]
    entry_type: String,
    mode: Option<u32>,
    content: Option<String>,
    target: Option<String>,
    hash: Option<String>,
    encoding: Option<Vec<String>>,
}

fn is_already_compressed(path_str: &str) -> bool {
    let lower = path_str.to_lowercase();

    if lower.ends_with(".tar") {
        return false;
    }

    const COMPRESSED_EXTS: &[&str] = &[
        ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz", ".zst", ".tzst",
        ".zip", ".7z", ".rar", ".lz4", ".br",
    ];

    COMPRESSED_EXTS.iter().any(|ext| lower.ends_with(ext))
}

/// Iterative Glob-Matching-Engine in O(N * M) ohne ReDoS-Backtracking-Risiko
fn fnmatch(text: &str, pat: &str) -> bool {
    let t: Vec<char> = text.chars().collect();
    let p: Vec<char> = pat.chars().collect();

    let mut ti = 0usize;
    let mut pi = 0usize;
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0usize;

    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            while pi < p.len() && p[pi] == '*' {
                pi += 1;
            }
            star_pi = Some(pi);
            star_ti = ti;
        } else if pi < p.len() && p[pi] == '?' {
            ti += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '[' {
            if let Some((matched, next_pi)) = match_bracket_idx(t[ti], &p, pi + 1) {
                if matched {
                    ti += 1;
                    pi = next_pi;
                    continue;
                }
            } else if t[ti] == '[' {
                ti += 1;
                pi += 1;
                continue;
            }
            if let Some(sp) = star_pi {
                pi = sp;
                star_ti += 1;
                ti = star_ti;
            } else {
                return false;
            }
        } else if pi < p.len() && p[pi] == t[ti] {
            ti += 1;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }

    pi == p.len()
}

fn match_bracket_idx(ch: char, p: &[char], start_idx: usize) -> Option<(bool, usize)> {
    if start_idx >= p.len() {
        return None;
    }
    let mut i = start_idx;
    let negate = if p[i] == '!' || p[i] == '^' {
        i += 1;
        true
    } else {
        false
    };
    if i >= p.len() {
        return None;
    }
    let mut matched = false;
    let mut first = true;
    while i < p.len() {
        if p[i] == ']' && !first {
            let res = if negate { !matched } else { matched };
            return Some((res, i + 1));
        }
        first = false;
        if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
            let start = p[i];
            let end = p[i + 2];
            if ch >= start && ch <= end {
                matched = true;
            }
            i += 3;
        } else {
            if ch == p[i] {
                matched = true;
            }
            i += 1;
        }
    }
    None
}

fn path_to_posix(path: &Path) -> String {
    path.components()
    .map(|c| c.as_os_str().to_string_lossy())
    .collect::<Vec<_>>()
    .join("/")
}

fn matches_exclude(rel_path: &Path, excludes: &[String]) -> bool {
    let rel_str = path_to_posix(rel_path);
    let parts: Vec<String> = rel_path
    .components()
    .map(|c| c.as_os_str().to_string_lossy().into_owned())
    .collect();

    for pat in excludes {
        if fnmatch(&rel_str, pat) {
            return true;
        }
        for part in &parts {
            if fnmatch(part, pat) {
                return true;
            }
        }
    }
    false
}

/// Liest die Datei komplett für den SHA-256-Hash und prüft gleichzeitig über die
/// gesamte Dateilänge, ob es sich um valides, nullbyte-freies UTF-8 handelt.
fn analyze_file(full_path: &Path) -> io::Result<(String, u64, bool)> {
    let mut f = File::open(full_path)?;
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    let mut is_valid_text = true;
    let mut utf8_buf = vec![0u8; READ_CHUNK + 4];
    let mut leftover = 0usize;

    loop {
        let n = f.read(&mut utf8_buf[leftover..leftover + READ_CHUNK])?;
        if n == 0 {
            if leftover > 0 {
                is_valid_text = false;
            }
            break;
        }

        let new_bytes = &utf8_buf[leftover..leftover + n];
        hasher.update(new_bytes);
        size += n as u64;

        if is_valid_text {
            if new_bytes.contains(&0) {
                is_valid_text = false;
                leftover = 0;
            } else {
                let total = leftover + n;
                match std::str::from_utf8(&utf8_buf[..total]) {
                    Ok(_) => {
                        leftover = 0;
                    }
                    Err(e) => {
                        if e.error_len().is_none() {
                            let valid_up_to = e.valid_up_to();
                            leftover = total - valid_up_to;
                            utf8_buf.copy_within(valid_up_to..total, 0);
                        } else {
                            is_valid_text = false;
                            leftover = 0;
                        }
                    }
                }
            }
        }
    }

    let digest: String = hasher
    .finalize()
    .iter()
    .map(|b| format!("{:02x}", b))
    .collect();

    Ok((digest, size, is_valid_text))
}

enum StreamTextError {
    Io(io::Error),
    InvalidUtf8,
}

fn stream_text_into_json<W: Write>(
    f_out: &mut W,
    full_path: &Path,
) -> Result<(String, u64), StreamTextError> {
    f_out.write_all(b"\"").map_err(StreamTextError::Io)?;
    let mut fs = File::open(full_path).map_err(StreamTextError::Io)?;
    let mut buf = vec![0u8; TEXT_CHUNK + 4];
    let mut leftover = 0usize;
    let mut hasher = Sha256::new();
    let mut total_read = 0u64;

    loop {
        let n = fs
        .read(&mut buf[leftover..leftover + TEXT_CHUNK])
        .map_err(StreamTextError::Io)?;
        if n > 0 {
            hasher.update(&buf[leftover..leftover + n]);
            total_read += n as u64;
        }
        let total = leftover + n;
        if total == 0 {
            break;
        }

        let valid_str = match std::str::from_utf8(&buf[..total]) {
            Ok(s) => {
                leftover = 0;
                s
            }
            Err(e) => {
                if e.error_len().is_none() && n > 0 {
                    let valid_up_to = e.valid_up_to();
                    leftover = total - valid_up_to;
                    let s = std::str::from_utf8(&buf[..valid_up_to]).unwrap();
                    let esc = serde_json::to_string(s).unwrap();
                    f_out
                    .write_all(&esc.as_bytes()[1..esc.len() - 1])
                    .map_err(StreamTextError::Io)?;
                    buf.copy_within(valid_up_to..total, 0);
                    continue;
                } else {
                    return Err(StreamTextError::InvalidUtf8);
                }
            }
        };

        let esc = serde_json::to_string(valid_str).unwrap();
        f_out
        .write_all(&esc.as_bytes()[1..esc.len() - 1])
        .map_err(StreamTextError::Io)?;
    }

    f_out.write_all(b"\"").map_err(StreamTextError::Io)?;
    let digest: String = hasher
    .finalize()
    .iter()
    .map(|b| format!("{:02x}", b))
    .collect();
    Ok((digest, total_read))
}

fn stream_binary_into_json<W: Write>(
    f_out: &mut W,
    full_path: &Path,
    compress_with_zstd: bool,
) -> io::Result<(String, u64)> {
    f_out.write_all(b"\"")?;
    let mut fs = File::open(full_path)?;
    let mut hasher = Sha256::new();
    let mut total_read = 0u64;

    if compress_with_zstd {
        let mut raw_data = Vec::new();
        fs.read_to_end(&mut raw_data)?;
        hasher.update(&raw_data);
        total_read = raw_data.len() as u64;
        let compressed = zstd::encode_all(&raw_data[..], 3)?;
        let encoded = BASE64.encode(&compressed);
        f_out.write_all(encoded.as_bytes())?;
    } else {
        let mut buf = vec![0u8; B64_CHUNK];
        loop {
            let mut filled = 0;
            while filled < B64_CHUNK {
                let n = fs.read(&mut buf[filled..])?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            if filled == 0 {
                break;
            }
            hasher.update(&buf[..filled]);
            total_read += filled as u64;
            let encoded = BASE64.encode(&buf[..filled]);
            f_out.write_all(encoded.as_bytes())?;
        }
    }

    f_out.write_all(b"\"")?;
    let digest: String = hasher
    .finalize()
    .iter()
    .map(|b| format!("{:02x}", b))
    .collect();
    Ok((digest, total_read))
}

fn resolve_out_path(p: &Path) -> PathBuf {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        env::current_dir().unwrap_or_default().join(p)
    };
    if let (Some(parent), Some(name)) = (abs.parent(), abs.file_name()) {
        if let Ok(canon_parent) = fs::canonicalize(parent) {
            return canon_parent.join(name);
        }
    }
    abs
}

fn walk_dir(
    src_root: &Path,
    current_dir: &Path,
    excludes: &[String],
    skip_files: &HashSet<PathBuf>,
    entries: &mut Vec<PackEntry>,
    excluded: &mut Vec<String>,
) -> Result<(), String> {
    let read_dir = fs::read_dir(current_dir)
    .map_err(|e| format!("Fehler beim Lesen des Ordners '{}': {}", current_dir.display(), e))?;

    let mut dirs = Vec::new();
    let mut files = Vec::new();

    for item in read_dir {
        let item = item.map_err(|e| e.to_string())?;
        let path = item.path();
        if skip_files.contains(&path) {
            continue;
        }
        let ft = item.file_type().map_err(|e| e.to_string())?;
        if ft.is_dir() {
            dirs.push(path);
        } else {
            files.push((path, ft));
        }
    }

    let mut keep_dirs = Vec::new();
    for d in dirs {
        let rel_d = d.strip_prefix(src_root).unwrap();
        if matches_exclude(rel_d, excludes) {
            excluded.push(format!("{}/", path_to_posix(rel_d)));
        } else {
            keep_dirs.push(d);
        }
    }

    for (full, ft) in files {
        let rel = full.strip_prefix(src_root).unwrap();
        let rel_posix = path_to_posix(rel);

        if matches_exclude(rel, excludes) {
            excluded.push(rel_posix);
            continue;
        }

        if ft.is_symlink() {
            let target_path = fs::read_link(&full)
            .map_err(|e| format!("Fehler beim Lesen des Symlinks '{}': {}", rel_posix, e))?;
            entries.push(PackEntry {
                rel: rel_posix,
                full,
                entry_type: EntryType::Symlink,
                target: Some(target_path.to_string_lossy().into_owned()),
                         mode: 0,
                         hash: None,
                         size: 0,
            });
            continue;
        }

        // Sicherheitsschutz gegen Blockade durch FIFOs (Named Pipes), Sockets oder Device-Nodes
        if !ft.is_file() {
            eprintln!(
                "WARN: Spezialdatei '{}' (FIFO/Socket/Device) wird übersprungen.",
                      rel_posix
            );
            excluded.push(rel_posix);
            continue;
        }

        let st = fs::symlink_metadata(&full)
        .map_err(|e| format!("Fehler bei lstat von '{}': {}", rel_posix, e))?;
        let mode = st.permissions().mode() & 0o777;

        let (digest, size, is_text) = analyze_file(&full)
        .map_err(|e| format!("Fehler beim Analysieren von '{}': {}", rel_posix, e))?;

        entries.push(PackEntry {
            rel: rel_posix,
            full,
            entry_type: if is_text { EntryType::Text } else { EntryType::Binary },
            target: None,
            mode,
            hash: Some(digest),
                     size,
        });
    }

    for d in keep_dirs {
        walk_dir(src_root, &d, excludes, skip_files, entries, excluded)?;
    }

    Ok(())
}

fn pack(
    src: &Path,
    out_arg: &str,
    excludes: &[String],
    verbose: bool,
    dedup: bool,
    no_compress: bool,
) -> Result<(usize, Vec<String>, Stats), String> {
    let src_resolved = fs::canonicalize(src)
    .map_err(|_| format!("Kein Ordner: {}", src.display()))?;
    if !src_resolved.is_dir() {
        return Err(format!("Kein Ordner: {}", src_resolved.display()));
    }

    let is_stdout = out_arg == "-";
    let mut skip_files = HashSet::new();
    let out_resolved = if !is_stdout {
        let out_p = resolve_out_path(Path::new(out_arg));
        let tmp_name = format!(
            "{}.tmp",
            out_p.file_name().unwrap_or_default().to_string_lossy()
        );
        let tmp_p = out_p.with_file_name(tmp_name);
        skip_files.insert(out_p.clone());
        skip_files.insert(tmp_p);
        Some(out_p)
    } else {
        None
    };

    let mut entries = Vec::new();
    let mut excluded = Vec::new();

    walk_dir(
        &src_resolved,
        &src_resolved,
        excludes,
        &skip_files,
        &mut entries,
        &mut excluded,
    )?;

    let mut hash_to_canon: HashMap<String, String> = HashMap::new();
    if dedup {
        for e in &entries {
            if let Some(ref h) = e.hash {
                if h.is_empty() {
                    continue;
                }
                match hash_to_canon.get(h) {
                    Some(existing) if e.rel >= *existing => {}
                    _ => {
                        hash_to_canon.insert(h.clone(), e.rel.clone());
                    }
                }
            }
        }
    }

    entries.sort_by(|a, b| a.rel.cmp(&b.rel));

    let linked_count = Cell::new(0usize);
    let saved_bytes = Cell::new(0u64);

    let write_contents = |writer: &mut dyn Write| -> Result<(), String> {
        let mut f = BufWriter::new(writer);
        let src_name = src_resolved
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

        writeln!(f, "{{").map_err(|e| e.to_string())?;
        writeln!(f, "  \"format\": \"folder-json\",").map_err(|e| e.to_string())?;
        writeln!(f, "  \"version\": 1,").map_err(|e| e.to_string())?;
        writeln!(
            f,
            "  \"source\": {},",
            serde_json::to_string(&src_name).unwrap()
        )
        .map_err(|e| e.to_string())?;
        writeln!(
            f,
            "  \"repository\": {},",
            serde_json::to_string(REPOSITORY_URL).unwrap()
        )
        .map_err(|e| e.to_string())?;
        writeln!(
            f,
            "  \"ai_instructions\": {},",
            serde_json::to_string(AI_INSTRUCTIONS).unwrap()
        )
        .map_err(|e| e.to_string())?;
        writeln!(
            f,
            "  \"schema_description\": {},",
            serde_json::to_string(SCHEMA_DESCRIPTION).unwrap()
        )
        .map_err(|e| e.to_string())?;
        writeln!(
            f,
            "  \"python_reference\": {},",
            serde_json::to_string(PYTHON_REFERENCE).unwrap()
        )
        .map_err(|e| e.to_string())?;

        writeln!(f, "  \"excludes\": [").map_err(|e| e.to_string())?;
        for (i, pat) in excludes.iter().enumerate() {
            let comma = if i + 1 < excludes.len() { "," } else { "" };
            writeln!(
                f,
                "    {}{}",
                serde_json::to_string(pat).unwrap(),
                     comma
            )
            .map_err(|e| e.to_string())?;
        }
        writeln!(f, "  ],").map_err(|e| e.to_string())?;

        writeln!(f, "  \"file_count\": {},", entries.len()).map_err(|e| e.to_string())?;
        writeln!(f, "  \"files\": [").map_err(|e| e.to_string())?;

        for (i, e) in entries.iter().enumerate() {
            if i > 0 {
                writeln!(f, ",").map_err(|e| e.to_string())?;
            }

            let rel_json = serde_json::to_string(&e.rel).unwrap();

            if e.entry_type == EntryType::Symlink {
                let target_str = e.target.as_deref().unwrap_or("");
                let target_json = serde_json::to_string(target_str).unwrap();
                writeln!(f, "    {{").map_err(|e| e.to_string())?;
                writeln!(f, "      \"path\": {},", rel_json).map_err(|e| e.to_string())?;
                writeln!(f, "      \"type\": \"symlink\",").map_err(|e| e.to_string())?;
                writeln!(f, "      \"target\": {}", target_json).map_err(|e| e.to_string())?;
                write!(f, "    }}").map_err(|e| e.to_string())?;
                if verbose {
                    if is_stdout {
                        eprintln!("  L {} -> {}", e.rel, target_str);
                    } else {
                        println!("  L {} -> {}", e.rel, target_str);
                    }
                }
                continue;
            }

            let expected_full_hash = e.hash.as_deref().unwrap_or("");
            let short_hash = if !expected_full_hash.is_empty() {
                Some(expected_full_hash.chars().take(16).collect::<String>())
            } else {
                None
            };

            let canon_rel = if dedup {
                e.hash
                .as_ref()
                .and_then(|h| hash_to_canon.get(h))
                .map(|s| s.as_str())
                .unwrap_or(&e.rel)
            } else {
                &e.rel
            };
            let is_canonical = canon_rel == e.rel;

            if !is_canonical {
                let canon_json = serde_json::to_string(canon_rel).unwrap();
                writeln!(f, "    {{").map_err(|e| e.to_string())?;
                writeln!(f, "      \"path\": {},", rel_json).map_err(|e| e.to_string())?;
                writeln!(f, "      \"mode\": {},", e.mode).map_err(|e| e.to_string())?;
                writeln!(f, "      \"type\": \"link\",").map_err(|e| e.to_string())?;
                if let Some(ref sh) = short_hash {
                    writeln!(
                        f,
                        "      \"hash\": {},",
                        serde_json::to_string(sh).unwrap()
                    )
                    .map_err(|e| e.to_string())?;
                }
                writeln!(f, "      \"content\": {}", canon_json).map_err(|e| e.to_string())?;
                write!(f, "    }}").map_err(|e| e.to_string())?;
                linked_count.set(linked_count.get() + 1);
                saved_bytes.set(saved_bytes.get() + e.size);
                if verbose {
                    if is_stdout {
                        eprintln!("  → {} (link → {})", e.rel, canon_rel);
                    } else {
                        println!("  → {} (link → {})", e.rel, canon_rel);
                    }
                }
                continue;
            }

            if e.entry_type == EntryType::Binary {
                let already_comp = is_already_compressed(&e.rel);
                let use_zstd = !no_compress && !already_comp;

                let encodings = if use_zstd {
                    vec!["zstd", "base64"]
                } else {
                    vec!["base64"]
                };
                let encodings_json = serde_json::to_string(&encodings).unwrap();

                writeln!(f, "    {{").map_err(|e| e.to_string())?;
                writeln!(f, "      \"path\": {},", rel_json).map_err(|e| e.to_string())?;
                writeln!(f, "      \"mode\": {},", e.mode).map_err(|e| e.to_string())?;
                writeln!(f, "      \"type\": \"binary\",").map_err(|e| e.to_string())?;
                writeln!(f, "      \"encoding\": {},", encodings_json).map_err(|e| e.to_string())?;
                if let Some(ref sh) = short_hash {
                    writeln!(
                        f,
                        "      \"hash\": {},",
                        serde_json::to_string(sh).unwrap()
                    )
                    .map_err(|e| e.to_string())?;
                }
                write!(f, "      \"content\": ").map_err(|e| e.to_string())?;
                let (actual_hash, actual_size) =
                stream_binary_into_json(&mut f, &e.full, use_zstd)
                .map_err(|ex| format!("Fehler beim Lesen von '{}': {}", e.rel, ex))?;
                if actual_hash != expected_full_hash || actual_size != e.size {
                    return Err(format!(
                        "TOCTOU-Fehler: Datei '{}' wurde während des Packvorgangs verändert!",
                        e.rel
                    ));
                }
                write!(f, "\n    }}").map_err(|e| e.to_string())?;
                if verbose {
                    let comp_info = if use_zstd { " [zstd]" } else { "" };
                    if is_stdout {
                        eprintln!("  B {}{}", e.rel, comp_info);
                    } else {
                        println!("  B {}{}", e.rel, comp_info);
                    }
                }
                continue;
            }

            writeln!(f, "    {{").map_err(|e| e.to_string())?;
            writeln!(f, "      \"path\": {},", rel_json).map_err(|e| e.to_string())?;
            writeln!(f, "      \"mode\": {},", e.mode).map_err(|e| e.to_string())?;
            writeln!(f, "      \"type\": \"text\",").map_err(|e| e.to_string())?;
            if let Some(ref sh) = short_hash {
                writeln!(
                    f,
                    "      \"hash\": {},",
                    serde_json::to_string(sh).unwrap()
                )
                .map_err(|e| e.to_string())?;
            }
            write!(f, "      \"content\": ").map_err(|e| e.to_string())?;
            match stream_text_into_json(&mut f, &e.full) {
                Ok((actual_hash, actual_size)) => {
                    if actual_hash != expected_full_hash || actual_size != e.size {
                        return Err(format!(
                            "TOCTOU-Fehler: Datei '{}' wurde während des Packvorgangs verändert!",
                            e.rel
                        ));
                    }
                }
                Err(StreamTextError::InvalidUtf8) => {
                    return Err(format!(
                        "'{}' wurde während des Packens verändert und enthält nun ungültiges UTF-8.",
                        e.rel
                    ));
                }
                Err(StreamTextError::Io(ex)) => {
                    return Err(format!("Fehler beim Lesen von '{}': {}", e.rel, ex));
                }
            }
            write!(f, "\n    }}").map_err(|e| e.to_string())?;
            if verbose {
                if is_stdout {
                    eprintln!("  F {}", e.rel);
                } else {
                    println!("  F {}", e.rel);
                }
            }
        }

        writeln!(f, "\n  ]").map_err(|e| e.to_string())?;
        writeln!(f, "}}").map_err(|e| e.to_string())?;
        f.flush().map_err(|e| e.to_string())?;
        Ok(())
    };

    if is_stdout {
        let mut stdout = io::stdout();
        write_contents(&mut stdout)?;
    } else if let Some(out_p) = out_resolved {
        let tmp_name = format!(
            "{}.tmp",
            out_p.file_name().unwrap_or_default().to_string_lossy()
        );
        let tmp_json = out_p.with_file_name(tmp_name);

        let write_res = (|| -> Result<(), String> {
            let mut file = File::create(&tmp_json)
            .map_err(|e| format!("Fehler beim Erstellen von '{}': {}", tmp_json.display(), e))?;
            write_contents(&mut file)
        })();

        if let Err(err) = write_res {
            let _ = fs::remove_file(&tmp_json);
            return Err(err);
        }

        if let Err(e) = fs::rename(&tmp_json, &out_p) {
            let _ = fs::remove_file(&tmp_json);
            return Err(format!("Fehler beim Umbenennen der temporären Datei: {}", e));
        }
    }

    let stats = Stats {
        unique: if dedup { hash_to_canon.len() } else { entries.len() },
        linked: linked_count.get(),
        bytes_saved: saved_bytes.get(),
    };

    Ok((entries.len(), excluded, stats))
}

/// Prüft strikt, dass ein Archiv-Pfad relativ bleibt und keinerlei Path-Traversal enthält.
fn validate_safe_rel_path(raw_path: &str) -> Result<PathBuf, String> {
    if raw_path.is_empty() {
        return Err("Leerer Dateipfad im Archiv erkannt!".to_string());
    }

    if raw_path.contains('\0') || raw_path.contains('\\') {
        return Err(format!(
            "Gefährliche Pfad-Manipulation (Backslash '\\' oder Null-Byte) blockiert."
        ));
    }

    if raw_path.starts_with('/') || raw_path.starts_with('~') {
        return Err(format!(
            "Absolute Pfade ('/') oder Home-Referenzen ('~') blockiert."
        ));
    }

    let mut clean = PathBuf::new();
    for comp in Path::new(raw_path).components() {
        match comp {
            Component::Normal(os_str) => {
                let part = os_str.to_string_lossy();
                if part.is_empty() || part == "~" || part.starts_with('~') {
                    return Err(format!("Gefährliche Pfad-Komponente ('{}') erkannt.", part));
                }
                clean.push(os_str);
            }
            Component::ParentDir => {
                return Err("Path-Traversal-Angriff ('..') blockiert.".to_string());
            }
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {
                return Err("Ungültige Pfad-Struktur ('.', '/') blockiert.".to_string());
            }
        }
    }

    if clean.as_os_str().is_empty() {
        return Err("Pfad löst zu leerem Ziel auf!".to_string());
    }

    Ok(clean)
}

/// Prüft, ob das Ziel eines Symlinks innerhalb des Zielordners (`dst`) bleibt.
fn validate_symlink_target(
    entry_clean_rel: &Path,
    sym_target: &str,
    allow_external: bool,
) -> Result<(), String> {
    if sym_target.is_empty() || sym_target.contains('\0') {
        return Err("Ungültiges/leeres Symlink-Ziel!".to_string());
    }

    if allow_external {
        return Ok(());
    }

    if sym_target.contains('\\') || sym_target.starts_with('/') || sym_target.starts_with('~') {
        return Err("Symlink-Escape (Ziel außerhalb des Ordners) blockiert.".to_string());
    }

    let mut depth_stack: Vec<String> = Vec::new();
    if let Some(parent) = entry_clean_rel.parent() {
        for comp in parent.components() {
            if let Component::Normal(c) = comp {
                depth_stack.push(c.to_string_lossy().into_owned());
            }
        }
    }

    for comp in Path::new(sym_target).components() {
        match comp {
            Component::Normal(c) => {
                let s = c.to_string_lossy();
                if s == "~" || s.starts_with('~') {
                    return Err("Tilde '~' im Symlink-Ziel blockiert.".to_string());
                }
                depth_stack.push(s.into_owned());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if depth_stack.pop().is_none() {
                    return Err("Symlink-Traversal ('..') verlässt den Scope.".to_string());
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err("Root/Prefix-Referenz im Symlink blockiert.".to_string());
            }
        }
    }

    Ok(())
}

/// Erstellt Elternverzeichnisse Komponente für Komponente und stellt sicher,
/// dass kein einziger Ordner auf dem Pfad ein Symlink ist (verhindert 2-Stage-Symlink-Traversal).
fn ensure_safe_parent_dirs(dst_canon: &Path, clean_rel: &Path) -> Result<PathBuf, String> {
    let mut current = dst_canon.to_path_buf();

    if let Some(parent) = clean_rel.parent() {
        for comp in parent.components() {
            if let Component::Normal(c) = comp {
                current.push(c);
                match fs::symlink_metadata(&current) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() {
                            return Err(format!(
                                "🚨 KRITISCHE SICHERHEITSWARNUNG: Symlink-Traversal-Angriff erkannt!\n\
Das Elternverzeichnis '{}' ist ein Symlink. Schreiben durch Symlinks ist blockiert!",
current.display()
                            ));
                        }
                        if !meta.file_type().is_dir() {
                            return Err(format!(
                                "Konflikt beim Entpacken: '{}' existiert bereits und ist kein Ordner.",
                                current.display()
                            ));
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        fs::create_dir(&current).map_err(|err| {
                            format!(
                                "Fehler beim Erstellen des Unterordners '{}': {}",
                                current.display(),
                                    err
                            )
                        })?;
                    }
                    Err(e) => {
                        return Err(format!(
                            "Fehler beim Prüfen des Ordners '{}': {}",
                            current.display(),
                                           e
                        ));
                    }
                }
            }
        }
    }

    let canon_parent = fs::canonicalize(&current).map_err(|e| {
        format!(
            "Fehler bei Kanonisierung von '{}': {}",
            current.display(),
                e
        )
    })?;

    if !canon_parent.starts_with(dst_canon) {
        return Err(format!(
            "🚨 KRITISCHE SICHERHEITSWARNUNG: Zielpfad '{}' liegt außerhalb des Zielordners '{}'!",
            canon_parent.display(),
                           dst_canon.display()
        ));
    }

    Ok(canon_parent.join(clean_rel.file_name().unwrap()))
}

/// Dekomprimiert Zstd-Daten mit einer harten Obergrenze gegen Zip-/Zstd-Bomben.
fn decode_zstd_bounded(compressed: &[u8], max_bytes: u64, entry_path: &str) -> Result<Vec<u8>, String> {
    let decoder = zstd::Decoder::new(compressed)
    .map_err(|e| format!("Zstd-Init-Fehler bei '{}': {}", entry_path, e))?;
    let mut limited_reader = decoder.take(max_bytes.saturating_add(1));
    let mut out = Vec::new();
    limited_reader
    .read_to_end(&mut out)
    .map_err(|e| format!("Zstd-Decompress-Fehler bei '{}': {}", entry_path, e))?;

    if out.len() as u64 > max_bytes {
        return Err(format!(
            "🚨 KRITISCHE SICHERHEITSWARNUNG: Dekompressionsbombe (Zstd-Bomb) bei '{}' erkannt!\n\
Die entpackte Datei überschreitet das Sicherheitslimit von {} MiB.\n\
Entpackvorgang abgebrochen (Limit anpassbar via '--max-size-mib').",
                           entry_path,
                           max_bytes / (1024 * 1024)
        ));
    }

    Ok(out)
}

fn is_valid_short_sha256(h: &str) -> bool {
    h.len() == 16 && h.chars().all(|c| c.is_ascii_hexdigit())
}

fn resolve_link<'a>(
    by_path: &HashMap<&'a str, &'a ArchiveEntry>,
    mut entry: &'a ArchiveEntry,
) -> Result<&'a ArchiveEntry, String> {
    let mut seen = HashSet::new();
    while entry.entry_type == "link" {
        let p = entry.path.as_str();
        if !seen.insert(p) {
            return Err(format!("Zyklische Link-Referenz bei: {}", p));
        }
        let target_ref = entry
        .content
        .as_deref()
        .ok_or_else(|| format!("Link-Eintrag '{}' hat kein content-Feld.", p))?;
        entry = by_path.get(target_ref).copied().ok_or_else(|| {
            format!(
                "Link-Ziel '{}' (verwiesen von '{}') nicht im Archiv.",
                    target_ref, p
            )
        })?;
    }
    Ok(entry)
}

fn unpack(
    in_arg: &str,
    dst: &Path,
    verbose: bool,
    no_verify: bool,
    allow_external_symlinks: bool,
    max_size_mib: u64,
) -> Result<(usize, usize, Vec<String>), String> {
    let max_decompressed_bytes = max_size_mib.saturating_mul(1024 * 1024);

    let raw = if in_arg == "-" {
        let mut buffer = String::new();
        io::stdin()
        .read_to_string(&mut buffer)
        .map_err(|e| format!("Fehler beim Lesen von Stdin: {}", e))?;
        buffer
    } else {
        let in_resolved = fs::canonicalize(Path::new(in_arg))
        .map_err(|e| format!("Kann '{}' nicht öffnen: {}", in_arg, e))?;
        fs::read_to_string(&in_resolved)
        .map_err(|e| format!("Fehler beim Lesen von '{}': {}", in_resolved.display(), e))?
    };

    let doc: ArchiveDoc = serde_json::from_str(&raw)
    .map_err(|e| format!("Ungültiges JSON: {}", e))?;

    let mut failed_files = Vec::new();
    let mut seen_clean_paths: HashSet<PathBuf> = HashSet::new();
    let mut validated_paths: Vec<Option<PathBuf>> = Vec::with_capacity(doc.files.len());

    // Pre-Pass: Validierung
    for entry in &doc.files {
        match validate_safe_rel_path(&entry.path) {
            Ok(clean_rel) => {
                if !seen_clean_paths.insert(clean_rel.clone()) {
                    failed_files.push(format!("'{}': Duplizierter Pfad im Archiv (wird übersprungen)", entry.path));
                    validated_paths.push(None);
                    continue;
                }
                if entry.entry_type == "symlink" {
                    let sym_target = entry.target.as_deref().unwrap_or("");
                    if let Err(e) = validate_symlink_target(&clean_rel, sym_target, allow_external_symlinks) {
                        failed_files.push(format!("'{}': {}", entry.path, e));
                        validated_paths.push(None);
                        continue;
                    }
                }
                validated_paths.push(Some(clean_rel));
            }
            Err(e) => {
                failed_files.push(format!("'{}': {}", entry.path, e));
                validated_paths.push(None);
            }
        }
    }

    fs::create_dir_all(dst)
    .map_err(|e| format!("Kann Zielordner '{}' nicht erstellen: {}", dst.display(), e))?;
    let dst_canon = fs::canonicalize(dst)
    .map_err(|e| format!("Kann Zielordner '{}' nicht kanonisieren: {}", dst.display(), e))?;

    let mut by_path: HashMap<&str, &ArchiveEntry> = HashMap::new();
    for e in &doc.files {
        by_path.insert(e.path.as_str(), e);
    }

    let mut file_count = 0usize;
    let mut link_count = 0usize;

    // Pass 1: Reguläre Dateien
    for (entry, clean_rel_opt) in doc.files.iter().zip(validated_paths.iter()) {
        let clean_rel = match clean_rel_opt {
            Some(p) => p,
            None => continue,
        };

        let t = entry.entry_type.as_str();
        if t == "symlink" {
            continue;
        }

        let process_file = || -> Result<(), String> {
            let resolved = resolve_link(&by_path, entry)?;
            let rt = resolved.entry_type.as_str();

            let decoded_bin: Vec<u8>;
            let payload_bytes: &[u8] = if rt == "binary" {
                let mut current_data = resolved.content.as_deref().unwrap_or("").as_bytes().to_vec();
                let encodings = resolved
                .encoding
                .as_deref()
                .ok_or_else(|| "Fehlendes 'encoding'-Array".to_string())?;

                if encodings.is_empty() || encodings.len() > MAX_ENCODING_STEPS {
                    return Err(format!("Ungültige Encoding-Länge ({})", encodings.len()));
                }

                for enc in encodings.iter().rev() {
                    if enc == "base64" {
                        current_data = BASE64
                        .decode(&current_data)
                        .map_err(|e| format!("Base64-Fehler: {}", e))?;
                    } else if enc == "zstd" {
                        current_data = decode_zstd_bounded(&current_data, max_decompressed_bytes, &entry.path)?;
                    } else {
                        return Err(format!("Nicht unterstütztes Encoding '{}'", enc));
                    }
                }
                decoded_bin = current_data;
                &decoded_bin
            } else if rt == "text" {
                let text_str = resolved.content.as_deref().unwrap_or("");
                text_str.as_bytes()
            } else {
                return Err(format!("Unerwarteter Typ '{}' als Link-Ziel", rt));
            };

            if !no_verify {
                let expected = match (entry.hash.as_deref(), resolved.hash.as_deref()) {
                    (Some(eh), Some(rh)) if eh != rh => {
                        return Err(format!("Inkonsistenter Link-Hash ({} != {})", eh, rh));
                    }
                    (Some(eh), _) => eh,
                    (None, Some(rh)) => rh,
                    (None, None) => return Err("Fehlender SHA-256-Hash".to_string()),
                };

                if !is_valid_short_sha256(expected) {
                    return Err(format!("Ungültiges Hash-Format ('{}')", expected));
                }

                let mut hasher = Sha256::new();
                hasher.update(payload_bytes);
                let actual_full: String = hasher
                .finalize()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect();
                let actual_short: String = actual_full.chars().take(16).collect();
                if actual_short != expected {
                    return Err(format!(
                        "Hash-Mismatch! Erwartet: {}, Erhalten: {}",
                        expected, actual_short
                    ));
                }
            }

            let target = ensure_safe_parent_dirs(&dst_canon, clean_rel)?;

            if let Ok(existing_meta) = fs::symlink_metadata(&target) {
                if existing_meta.file_type().is_dir() {
                    return Err("Am Zielort existiert bereits ein Ordner".to_string());
                }
                if existing_meta.file_type().is_symlink() {
                    fs::remove_file(&target).map_err(|e| format!("Symlink-Entfernung fehlgeschlagen: {}", e))?;
                }
            }

            fs::write(&target, payload_bytes).map_err(|e| e.to_string())?;

            if let Some(raw_mode) = entry.mode.or(resolved.mode) {
                let safe_mode = raw_mode & 0o777;
                fs::set_permissions(&target, Permissions::from_mode(safe_mode))
                .map_err(|e| e.to_string())?;
            }
            Ok(())
        };

        match process_file() {
            Ok(()) => {
                if t == "link" {
                    link_count += 1;
                }
                file_count += 1;
                if verbose {
                    let tag = if t == "link" { "→" } else { "F" };
                    println!("  {} {}", tag, entry.path);
                }
            }
            Err(e) => {
                eprintln!("❌ Übersprungen: '{}' ({})", entry.path, e);
                failed_files.push(format!("'{}': {}", entry.path, e));
            }
        }
    }

    // Pass 2: Symlinks
    for (entry, clean_rel_opt) in doc.files.iter().zip(validated_paths.iter()) {
        let clean_rel = match clean_rel_opt {
            Some(p) => p,
            None => continue,
        };

        if entry.entry_type != "symlink" {
            continue;
        }

        let process_symlink = || -> Result<(), String> {
            let target = ensure_safe_parent_dirs(&dst_canon, clean_rel)?;
            if let Ok(existing_meta) = fs::symlink_metadata(&target) {
                if existing_meta.file_type().is_dir() {
                    return Err("Ziel ist bereits ein Ordner".to_string());
                }
                let _ = fs::remove_file(&target);
            }

            let sym_target = entry.target.as_deref().unwrap_or("");
            symlink(sym_target, &target).map_err(|e| format!("Erstellen fehlgeschlagen: {}", e))?;
            Ok(())
        };

        match process_symlink() {
            Ok(()) => {
                file_count += 1;
                if verbose {
                    println!("  L {} -> {}", entry.path, entry.target.as_deref().unwrap_or(""));
                }
            }
            Err(e) => {
                eprintln!("❌ Übersprungen (Symlink): '{}' ({})", entry.path, e);
                failed_files.push(format!("'{}': {}", entry.path, e));
            }
        }
    }

    Ok((file_count, link_count, failed_files))
}

fn fmt_size(n: u64) -> String {
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

fn main() {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Pack {
            // ... (Bleibt exakt wie zuvor) ...
            src, out, all, exclude, no_dedup, no_compress, verbose,
        } => {
            // ... (Hier ändert sich nichts) ...
            let mut excludes: Vec<String> = Vec::new();
            if !all {
                excludes.push(".*".to_string());
            }
            excludes.extend(exclude);
            let dedup = !no_dedup;

            match pack(&src, &out, &excludes, verbose, dedup, no_compress) {
                Ok((file_len, excluded, stats)) => {
                    if out != "-" {
                        println!("Gepackt: {} Dateien → {}", file_len, out);
                        if dedup {
                            println!(
                                "  Unique: {}, verlinkt: {} ({} gespart)",
                                     stats.unique,
                                     stats.linked,
                                     fmt_size(stats.bytes_saved)
                            );
                        } else {
                            println!("  Dedup deaktiviert (16-Char-Hashes dennoch erzeugt)");
                        }
                        if !excluded.is_empty() {
                            println!("  {} Einträge ausgeschlossen", excluded.len());
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Unpack {
            in_json,
            dst,
            no_verify,
            allow_external_symlinks,
            max_size_mib,
            verbose,
        } => match unpack(
            &in_json,
            &dst,
            verbose,
            no_verify,
            allow_external_symlinks,
            max_size_mib,
        ) {
            Ok((files, links, failures)) => {
                println!(
                    "\n✅ Entpackt: {} Dateien → {} (davon {} Links aufgelöst)",
                         files,
                         dst.display(),
                         links
                );

                if !failures.is_empty() {
                    eprintln!(
                        "\n⚠️  WARNUNG: {} Datei(en) konnten nicht entpackt werden (manipuliert/fehlerhaft):",
                              failures.len()
                    );
                    for f in &failures {
                        eprintln!("  - {}", f);
                    }
                    // Rückgabecode 1 signalisiert Shell-Scripts, dass nicht alles 100% glatt lief
                    process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("\n🚨 KRITISCHER FEHLER: {}", e);
                process::exit(1);
            }
        },
    }
}
