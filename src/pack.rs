use crate::constants::{
    fmt_size, EntryType, PackEntry, Stats, AI_INSTRUCTIONS, DEFAULT_MAX_SIZE_MIB, PYTHON_REFERENCE,
    REPOSITORY_URL, SCHEMA_DESCRIPTION,
};
use crate::glob::{matches_exclude, path_to_posix};
use crate::security::is_potentially_sensitive;
use crate::stream::{
    analyze_file, stream_binary_into_json, stream_text_into_json, StreamTextError,
};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn is_already_compressed(path_str: &str) -> bool {
    let lower = path_str.to_lowercase();

    if lower.ends_with(".tar") {
        return false;
    }

    const COMPRESSED_EXTS: &[&str] = &[
        ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz", ".zst", ".tzst", ".zip", ".7z", ".rar",
        ".lz4", ".br",
    ];

    COMPRESSED_EXTS.iter().any(|ext| lower.ends_with(ext))
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
        let rel_d_posix = path_to_posix(rel_d);
        if matches_exclude(rel_d, excludes) {
            excluded.push(format!("{}/", rel_d_posix));
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

        if is_potentially_sensitive(&rel_posix) {
            eprintln!(
                "⚠️  SICHERHEITSHINWEIS: Potenziell sensible Datei '{}' wird ins Archiv gepackt!",
                rel_posix
            );
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
        #[cfg(unix)]
        let mode = st.permissions().mode() & 0o777;
        #[cfg(windows)]
        let mode = 0o644; // Windows nutzt Fallback-Berechtigungen

        let (digest, size, is_text) = analyze_file(&full)
        .map_err(|e| format!("Fehler beim Analysieren von '{}': {}", rel_posix, e))?;

        if size > DEFAULT_MAX_SIZE_MIB * 1024 * 1024 {
            eprintln!(
                "ℹ️  HINWEIS: '{}' ({}) überschreitet das Standard-Entpacklimit von {} MiB. \
Beim Entpacken '--max-size-mib' angeben.",
rel_posix,
fmt_size(size),
                      DEFAULT_MAX_SIZE_MIB
            );
        }

        entries.push(PackEntry {
            rel: rel_posix,
            full,
            entry_type: if is_text {
                EntryType::Text
            } else {
                EntryType::Binary
            },
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

pub fn pack(
    src: &Path,
    out_arg: &str,
    excludes: &[String],
    verbose: bool,
    dedup: bool,
    no_compress: bool,
) -> Result<(usize, Vec<String>, Stats), String> {
    let src_resolved =
    fs::canonicalize(src).map_err(|_| format!("Kein Ordner: {}", src.display()))?;
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
            writeln!(f, "    {}{}", serde_json::to_string(pat).unwrap(), comma)
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
        unique: if dedup {
            hash_to_canon.len()
        } else {
            entries.len()
        },
        linked: linked_count.get(),
        bytes_saved: saved_bytes.get(),
    };

    Ok((entries.len(), excluded, stats))
}
