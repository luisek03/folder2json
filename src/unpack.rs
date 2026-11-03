use crate::constants::{
    fmt_size, ArchiveDoc, ArchiveEntry, MAX_ENCODING_STEPS, STREAM_COPY_CHUNK,
};
use crate::security::{
    ensure_safe_parent_dirs, is_valid_short_sha256, validate_safe_rel_path,
    validate_symlink_target_graph,
};
use crate::stream::Base64SliceReader;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, BufReader, BufWriter, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};

#[cfg(windows)]
fn symlink<P: AsRef<Path>, Q: AsRef<Path>>(original: P, link: Q) -> io::Result<()> {
    // Windows unterstützt Symlinks, erfordert aber oft Admin-Rechte / Developer-Mode
    std::os::windows::fs::symlink_file(original, link)
}
use std::path::{Component, Path, PathBuf};
use std::process;

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
                "Link-Ziel '{}' (verwiesen von '{}') nicht im Archiv oder ungültig.",
                    target_ref, p
            )
        })?;
    }
    Ok(entry)
}

/// Schreibt einen beliebigen Read-Stream mit hartem Größenlimit in eine temporäre Datei
/// (sofort mit 0600-Rechten erstellt), prüft den SHA-256-Hash und benennt die Datei
/// erst bei Erfolg atomar um.
fn write_stream_verified<R: Read>(
    mut reader: R,
    target: &Path,
    expected_hash: Option<&str>,
    max_bytes: u64,
    mode: Option<u32>,
    force: bool,
        tmp_id: usize,
) -> Result<(), String> {
    if let Ok(existing_meta) = fs::symlink_metadata(target) {
        if existing_meta.file_type().is_dir() {
            return Err("Am Zielort existiert bereits ein Ordner".to_string());
        }
        if !force {
            return Err(
                "Datei existiert bereits (nutze '-f' / '--force' zum Überschreiben)".to_string(),
            );
        }
    }

    let parent = target
    .parent()
    .ok_or_else(|| "Ungültiger Zielpfad ohne Elternordner".to_string())?;
    let tmp_path = parent.join(format!(
        ".folder2json.tmp.{}.{}",
        process::id(),
                                       tmp_id
    ));

    let mut write_and_hash = || -> Result<String, String> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        options.mode(0o600); // Unter Linux/Unix sofort mit 0600 anlegen

        let f = options
        .open(&tmp_path)
        .map_err(|e| format!("Konnte temporäre Datei nicht anlegen: {}", e))?;

        let mut writer = BufWriter::new(f);
        let mut hasher = Sha256::new();
        let mut total_written: u64 = 0;
        let mut buf = [0u8; STREAM_COPY_CHUNK];

        loop {
            let n = reader
            .read(&mut buf)
            .map_err(|e| format!("Stream-Lesefehler: {}", e))?;
            if n == 0 {
                break;
            }
            total_written = total_written.saturating_add(n as u64);
            if total_written > max_bytes {
                return Err(format!(
                    "Dekompressionsbombe / Größenlimit überschritten (> {} MiB, anpassbar via '--max-size-mib')",
                                   max_bytes / (1024 * 1024)
                ));
            }
            hasher.update(&buf[..n]);
            writer
            .write_all(&buf[..n])
            .map_err(|e| format!("Schreibfehler: {}", e))?;
        }

        writer.flush().map_err(|e| format!("Flush-Fehler: {}", e))?;
        let digest: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
        Ok(digest.chars().take(16).collect())
    };

    let actual_short = match write_and_hash() {
        Ok(h) => h,
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
    };

    if let Some(expected) = expected_hash {
        if actual_short != expected {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!(
                "Hash-Mismatch! Erwartet: {}, Erhalten: {}",
                expected, actual_short
            ));
        }
    }

    #[cfg(unix)]
    {
        let raw_mode = mode.unwrap_or(0o644);
        if raw_mode & !0o777 != 0 {
            eprintln!(
                "⚠️  SICHERHEITSHINWEIS: Spezial-Bits (SUID/SGID/Sticky: {:o}) wurden entfernt.",
                      raw_mode
            );
        }
        let safe_mode = raw_mode & 0o777;
        if let Err(e) = fs::set_permissions(&tmp_path, Permissions::from_mode(safe_mode)) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("Konnte Berechtigungen nicht setzen: {}", e));
        }
    }

    if let Err(e) = fs::rename(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("Atomares Umbenennen fehlgeschlagen: {}", e));
    }

    Ok(())
}

pub fn unpack(
    in_arg: &str,
    dst: &Path,
    force: bool,
        verbose: bool,
        no_verify: bool,
        allow_external_symlinks: bool,
        max_size_mib: u64,
        max_archive_mib: u64,
) -> Result<(usize, usize, Vec<String>), String> {
    let max_decompressed_bytes = max_size_mib.saturating_mul(1024 * 1024);
    let max_archive_bytes = max_archive_mib.saturating_mul(1024 * 1024);

    let doc: ArchiveDoc = if in_arg == "-" {
        let stdin = io::stdin();
        let bounded = BufReader::new(stdin.lock()).take(max_archive_bytes.saturating_add(1));
        serde_json::from_reader(bounded).map_err(|e| {
            format!(
                "Ungültiges JSON oder Archiv überschreitet Limit von {} MiB ('--max-archive-mib'): {}",
                    max_archive_mib, e
            )
        })?
    } else {
        let in_resolved = fs::canonicalize(Path::new(in_arg))
        .map_err(|e| format!("Kann '{}' nicht öffnen: {}", in_arg, e))?;
        let meta = fs::metadata(&in_resolved).map_err(|e| {
            format!(
                "Kann Metadaten von '{}' nicht lesen: {}",
                in_resolved.display(),
                    e
            )
        })?;
        if meta.len() > max_archive_bytes {
            return Err(format!(
                "Archiv '{}' ({}) überschreitet das Limit von {} MiB (anpassbar via '--max-archive-mib').",
                               in_resolved.display(),
                               fmt_size(meta.len()),
                               max_archive_mib
            ));
        }
        let file = File::open(&in_resolved)
        .map_err(|e| format!("Fehler beim Öffnen von '{}': {}", in_resolved.display(), e))?;
        serde_json::from_reader(BufReader::new(file))
        .map_err(|e| format!("Ungültiges JSON: {}", e))?
    };

    fs::create_dir_all(dst)
    .map_err(|e| format!("Kann Zielordner '{}' nicht erstellen: {}", dst.display(), e))?;
    let dst_canon = fs::canonicalize(dst)
    .map_err(|e| format!("Kann Zielordner '{}' nicht kanonisieren: {}", dst.display(), e))?;

    let mut failed_files = Vec::new();
    let mut seen_clean_paths: HashSet<PathBuf> = HashSet::new();
    let mut validated_paths: Vec<Option<PathBuf>> = Vec::with_capacity(doc.files.len());
    let mut by_path: HashMap<&str, &ArchiveEntry> = HashMap::new();
    let mut symlink_map: HashMap<PathBuf, String> = HashMap::new();

    // Pre-Pass A: Grundlegende Pfad-Validierung & Duplikat-Filter
    for entry in &doc.files {
        match validate_safe_rel_path(&entry.path) {
            Ok(clean_rel) => {
                if !seen_clean_paths.insert(clean_rel.clone()) {
                    let msg = "Duplizierter Pfad im Archiv (wird übersprungen)".to_string();
                    eprintln!("❌ Übersprungen: '{}' ({})", entry.path, msg);
                    failed_files.push(format!("'{}': {}", entry.path, msg));
                    validated_paths.push(None);
                    continue;
                }
                if entry.entry_type == "symlink" {
                    let sym_target = entry.target.as_deref().unwrap_or("").to_string();
                    symlink_map.insert(clean_rel.clone(), sym_target);
                }
                by_path.insert(entry.path.as_str(), entry);
                validated_paths.push(Some(clean_rel));
            }
            Err(e) => {
                eprintln!("❌ Übersprungen: '{}' ({})", entry.path, e);
                failed_files.push(format!("'{}': {}", entry.path, e));
                validated_paths.push(None);
            }
        }
    }

    // Pre-Pass B: Verkettete Symlinks & Symlink-Elternverzeichnisse (im Archiv UND auf Disk) prüfen
    for (entry, clean_rel_opt) in doc.files.iter().zip(validated_paths.iter_mut()) {
        let clean_rel = match clean_rel_opt {
            Some(ref p) => p.clone(),
            None => continue,
        };

        let mut ancestor = PathBuf::new();
        if let Some(parent) = clean_rel.parent() {
            let mut through_symlink = false;
            for comp in parent.components() {
                if let Component::Normal(c) = comp {
                    ancestor.push(c);
                    let disk_ancestor = dst_canon.join(&ancestor);
                    let is_disk_symlink = fs::symlink_metadata(&disk_ancestor)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false);
                    if symlink_map.contains_key(&ancestor) || is_disk_symlink {
                        through_symlink = true;
                        break;
                    }
                }
            }
            if through_symlink {
                let msg = format!(
                    "Pfad verläuft durch einen Symlink ('{}') – blockiert!",
                                  ancestor.display()
                );
                eprintln!("❌ Übersprungen: '{}' ({})", entry.path, msg);
                failed_files.push(format!("'{}': {}", entry.path, msg));
                by_path.remove(entry.path.as_str());
                *clean_rel_opt = None;
                continue;
            }
        }

        if entry.entry_type == "symlink" {
            let sym_target = entry.target.as_deref().unwrap_or("");
            if let Err(e) = validate_symlink_target_graph(
                &dst_canon,
                &clean_rel,
                sym_target,
                &symlink_map,
                allow_external_symlinks,
            ) {
                eprintln!("❌ Übersprungen (Symlink): '{}' ({})", entry.path, e);
                failed_files.push(format!("'{}': {}", entry.path, e));
                symlink_map.remove(&clean_rel);
                by_path.remove(entry.path.as_str());
                *clean_rel_opt = None;
            }
        }
    }

    let mut file_count = 0usize;
    let mut link_count = 0usize;
    let mut extracted_canon_paths: HashMap<&str, PathBuf> = HashMap::new();

    // Pass 1: Kanonische Dateien (text & binary) streamend direkt auf die Platte entpacken
    for (idx, (entry, clean_rel_opt)) in doc.files.iter().zip(validated_paths.iter()).enumerate() {
        let clean_rel = match clean_rel_opt {
            Some(p) => p,
            None => continue,
        };

        let t = entry.entry_type.as_str();
        if t == "symlink" || t == "link" {
            continue;
        }

        let process_canonical = || -> Result<PathBuf, String> {
            let expected_hash = if !no_verify {
                let h = entry
                .hash
                .as_deref()
                .ok_or_else(|| "Fehlender SHA-256-Hash".to_string())?;
                if !is_valid_short_sha256(h) {
                    return Err(format!("Ungültiges Hash-Format ('{}')", h));
                }
                Some(h)
            } else {
                None
            };

            let target = ensure_safe_parent_dirs(&dst_canon, clean_rel)?;

            if t == "text" {
                let text_bytes = entry.content.as_deref().unwrap_or("").as_bytes();
                write_stream_verified(
                    text_bytes,
                    &target,
                    expected_hash,
                    max_decompressed_bytes,
                    entry.mode,
                    force,
                        idx,
                )?;
            } else if t == "binary" {
                let raw_b64 = entry.content.as_deref().unwrap_or("").as_bytes();
                let encodings = entry
                .encoding
                .as_deref()
                .ok_or_else(|| "Fehlendes 'encoding'-Array".to_string())?;

                if encodings.is_empty() || encodings.len() > MAX_ENCODING_STEPS {
                    return Err(format!("Ungültige Encoding-Länge ({})", encodings.len()));
                }

                match encodings {
                    [b64] if b64 == "base64" => {
                        let b64_reader = Base64SliceReader::new(raw_b64);
                        write_stream_verified(
                            b64_reader,
                            &target,
                            expected_hash,
                            max_decompressed_bytes,
                            entry.mode,
                            force,
                                idx,
                        )?;
                    }
                    [zst, b64] if zst == "zstd" && b64 == "base64" => {
                        let b64_reader = Base64SliceReader::new(raw_b64);
                        let zstd_decoder = zstd::Decoder::new(b64_reader)
                        .map_err(|e| format!("Zstd-Init-Fehler: {}", e))?;
                        write_stream_verified(
                            zstd_decoder,
                            &target,
                            expected_hash,
                            max_decompressed_bytes,
                            entry.mode,
                            force,
                                idx,
                        )?;
                    }
                    _ => {
                        return Err(format!(
                            "Nicht unterstützte Encoding-Pipeline: {:?}",
                            encodings
                        ));
                    }
                }
            } else {
                return Err(format!("Unbekannter Dateityp '{}'", t));
            }

            Ok(target)
        };

        match process_canonical() {
            Ok(target_path) => {
                extracted_canon_paths.insert(entry.path.as_str(), target_path);
                file_count += 1;
                if verbose {
                    println!("  F {}", entry.path);
                }
            }
            Err(e) => {
                eprintln!("❌ Übersprungen: '{}' ({})", entry.path, e);
                failed_files.push(format!("'{}': {}", entry.path, e));
            }
        }
    }

    // Pass 2: Deduplizierte Links direkt von der bereits verifizierten Originaldatei streamen
    for (idx, (entry, clean_rel_opt)) in doc.files.iter().zip(validated_paths.iter()).enumerate() {
        let clean_rel = match clean_rel_opt {
            Some(p) => p,
            None => continue,
        };

        if entry.entry_type != "link" {
            continue;
        }

        let process_link = || -> Result<&str, String> {
            let resolved = resolve_link(&by_path, entry)?;
            let canon_disk_path = extracted_canon_paths
            .get(resolved.path.as_str())
            .ok_or_else(|| {
                format!(
                    "Originaldatei '{}' konnte zuvor nicht entpackt werden",
                    resolved.path
                )
            })?;

            let expected_hash = if !no_verify {
                let eh = match (entry.hash.as_deref(), resolved.hash.as_deref()) {
                    (Some(eh), Some(rh)) if eh != rh => {
                        return Err(format!("Inkonsistenter Link-Hash ({} != {})", eh, rh));
                    }
                    (Some(eh), _) => eh,
                    (None, Some(rh)) => rh,
                    (None, None) => return Err("Fehlender SHA-256-Hash".to_string()),
                };
                if !is_valid_short_sha256(eh) {
                    return Err(format!("Ungültiges Hash-Format ('{}')", eh));
                }
                Some(eh)
            } else {
                None
            };

            let target = ensure_safe_parent_dirs(&dst_canon, clean_rel)?;
            let src_file = File::open(canon_disk_path).map_err(|e| {
                format!(
                    "Konnte extrahierte Originaldatei '{}' nicht öffnen: {}",
                    resolved.path, e
                )
            })?;

            write_stream_verified(
                BufReader::new(src_file),
                                  &target,
                                  expected_hash,
                                  max_decompressed_bytes,
                                  entry.mode.or(resolved.mode),
                                  force,
                                      idx,
            )?;

            Ok(resolved.path.as_str())
        };

        match process_link() {
            Ok(canon_rel) => {
                link_count += 1;
                file_count += 1;
                if verbose {
                    println!("  → {} (← {})", entry.path, canon_rel);
                }
            }
            Err(e) => {
                eprintln!("❌ Übersprungen (Link): '{}' ({})", entry.path, e);
                failed_files.push(format!("'{}': {}", entry.path, e));
            }
        }
    }

    // Pass 3: Symlinks anlegen
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
                    return Err("Am Zielort existiert bereits ein Ordner".to_string());
                }
                if !force {
                    return Err(
                        "Ziel existiert bereits (nutze '-f' / '--force' zum Überschreiben)"
                        .to_string(),
                    );
                }
                fs::remove_file(&target)
                .map_err(|e| format!("Konnte bestehende Datei nicht entfernen: {}", e))?;
            }

            let sym_target = entry.target.as_deref().unwrap_or("");
            symlink(sym_target, &target)
            .map_err(|e| format!("Erstellen fehlgeschlagen: {}", e))?;
            Ok(())
        };

        match process_symlink() {
            Ok(()) => {
                file_count += 1;
                if verbose {
                    println!(
                        "  L {} -> {}",
                        entry.path,
                        entry.target.as_deref().unwrap_or("")
                    );
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
