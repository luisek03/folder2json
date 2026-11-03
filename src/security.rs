use crate::constants::MAX_SYMLINK_HOPS;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

/// Erkennt potenziell sensible Konfigurations-, Schlüssel- und Zugangsdateien,
/// wenn der Nutzer z. B. mit `-a` versteckte Dateien einschließt.
pub fn is_potentially_sensitive(rel_posix: &str) -> bool {
    let lower_rel = rel_posix.to_lowercase();
    let path = Path::new(&lower_rel);

    let file_name = path
    .file_name()
    .map(|f| f.to_string_lossy())
    .unwrap_or_default();

    for comp in path.components() {
        if let Component::Normal(c) = comp {
            let s = c.to_string_lossy();
            if s == ".ssh" || s == ".aws" || s == ".gnupg" {
                return true;
            }
        }
    }

    if lower_rel == ".git/config" || lower_rel.ends_with("/.git/config") {
        return true;
    }

    matches!(
        file_name.as_ref(),
             ".env"
             | ".netrc"
             | ".git-credentials"
             | ".npmrc"
             | ".pypirc"
             | "id_rsa"
             | "id_ed25519"
             | "id_ecdsa"
             | "id_dsa"
             | "credentials"
    ) || file_name.starts_with(".env.")
    || file_name.starts_with("secrets.")
    || file_name.starts_with("secret.")
    || file_name.ends_with(".pem")
    || file_name.ends_with(".key")
    || file_name.ends_with(".p12")
    || file_name.ends_with(".pfx")
    || file_name.ends_with(".kdbx")
    || file_name.ends_with(".age")
}

/// Prüft strikt, dass ein Archiv-Pfad relativ bleibt und keinerlei Path-Traversal enthält.
pub fn validate_safe_rel_path(raw_path: &str) -> Result<PathBuf, String> {
    if raw_path.is_empty() {
        return Err("Leerer Dateipfad im Archiv erkannt!".to_string());
    }

    if raw_path.contains('\0') || raw_path.contains('\\') {
        return Err(
            "Gefährliche Pfad-Manipulation (Backslash '\\' oder Null-Byte) blockiert.".to_string(),
        );
    }

    if raw_path.starts_with('/') || raw_path.starts_with('~') {
        return Err("Absolute Pfade ('/') oder Home-Referenzen ('~') blockiert.".to_string());
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

/// Simuliert die Betriebssystem-Auflösung eines Symlinks innerhalb von `dst_canon`
/// unter Berücksichtigung sowohl aller Archiv-Symlinks (`symlink_map`) als auch
/// bereits im Zielordner auf der Festplatte existierender Symlinks!
pub fn validate_symlink_target_graph(
    dst_canon: &Path,
    entry_clean_rel: &Path,
    sym_target: &str,
    symlink_map: &HashMap<PathBuf, String>,
    allow_external: bool,
) -> Result<(), String> {
    if sym_target.is_empty() || sym_target.contains('\0') {
        return Err("Ungültiges/leeres Symlink-Ziel!".to_string());
    }

    if allow_external {
        return Ok(());
    }

    let check_raw_target = |t: &str| -> Result<Vec<String>, String> {
        if t.is_empty()
            || t.contains('\0')
            || t.contains('\\')
            || t.starts_with('/')
            || t.starts_with('~')
            {
                return Err("Symlink-Escape (absoluter Pfad, '\\' oder '~') blockiert.".to_string());
            }
            let mut tokens = Vec::new();
        for comp in Path::new(t).components() {
            match comp {
                Component::Normal(c) => {
                    let s = c.to_string_lossy();
                    if s == "~" || s.starts_with('~') {
                        return Err("Tilde '~' im Symlink-Ziel blockiert.".to_string());
                    }
                    tokens.push(s.into_owned());
                }
                Component::CurDir => {}
                Component::ParentDir => tokens.push("..".to_string()),
                Component::RootDir | Component::Prefix(_) => {
                    return Err("Root/Prefix-Referenz im Symlink blockiert.".to_string());
                }
            }
        }
        Ok(tokens)
    };

    let mut current_stack: Vec<String> = Vec::new();
    if let Some(parent) = entry_clean_rel.parent() {
        for comp in parent.components() {
            if let Component::Normal(c) = comp {
                current_stack.push(c.to_string_lossy().into_owned());
            }
        }
    }

    let mut work: Vec<String> = check_raw_target(sym_target)?.into_iter().rev().collect();
    let mut hops = 0usize;

    while let Some(token) = work.pop() {
        if token == ".." {
            if current_stack.pop().is_none() {
                return Err(
                    "Symlink-Traversal ('..') verlässt (direkt oder über verkettete Symlinks) den Zielordner-Scope."
                    .to_string(),
                );
            }
        } else {
            current_stack.push(token);
            let current_rel: PathBuf = current_stack.iter().collect();

            // Prüfe sowohl Archiv-Symlinks als auch bereits im Zielordner liegende Symlinks
            let nested_target_opt: Option<String> = if let Some(t) = symlink_map.get(&current_rel) {
                Some(t.clone())
            } else {
                let disk_path = dst_canon.join(&current_rel);
                if let Ok(meta) = fs::symlink_metadata(&disk_path) {
                    if meta.file_type().is_symlink() {
                        let link_dest = fs::read_link(&disk_path).map_err(|e| {
                            format!(
                                "Bestehender Symlink '{}' im Zielordner nicht lesbar: {}",
                                current_rel.display(),
                                    e
                            )
                        })?;
                        Some(link_dest.to_string_lossy().into_owned())
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            if let Some(nested_target) = nested_target_opt {
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    return Err(
                        "Zyklische Symlink-Kette (zu viele Symlink-Hops) blockiert.".to_string(),
                    );
                }
                current_stack.pop();
                let nested_tokens = check_raw_target(&nested_target)?;
                for nt in nested_tokens.into_iter().rev() {
                    work.push(nt);
                }
            }
        }
    }

    Ok(())
}

/// Erstellt Elternverzeichnisse Komponente für Komponente und stellt sicher,
/// dass kein einziger Ordner auf dem Pfad ein Symlink ist.
pub fn ensure_safe_parent_dirs(dst_canon: &Path, clean_rel: &Path) -> Result<PathBuf, String> {
    let mut current = dst_canon.to_path_buf();

    if let Some(parent) = clean_rel.parent() {
        for comp in parent.components() {
            if let Component::Normal(c) = comp {
                current.push(c);
                match fs::symlink_metadata(&current) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() {
                            return Err(format!(
                                "Symlink-Traversal blockiert: Elternverzeichnis '{}' ist ein Symlink!",
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
            "Zielpfad '{}' liegt außerhalb des Zielordners '{}'!",
            canon_parent.display(),
                           dst_canon.display()
        ));
    }

    Ok(canon_parent.join(clean_rel.file_name().unwrap()))
}

pub fn is_valid_short_sha256(h: &str) -> bool {
    h.len() == 16 && h.chars().all(|c| c.is_ascii_hexdigit())
}
