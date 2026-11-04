use crate::constants::MAX_SYMLINK_HOPS;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

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

pub fn validate_safe_rel_path(raw_path: &str) -> Result<PathBuf, String> {
    if raw_path.is_empty() {
        return Err("Empty file path encountered in archive!".to_string());
    }

    if raw_path.contains('\0') || raw_path.contains('\\') {
        return Err(
            "Dangerous path characters (backslash '\\' or null byte) blocked.".to_string(),
        );
    }

    if raw_path.starts_with('/') || raw_path.starts_with('~') {
        return Err("Absolute path ('/') or home directory reference ('~') blocked.".to_string());
    }

    let mut clean = PathBuf::new();
    for comp in Path::new(raw_path).components() {
        match comp {
            Component::Normal(os_str) => {
                let part = os_str.to_string_lossy();
                if part.is_empty() || part == "~" || part.starts_with('~') {
                    return Err(format!("Dangerous path component ('{}') detected.", part));
                }
                clean.push(os_str);
            }
            Component::ParentDir => {
                return Err("Path traversal attempt ('..') blocked.".to_string());
            }
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {
                return Err("Invalid path structure ('.', '/') blocked.".to_string());
            }
        }
    }

    if clean.as_os_str().is_empty() {
        return Err("Path resolves to an empty destination!".to_string());
    }

    Ok(clean)
}

pub fn validate_symlink_target_graph(
    dst_canon: &Path,
    entry_clean_rel: &Path,
    sym_target: &str,
    symlink_map: &HashMap<PathBuf, String>,
    allow_external: bool,
) -> Result<(), String> {
    if sym_target.is_empty() || sym_target.contains('\0') {
        return Err("Invalid or empty symlink target!".to_string());
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
                return Err("Symlink escape (absolute path, '\\' or '~') blocked.".to_string());
            }
            let mut tokens = Vec::new();
        for comp in Path::new(t).components() {
            match comp {
                Component::Normal(c) => {
                    let s = c.to_string_lossy();
                    if s == "~" || s.starts_with('~') {
                        return Err("Tilde '~' inside symlink target blocked.".to_string());
                    }
                    tokens.push(s.into_owned());
                }
                Component::CurDir => {}
                Component::ParentDir => tokens.push("..".to_string()),
                Component::RootDir | Component::Prefix(_) => {
                    return Err("Root/Prefix reference inside symlink blocked.".to_string());
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
                    "Symlink traversal ('..') escapes target directory scope.".to_string(),
                );
            }
        } else {
            current_stack.push(token);
            let current_rel: PathBuf = current_stack.iter().collect();

            let nested_target_opt: Option<String> = if let Some(t) = symlink_map.get(&current_rel) {
                Some(t.clone())
            } else {
                let disk_path = dst_canon.join(&current_rel);
                if let Ok(meta) = fs::symlink_metadata(&disk_path) {
                    if meta.file_type().is_symlink() {
                        let link_dest = fs::read_link(&disk_path).map_err(|e| {
                            format!(
                                "Existing destination symlink '{}' cannot be read: {}",
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
                        "Cyclic symlink chain (too many symlink hops) blocked.".to_string(),
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
                                "Symlink traversal blocked: parent directory '{}' is a symlink!",
                                current.display()
                            ));
                        }
                        if !meta.file_type().is_dir() {
                            return Err(format!(
                                "Extraction conflict: '{}' already exists and is not a directory.",
                                current.display()
                            ));
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        fs::create_dir(&current).map_err(|err| {
                            format!(
                                "Failed to create parent directory '{}': {}",
                                current.display(),
                                    err
                            )
                        })?;
                    }
                    Err(e) => {
                        return Err(format!(
                            "Failed to inspect directory '{}': {}",
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
            "Failed to canonicalize directory '{}': {}",
            current.display(),
                e
        )
    })?;

    if !canon_parent.starts_with(dst_canon) {
        return Err(format!(
            "Target path '{}' escapes destination root '{}'!",
            canon_parent.display(),
                           dst_canon.display()
        ));
    }

    Ok(canon_parent.join(clean_rel.file_name().unwrap()))
}

pub fn is_valid_short_sha256(h: &str) -> bool {
    h.len() == 16 && h.chars().all(|c| c.is_ascii_hexdigit())
}
