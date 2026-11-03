use std::path::Path;

/// Iterative Glob-Matching-Engine in O(N * M) ohne ReDoS-Backtracking-Risiko
pub fn fnmatch(text: &str, pat: &str) -> bool {
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

pub fn path_to_posix(path: &Path) -> String {
    path.components()
    .map(|c| c.as_os_str().to_string_lossy())
    .collect::<Vec<_>>()
    .join("/")
}

pub fn matches_exclude(rel_path: &Path, excludes: &[String]) -> bool {
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
