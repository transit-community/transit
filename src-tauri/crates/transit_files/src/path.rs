//! Remote **POSIX** path helpers.
//!
//! SFTP paths are always `/`-separated regardless of what OS Transit runs
//! on, so remote paths are manipulated as strings and NEVER through
//! `std::path` — on Windows `Path::join` would emit `\` separators and
//! `Path::parent` would treat `C:` as a prefix, silently corrupting a
//! remote path. (`crate::localfs` is the only module that may use
//! `std::path`, because there the platform IS the local one.)
//!
//! Deliberately does NOT resolve `.` / `..` segments: the SFTP server
//! canonicalizes (`SSH_FXP_REALPATH`) and the listing echoes that answer
//! back, so resolving them here could only ever disagree with the device.

/// Collapse repeated separators and drop a trailing separator.
/// `""` → `"."` (the SFTP "current directory" spelling); `"/"` stays `"/"`.
pub fn normalize(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let absolute = path.starts_with('/');
    let mut out = String::with_capacity(path.len());
    if absolute {
        out.push('/');
    }
    let mut first = true;
    for segment in path.split('/').filter(|s| !s.is_empty()) {
        if !first {
            out.push('/');
        }
        out.push_str(segment);
        first = false;
    }
    if out.is_empty() {
        // Input was all separators (`"///"`).
        return "/".to_string();
    }
    out
}

/// Join a single component onto a directory path. An absolute `name`
/// wins (it is already a full path); otherwise the result is
/// `normalize("{base}/{name}")`.
pub fn join(base: &str, name: &str) -> String {
    if name.starts_with('/') {
        return normalize(name);
    }
    if base.is_empty() {
        return normalize(name);
    }
    normalize(&format!("{base}/{name}"))
}

/// The parent directory, or `None` when there isn't one (`"/"`, or a
/// bare relative component like `"file.txt"`).
pub fn parent(path: &str) -> Option<String> {
    let normalized = normalize(path);
    if normalized == "/" || normalized == "." {
        return None;
    }
    match normalized.rfind('/') {
        Some(0) => Some("/".to_string()),
        Some(idx) => Some(normalized[..idx].to_string()),
        None => None,
    }
}

/// The final component. `""` for `"/"`.
pub fn basename(path: &str) -> String {
    let normalized = normalize(path);
    if normalized == "/" {
        return String::new();
    }
    match normalized.rfind('/') {
        Some(idx) => normalized[idx + 1..].to_string(),
        None => normalized,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_collapses_and_trims() {
        assert_eq!(normalize("/var//log/"), "/var/log");
        assert_eq!(normalize("/"), "/");
        assert_eq!(normalize("///"), "/");
        assert_eq!(normalize(""), ".");
        assert_eq!(normalize("config/juniper.conf"), "config/juniper.conf");
        assert_eq!(normalize("/a/"), "/a");
    }

    #[test]
    fn normalize_keeps_dot_segments_for_the_server_to_resolve() {
        // We never pretend to know the server's canonical answer.
        assert_eq!(normalize("/var/log/../tmp"), "/var/log/../tmp");
        assert_eq!(normalize("."), ".");
    }

    #[test]
    fn join_appends_one_component() {
        assert_eq!(join("/var/log", "messages"), "/var/log/messages");
        assert_eq!(join("/", "etc"), "/etc");
        assert_eq!(join("/var/", "log"), "/var/log");
        assert_eq!(join("", "etc"), "etc");
    }

    #[test]
    fn join_lets_an_absolute_name_win() {
        assert_eq!(join("/var/log", "/etc/passwd"), "/etc/passwd");
    }

    #[test]
    fn parent_walks_up_to_root_then_stops() {
        assert_eq!(parent("/var/log/messages").as_deref(), Some("/var/log"));
        assert_eq!(parent("/var").as_deref(), Some("/"));
        assert_eq!(parent("/"), None);
        assert_eq!(parent("messages"), None);
        assert_eq!(parent("a/b").as_deref(), Some("a"));
    }

    #[test]
    fn basename_takes_the_final_component() {
        assert_eq!(basename("/var/log/messages"), "messages");
        assert_eq!(basename("/var/log/"), "log");
        assert_eq!(basename("/"), "");
        assert_eq!(basename("messages"), "messages");
    }
}
