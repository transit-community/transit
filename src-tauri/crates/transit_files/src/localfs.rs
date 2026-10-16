//! The local pane: `std::fs` inside `spawn_blocking`.
//!
//! Deliberately NOT `tauri-plugin-fs` — that plugin is absent from the
//! project and the capability surface grants only `dialog:allow-open` /
//! `dialog:allow-save`; it stays that way (plan §5). Every local operation
//! is a Rust-side command with the same authority the user already has in
//! Finder/Explorer, reached only through human-driven `files_local_*` IPC.
//!
//! Blocking `std::fs` in `spawn_blocking` rather than `tokio::fs`: a
//! directory listing does one `read_dir` plus one `symlink_metadata` per
//! entry, and `tokio::fs` would round-trip to the blocking pool for each
//! of those calls individually.

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::error::FilesError;
use crate::types::{DirListing, EntryKind, FileEntry, LocalRoot};

fn local_err(op: &'static str, path: &Path, e: impl std::fmt::Display) -> FilesError {
    FilesError::Local {
        op,
        path: path.display().to_string(),
        detail: e.to_string(),
    }
}

/// Display form of a local path.
///
/// On Windows `canonicalize` returns a `\\?\C:\…` verbatim path, which is
/// correct but unreadable in a path bar (and users can't type it back), so
/// the prefix is stripped for display. The stripped form still round-trips
/// through every `std::fs` call.
fn display_path(path: &Path) -> String {
    let raw = path.display().to_string();
    #[cfg(windows)]
    {
        if let Some(stripped) = raw.strip_prefix(r"\\?\") {
            // Leave UNC verbatim paths (`\\?\UNC\server\share`) alone —
            // stripping the prefix there would produce an invalid path.
            if !stripped.starts_with("UNC\\") {
                return stripped.to_string();
            }
        }
    }
    raw
}

/// The user's home directory — the local pane's default location.
pub fn home() -> Result<String, FilesError> {
    let dir = dirs::home_dir().ok_or_else(|| FilesError::Local {
        op: "resolve home",
        path: String::new(),
        detail: "the OS did not report a home directory".to_string(),
    })?;
    Ok(display_path(&dir))
}

/// Roots for the local pane's picker: home and `/` always, plus existing
/// drive letters on Windows. (`/Volumes` enumeration is a later item.)
pub async fn roots() -> Result<Vec<LocalRoot>, FilesError> {
    tokio::task::spawn_blocking(roots_blocking)
        .await
        .map_err(|e| FilesError::Local {
            op: "list roots",
            path: String::new(),
            detail: e.to_string(),
        })
}

fn roots_blocking() -> Vec<LocalRoot> {
    let mut out = Vec::new();
    if let Some(home) = dirs::home_dir() {
        out.push(LocalRoot {
            path: display_path(&home),
            label: "Home".to_string(),
        });
    }
    #[cfg(windows)]
    {
        for letter in b'A'..=b'Z' {
            let path = format!("{}:\\", letter as char);
            if Path::new(&path).is_dir() {
                out.push(LocalRoot {
                    path: path.clone(),
                    label: format!("{} ({}:)", "Local disk", letter as char),
                });
            }
        }
    }
    #[cfg(not(windows))]
    {
        out.push(LocalRoot {
            path: "/".to_string(),
            label: "Filesystem root".to_string(),
        });
    }
    out
}

/// List a local directory (home when `path` is `None`).
///
/// Returns **every** entry including dotfiles — hiding them is a frontend
/// toggle, so the backend must not decide. `max_entries` bounds the IPC
/// payload the same way the remote listing does.
pub async fn list_dir(path: Option<&str>, max_entries: usize) -> Result<DirListing, FilesError> {
    let target = match path {
        Some(p) if !p.trim().is_empty() => PathBuf::from(p),
        _ => PathBuf::from(home()?),
    };
    tokio::task::spawn_blocking(move || list_dir_blocking(&target, max_entries))
        .await
        .map_err(|e| FilesError::Local {
            op: "list",
            path: String::new(),
            detail: e.to_string(),
        })?
}

fn list_dir_blocking(target: &Path, max_entries: usize) -> Result<DirListing, FilesError> {
    // Canonicalize so the path bar shows what we actually read (and so
    // `..` navigation resolves) — the same contract as the remote pane.
    let canonical = std::fs::canonicalize(target).map_err(|e| local_err("list", target, e))?;
    if !canonical.is_dir() {
        return Err(local_err("list", &canonical, "not a directory".to_string()));
    }
    let read = std::fs::read_dir(&canonical).map_err(|e| local_err("list", &canonical, e))?;

    let mut entries = Vec::new();
    let mut truncated = false;
    for item in read {
        if entries.len() >= max_entries {
            truncated = true;
            break;
        }
        let Ok(item) = item else { continue };
        let name = item.file_name().to_string_lossy().into_owned();
        // `symlink_metadata` (not `metadata`): a link must render as a
        // link, and a dangling link must still render at all.
        let meta = match std::fs::symlink_metadata(item.path()) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let file_type = meta.file_type();
        let kind = if file_type.is_symlink() {
            EntryKind::Symlink
        } else if file_type.is_dir() {
            EntryKind::Dir
        } else if file_type.is_file() {
            EntryKind::File
        } else {
            EntryKind::Other
        };
        entries.push(FileEntry {
            name,
            kind,
            size: Some(meta.len()),
            mtime: mtime_secs(&meta),
            perms: perms_string(&meta),
            symlink_target: None,
        });
    }

    Ok(DirListing {
        parent: canonical.parent().map(display_path),
        path: display_path(&canonical),
        entries,
        truncated,
    })
}

fn mtime_secs(meta: &std::fs::Metadata) -> Option<i64> {
    meta.modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}

/// `"rwxr-xr-x"` from POSIX mode bits. `None` on Windows, which has no
/// mode — the column renders empty rather than inventing one.
fn perms_string(meta: &std::fs::Metadata) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        let bit = |shift: u32, ch: char| {
            if mode & (1 << shift) != 0 {
                ch
            } else {
                '-'
            }
        };
        Some(
            [
                bit(8, 'r'),
                bit(7, 'w'),
                bit(6, 'x'),
                bit(5, 'r'),
                bit(4, 'w'),
                bit(3, 'x'),
                bit(2, 'r'),
                bit(1, 'w'),
                bit(0, 'x'),
            ]
            .iter()
            .collect(),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

pub async fn mkdir(path: &str) -> Result<(), FilesError> {
    let target = PathBuf::from(path);
    tokio::task::spawn_blocking(move || {
        std::fs::create_dir(&target).map_err(|e| local_err("mkdir", &target, e))
    })
    .await
    .map_err(|e| FilesError::Local {
        op: "mkdir",
        path: path.to_string(),
        detail: e.to_string(),
    })?
}

/// Create a directory and any missing parents. Used by the recursive
/// download walker (and idempotent, unlike [`mkdir`]).
pub(crate) async fn mkdir_all(path: &Path) -> Result<(), FilesError> {
    let target = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        std::fs::create_dir_all(&target).map_err(|e| local_err("mkdir", &target, e))
    })
    .await
    .map_err(|e| FilesError::Local {
        op: "mkdir",
        path: path.display().to_string(),
        detail: e.to_string(),
    })?
}

pub async fn rename(from: &str, to: &str) -> Result<(), FilesError> {
    let src = PathBuf::from(from);
    let dst = PathBuf::from(to);
    tokio::task::spawn_blocking(move || {
        std::fs::rename(&src, &dst).map_err(|e| local_err("rename", &src, e))
    })
    .await
    .map_err(|e| FilesError::Local {
        op: "rename",
        path: from.to_string(),
        detail: e.to_string(),
    })?
}

/// Delete a local path. `recursive` is required for a non-empty directory.
///
/// **Never deletes through a symlink.** If the target itself is a link,
/// the link is removed and its target tree is untouched — `remove_dir_all`
/// on a symlinked directory would otherwise wipe whatever it points at
/// (which may be nowhere near what the user selected). `remove_dir_all`'s
/// own recursion does not follow links either.
pub async fn delete(path: &str, recursive: bool) -> Result<(), FilesError> {
    let target = PathBuf::from(path);
    tokio::task::spawn_blocking(move || delete_blocking(&target, recursive))
        .await
        .map_err(|e| FilesError::Local {
            op: "delete",
            path: path.to_string(),
            detail: e.to_string(),
        })?
}

fn delete_blocking(target: &Path, recursive: bool) -> Result<(), FilesError> {
    let meta = std::fs::symlink_metadata(target).map_err(|e| local_err("delete", target, e))?;
    if meta.file_type().is_symlink() {
        // On Windows a directory symlink/junction must be removed with
        // `remove_dir`; on Unix `remove_file` unlinks either kind.
        return match std::fs::remove_file(target) {
            Ok(()) => Ok(()),
            Err(e) => {
                #[cfg(windows)]
                if std::fs::remove_dir(target).is_ok() {
                    return Ok(());
                }
                Err(local_err("delete", target, e))
            }
        };
    }
    if meta.is_dir() {
        return if recursive {
            std::fs::remove_dir_all(target).map_err(|e| local_err("delete", target, e))
        } else {
            std::fs::remove_dir(target).map_err(|e| local_err("delete", target, e))
        };
    }
    std::fs::remove_file(target).map_err(|e| local_err("delete", target, e))
}

// `pub(crate)`: an internal helper for the transfer engine's conflict /
// overwrite checks, not part of the `files_local_*` IPC surface (finding D4).
pub(crate) async fn exists(path: &str) -> Result<bool, FilesError> {
    let target = PathBuf::from(path);
    tokio::task::spawn_blocking(move || target.exists())
        .await
        .map_err(|e| FilesError::Local {
            op: "stat",
            path: path.to_string(),
            detail: e.to_string(),
        })
}

/// Whether `path` is itself a symlink (does NOT follow it). `false` when the
/// path doesn't exist or can't be stat'ed.
///
/// The recursive download walker uses this to refuse writing THROUGH a
/// pre-existing local symlink at a destination directory (T43 / finding A3):
/// `create_dir_all` on a symlink-to-dir silently follows it, so every file
/// below would escape the user's chosen destination.
pub(crate) async fn is_symlink(path: &Path) -> bool {
    let target = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        std::fs::symlink_metadata(&target)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(path: &Path, body: &str) {
        fs::write(path, body).expect("write fixture");
    }

    #[tokio::test]
    async fn list_dir_reports_kinds_sizes_and_dotfiles() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("config.txt"), "hello");
        write(&dir.path().join(".hidden"), "x");
        fs::create_dir(dir.path().join("sub")).unwrap();

        let listing = list_dir(Some(&dir.path().display().to_string()), 20_000)
            .await
            .expect("list");
        let mut names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec![".hidden", "config.txt", "sub"]);
        assert!(!listing.truncated);
        assert!(listing.parent.is_some());

        let file = listing
            .entries
            .iter()
            .find(|e| e.name == "config.txt")
            .unwrap();
        assert_eq!(file.kind, EntryKind::File);
        assert_eq!(file.size, Some(5));
        assert!(file.mtime.is_some());

        let sub = listing.entries.iter().find(|e| e.name == "sub").unwrap();
        assert_eq!(sub.kind, EntryKind::Dir);
    }

    #[tokio::test]
    async fn list_dir_caps_entries_and_flags_truncation() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..5 {
            write(&dir.path().join(format!("f{i}")), "x");
        }
        let listing = list_dir(Some(&dir.path().display().to_string()), 3)
            .await
            .expect("list");
        assert_eq!(listing.entries.len(), 3);
        assert!(listing.truncated, "over-cap listing must flag truncation");
    }

    #[tokio::test]
    async fn list_dir_defaults_to_home_and_rejects_files() {
        let listing = list_dir(None, 20_000).await.expect("home listing");
        assert!(!listing.path.is_empty());

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-dir");
        write(&file, "x");
        let err = list_dir(Some(&file.display().to_string()), 20_000).await;
        assert!(err.is_err(), "listing a file must fail");
    }

    #[tokio::test]
    async fn mkdir_rename_delete_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let made = dir.path().join("made");
        mkdir(&made.display().to_string()).await.expect("mkdir");
        assert!(made.is_dir());

        let moved = dir.path().join("moved");
        rename(&made.display().to_string(), &moved.display().to_string())
            .await
            .expect("rename");
        assert!(moved.is_dir() && !made.exists());

        // A non-empty directory needs `recursive`.
        write(&moved.join("inner.txt"), "x");
        assert!(delete(&moved.display().to_string(), false).await.is_err());
        delete(&moved.display().to_string(), true)
            .await
            .expect("recursive delete");
        assert!(!moved.exists());
    }

    #[tokio::test]
    async fn exists_and_mkdir_all_are_idempotent_shaped() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b");
        assert!(!exists(&nested.display().to_string()).await.unwrap());
        mkdir_all(&nested).await.expect("mkdir_all");
        mkdir_all(&nested).await.expect("mkdir_all again");
        assert!(exists(&nested.display().to_string()).await.unwrap());
        // Plain mkdir on an existing dir is an error (surfaced to the UI).
        assert!(mkdir(&nested.display().to_string()).await.is_err());
    }

    /// The symlink guard: deleting a *link to a directory* removes the
    /// link, never the directory it points at.
    #[cfg(unix)]
    #[tokio::test]
    async fn delete_removes_a_symlink_not_its_target_tree() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        write(&real.join("precious.txt"), "keep me");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Even with `recursive` — the guard runs first.
        delete(&link.display().to_string(), true)
            .await
            .expect("delete link");
        assert!(!link.exists(), "the link is gone");
        assert!(real.is_dir(), "the target directory survives");
        assert!(real.join("precious.txt").is_file(), "its contents survive");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn is_symlink_detects_a_link_without_following_it() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert!(is_symlink(&link).await, "a symlink is detected as one");
        assert!(
            !is_symlink(&real).await,
            "a real directory is not a symlink"
        );
        assert!(
            !is_symlink(&dir.path().join("missing")).await,
            "a missing path is not a symlink"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn list_dir_reports_symlinks_as_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("target.txt"), "x");
        std::os::unix::fs::symlink(dir.path().join("target.txt"), dir.path().join("link.txt"))
            .unwrap();
        let listing = list_dir(Some(&dir.path().display().to_string()), 20_000)
            .await
            .unwrap();
        let link = listing
            .entries
            .iter()
            .find(|e| e.name == "link.txt")
            .expect("link listed");
        assert_eq!(link.kind, EntryKind::Symlink);
    }
}
