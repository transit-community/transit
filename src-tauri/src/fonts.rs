//! Installed monospace-font enumeration for the Settings → Terminal
//! font picker (v1.0.2).
//!
//! Read-only scan of the OS font database (fontdb wraps the per-OS
//! font directories, plus fontconfig on Linux). Returns FAMILY NAMES
//! only — never file paths or font bytes — sorted case-insensitively
//! and deduplicated. A face counts as monospace when its own
//! metadata (the `post` table fixed-pitch flag) says so; fonts whose
//! metadata lies are handled on the frontend, which additionally
//! probes what the webview can actually render before listing
//! (`src/lib/fonts.ts`) — that probe also hides OS-shipped families
//! the webview refuses to serve to web content (e.g. SF Mono).

use std::collections::BTreeSet;

/// Dedup + trim + case-insensitive sort (ties broken byte-wise so
/// the order is total and stable across runs).
fn dedupe_and_sort(names: impl IntoIterator<Item = String>) -> Vec<String> {
    let set: BTreeSet<String> = names
        .into_iter()
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .collect();
    let mut out: Vec<String> = set.into_iter().collect();
    out.sort_by(|a, b| {
        a.to_lowercase()
            .cmp(&b.to_lowercase())
            .then_with(|| a.cmp(b))
    });
    out
}

fn monospace_families(db: &fontdb::Database) -> Vec<String> {
    dedupe_and_sort(
        db.faces()
            .filter(|f| f.monospaced)
            .filter_map(|f| f.families.first().map(|(name, _)| name.clone())),
    )
}

/// List installed monospace font families. Read-only enumeration;
/// the returned strings are family names a CSS `font-family` value
/// can reference (Rule 1 untouched — nothing here is a credential).
#[tauri::command]
pub async fn list_monospace_fonts() -> Result<Vec<String>, String> {
    // The directory walk + face parse is real disk IO — keep it off
    // the async runtime's core threads.
    tokio::task::spawn_blocking(|| {
        let mut db = fontdb::Database::new();
        db.load_system_fonts();
        monospace_families(&db)
    })
    .await
    .map_err(|e| format!("font scan failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupes_trims_and_sorts_case_insensitively() {
        let input = vec![
            "Menlo".to_string(),
            "  Menlo  ".to_string(),
            "iA Writer Mono".to_string(),
            "JetBrains Mono".to_string(),
            String::new(),
            "   ".to_string(),
        ];
        assert_eq!(
            dedupe_and_sort(input),
            vec!["iA Writer Mono", "JetBrains Mono", "Menlo"]
        );
    }

    #[test]
    fn system_scan_completes_and_is_sorted() {
        // CI containers may have few or zero fonts installed —
        // assert the scan completes and honors its own ordering
        // contract, not that it finds anything in particular.
        let mut db = fontdb::Database::new();
        db.load_system_fonts();
        let families = monospace_families(&db);
        let resorted = dedupe_and_sort(families.clone());
        assert_eq!(families, resorted);
    }
}
