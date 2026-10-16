//! Fixture-driven integration tests for the inventory loader.
//!
//! Each `*.toml` file in `fixtures/inventory/` carries a first-line
//! `# expect: <Outcome>` comment. The corpus driver iterates the
//! directory, calls `load()`, and asserts the result matches.
//!
//! Outcomes:
//!   - Ok                    — file should parse successfully
//!   - Err::InlineSecret     — pre-scan rejects a secret-shaped value
//!   - Err::ParseFailed      — TOML parse or UTF-8 conversion fails
//!   - Err::UnknownAuth      — Device.auth references a missing profile
//!   - Err::DuplicateDevice  — two devices share an id
//!
//! Runtime-generated cases (TooLarge, SymlinkRejected, non-UTF-8) live
//! in separate `#[test]` functions below since they need filesystem
//! manipulation.

use std::path::PathBuf;

use transit_core::inventory::{load, InventoryError};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/inventory")
}

#[test]
fn corpus_matches_expectations() {
    let dir = fixtures_dir();
    let mut tested = 0usize;

    let entries = std::fs::read_dir(&dir).expect("fixtures dir readable");
    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }

        let text = std::fs::read_to_string(&path).expect("fixture readable");
        let expect = text.lines().next().unwrap_or("").trim();
        let result = load(&path);

        let pass = matches!(
            (expect, &result),
            ("# expect: Ok", Ok(_))
                | (
                    "# expect: Err::InlineSecret",
                    Err(InventoryError::InlineSecret { .. })
                )
                | (
                    "# expect: Err::ParseFailed",
                    Err(InventoryError::ParseFailed { .. })
                )
                | (
                    "# expect: Err::UnknownAuth",
                    Err(InventoryError::UnknownAuth { .. })
                )
                | (
                    "# expect: Err::DuplicateDevice",
                    Err(InventoryError::DuplicateDevice { .. })
                )
        );

        assert!(
            pass,
            "fixture {:?}: header {:?}, got {:?}",
            path.file_name().unwrap(),
            expect,
            result
        );
        tested += 1;
    }

    assert!(tested >= 7, "expected at least 7 fixtures, got {tested}");
}

// ---------------------------------------------------------------------
// Runtime-generated edge cases.
// ---------------------------------------------------------------------

#[test]
fn rejects_oversized_file() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transit.toml");
    let mut f = std::fs::File::create(&path).unwrap();
    // Just over the cap, sized off the constant so it tracks changes.
    let line = "# filler comment that is fairly long to fill space\n";
    let target = transit_core::inventory::loader::MAX_INVENTORY_SIZE as usize + 1024;
    let mut written = 0;
    while written < target {
        f.write_all(line.as_bytes()).unwrap();
        written += line.len();
    }
    drop(f);
    match load(&path) {
        Err(InventoryError::TooLarge { size, max }) => {
            assert!(size > max);
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

#[test]
fn rejects_non_utf8_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("transit.toml");
    std::fs::write(&path, b"\xff\xfe\x80\x81 not valid utf-8").unwrap();
    match load(&path) {
        Err(InventoryError::ParseFailed { .. }) => {}
        other => panic!("expected ParseFailed, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn rejects_symlink_pointing_outside_parent() {
    let inside = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();

    let outside_target = outside.path().join("evil.toml");
    std::fs::write(&outside_target, b"# expect: Ok\n").unwrap();

    let symlink_path = inside.path().join("transit.toml");
    std::os::unix::fs::symlink(&outside_target, &symlink_path).unwrap();

    match load(&symlink_path) {
        Err(InventoryError::SymlinkRejected { .. }) => {}
        other => panic!("expected SymlinkRejected, got {other:?}"),
    }
}
