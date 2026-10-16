//! Tracing setup with a redaction-friendly format layer.
//!
//! `init()` sets up a `tracing-subscriber` that filters via `RUST_LOG` and
//! formats events to **stderr** (a GUI app must keep stdout clean).
//! Secret-bearing types must implement `Debug` such that they redact
//! themselves before formatting reaches this layer — Transit uses
//! `secrecy::SecretString`, whose `Debug` never reveals the inner bytes.
//!
//! # The optional file sink
//!
//! Passing [`FileLogging`] adds a rolling file alongside stderr, for the
//! opt-in diagnostic log in Settings → Developers. Two rules govern what
//! may end up in it, and they are different rules:
//!
//! 1. **No secrets** (`CLAUDE.md` §10). Unchanged by this module: a file
//!    sink records the same events stderr already gets, so the discipline
//!    that keeps credentials, host keys, tokens and prompt content out of
//!    logs keeps them out of the file too. A "log the payloads" mode would
//!    break that and must never be added here.
//! 2. **No architecture.** A file a user can read is a file a customer
//!    can publish, and `trace` with module targets is a runtime map of a
//!    closed-source product. THIS module does not decide the limit —
//!    `transit_app` does, because only it knows the release channel — but
//!    [`FileLogging::level`] and [`FileLogging::include_targets`] exist so
//!    the limit can be applied rather than hoped for.
//!
//! The two rules land differently on purpose: §10 forbids values
//! everywhere, while the architecture limit is a per-channel ceiling. What
//! makes the second cheap is that the first already forces `info` events
//! to read as "the fact of an operation" — which is operational detail,
//! not structural.

use std::path::PathBuf;
use std::sync::OnceLock;

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Keeps the non-blocking writer's worker thread alive.
///
/// Dropping the guard stops the background flusher, so the last events —
/// which for a crash are the interesting ones — never reach disk. It lives
/// here for the process lifetime rather than in a caller's local.
static FILE_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

/// Where the diagnostic log goes and how much of it there is.
#[derive(Debug, Clone)]
pub struct FileLogging {
    /// Directory for the rolling files. Created if missing.
    pub dir: PathBuf,
    /// Verbosity ceiling for the FILE only; stderr keeps its own filter.
    ///
    /// The caller is expected to clamp this per release channel. See the
    /// module docs: `trace` is a map of the internals.
    pub level: tracing::Level,
    /// Whether events carry their module path.
    ///
    /// Off for anything a user may send onward: `transit_agent::…`
    /// names the architecture rather than describing the problem.
    pub include_targets: bool,
    /// How many daily files to keep, so an enabled-and-forgotten log
    /// cannot fill a disk — the same reasoning as capture rotation.
    pub keep_files: usize,
}

/// Initialize the global tracing subscriber.
///
/// Called once from `transit_app::run()`. Idempotent — safe to call again
/// (the redundant call is a no-op): `try_init` errors when a global
/// subscriber is already set (e.g. a test harness installed its own), and
/// that error is deliberately ignored.
///
/// A file-sink failure is NOT fatal. Diagnostics that prevent the app from
/// starting are worse than no diagnostics, so a bad directory disables the
/// file and leaves stderr working.
pub fn init(file: Option<FileLogging>) {
    let (subscriber, guard) = build(file);
    if let Some(g) = guard {
        // If a guard is already installed, `init` ran twice; keep the
        // first rather than dropping it and silencing the writer.
        let _ = FILE_GUARD.set(g);
    }
    let _ = subscriber.try_init();
}

/// Compose the subscriber.
///
/// Separate from [`init`] so a test can install the SAME stack locally and
/// assert what reaches the file — which is how the global-filter bug below
/// should have been caught, and was not.
fn build(
    file: Option<FileLogging>,
) -> (
    impl tracing_subscriber::layer::SubscriberExt + Into<tracing::Dispatch> + Send + Sync + 'static,
    Option<tracing_appender::non_blocking::WorkerGuard>,
) {
    // PER-LAYER filters, and this is load-bearing rather than stylistic.
    //
    // `registry().with(env_filter)` installs a GLOBAL filter: it gates
    // every layer, and a per-layer filter downstream can only narrow it
    // further. With `RUST_LOG` unset that global is `info`, so a file
    // layer asking for `debug` or `trace` received nothing — the setting
    // applied, the events were discarded before reaching it, and the log
    // came back INFO-only on a build that allows trace.
    //
    // Attaching the env filter to stderr instead leaves the file layer's
    // level genuinely its own. The registry unions each layer's interest,
    // so the deeper events are enabled globally precisely when some layer
    // wants them.
    let env = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let stderr_layer = fmt::layer()
        .with_target(true)
        .with_writer(std::io::stderr)
        .with_filter(env);

    let captured_guard = std::cell::RefCell::new(None);
    let file_layer = file.and_then(|f| {
        std::fs::create_dir_all(&f.dir).ok()?;
        let appender = tracing_appender::rolling::Builder::new()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix("transit")
            .filename_suffix("log")
            .max_log_files(f.keep_files.max(1))
            .build(&f.dir)
            .ok()?;
        let (writer, guard) = tracing_appender::non_blocking(appender);
        *captured_guard.borrow_mut() = Some(guard);
        Some(
            fmt::layer()
                .with_ansi(false)
                .with_target(f.include_targets)
                .with_writer(writer)
                .with_filter(level_filter(f.level)),
        )
    });

    (
        tracing_subscriber::registry()
            .with(stderr_layer)
            .with(file_layer),
        captured_guard.into_inner(),
    )
}

fn level_filter(level: tracing::Level) -> tracing_subscriber::filter::LevelFilter {
    tracing_subscriber::filter::LevelFilter::from_level(level)
}

/// Parse a configured level name, defaulting to `info`.
///
/// Unknown text yields `info` rather than an error: a typo in a config
/// file should not decide how much a diagnostic log records, and `info` is
/// the level every channel allows.
pub fn parse_level(name: &str) -> tracing::Level {
    match name.trim().to_ascii_lowercase().as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file configured for `debug` must actually RECEIVE debug events.
    ///
    /// This is the test that was missing. `registry().with(env_filter)`
    /// installs a GLOBAL filter — it gates every layer, and with `RUST_LOG`
    /// unset it sits at `info` — so a file layer asking for `debug` got
    /// nothing. The setting was honoured, the events never arrived, and the
    /// only symptom was an INFO-only log on a build that allows trace.
    ///
    /// Asserting on the CONTENTS of a real file is the point: any test that
    /// checked the configured level rather than the delivered events would
    /// have passed against the bug.
    #[test]
    fn a_file_configured_for_debug_receives_debug_events() {
        let dir = tempfile::tempdir().unwrap();
        let (subscriber, guard) = build(Some(FileLogging {
            dir: dir.path().to_path_buf(),
            level: tracing::Level::DEBUG,
            include_targets: true,
            keep_files: 2,
        }));

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("probe-info-event");
            tracing::debug!("probe-debug-event");
            tracing::trace!("probe-trace-event");
        });

        // Dropping the guard flushes the non-blocking writer's queue.
        drop(guard);

        let written = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| std::fs::read_to_string(e.path()).unwrap_or_default())
            .collect::<String>();

        assert!(
            written.contains("probe-info-event"),
            "info must reach the file: {written:?}"
        );
        assert!(
            written.contains("probe-debug-event"),
            "DEBUG must reach a file configured for debug — a global env filter \
             would have swallowed it: {written:?}"
        );
        assert!(
            !written.contains("probe-trace-event"),
            "trace is below the configured level and must NOT appear: {written:?}"
        );
    }

    /// And the level is a real ceiling in the other direction.
    #[test]
    fn a_file_configured_for_info_excludes_debug() {
        let dir = tempfile::tempdir().unwrap();
        let (subscriber, guard) = build(Some(FileLogging {
            dir: dir.path().to_path_buf(),
            level: tracing::Level::INFO,
            include_targets: false,
            keep_files: 2,
        }));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("kept-info");
            tracing::debug!("dropped-debug");
        });
        drop(guard);

        let written = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| std::fs::read_to_string(e.path()).unwrap_or_default())
            .collect::<String>();
        assert!(written.contains("kept-info"), "{written:?}");
        assert!(
            !written.contains("dropped-debug"),
            "an info-capped file must not receive debug — this is the release \
             channel's guarantee: {written:?}"
        );
        assert!(
            !written.contains("transit_core"),
            "targets are off, so no module path may appear: {written:?}"
        );
    }

    #[test]
    fn unknown_level_names_fall_back_to_info() {
        assert_eq!(parse_level("trace"), tracing::Level::TRACE);
        assert_eq!(parse_level("  DEBUG "), tracing::Level::DEBUG);
        assert_eq!(parse_level("verbose"), tracing::Level::INFO);
        assert_eq!(parse_level(""), tracing::Level::INFO);
    }
}
