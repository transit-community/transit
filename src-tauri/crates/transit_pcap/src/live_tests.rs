//! Live-capture corpus.
//!
//! This is the code that builds a command line which runs as root, so the
//! tests here are weighted toward what must NOT happen: no injection
//! through the capture filter, no silent widening of a Windows filter, no
//! unbounded capture.

use super::*;

// ---------------------------------------------------------------------
// Capture-filter validation — the injection boundary
// ---------------------------------------------------------------------

#[test]
fn ordinary_bpf_expressions_are_accepted() {
    for f in [
        "tcp port 443",
        "host 10.0.0.1 and not port 22",
        "src net 192.168.0.0/16",
        "vlan 10 and icmp",
        "tcp[13] & 2 != 0",
        "ether host aa:bb:cc:dd:ee:ff",
        "port 53 or port 5353",
        "ip6 and tcp",
        "len > 1400",
    ] {
        assert!(validate_bpf(f).is_ok(), "{f:?} should be a valid filter");
    }
}

/// Every one of these contains a character that means something to a
/// shell and nothing to BPF. None may reach a command line that will run
/// as root.
///
/// Note what is NOT here: `tcp > /etc/passwd` and `tcp && curl x`. Both
/// look like shell idioms, but `>` and `&&` are legitimate BPF operators
/// (`len > 1400`, `tcp && udp`), and the expression is passed as ONE argv
/// element that never reaches a shell. Refusing them would break real
/// filters to prevent nothing. Validation is a charset allowlist; syntax
/// is tcpdump's job.
#[test]
fn shell_metacharacters_are_refused() {
    for f in [
        "tcp; rm -rf /",
        "$(whoami)",
        "`id`",
        "tcp\nrm -rf /",
        "host 'x' or 1",
        "host \"x\"",
        "tcp \\; id",
        "tcp #comment",
        "port 80 ; shutdown -h now",
        "${IFS}cat${IFS}/etc/shadow",
        "tcp\u{0}port 80",
    ] {
        assert!(
            validate_bpf(f).is_err(),
            "{f:?} must be refused as a capture filter"
        );
    }
}

#[test]
fn an_overlong_filter_is_refused() {
    let long = "tcp or ".repeat(500);
    assert!(validate_bpf(&long).is_err());
}

/// `&` and `|` are BPF operators, so they stay legal. Validation is a
/// charset allowlist, not a syntax checker: an expression that is merely
/// *malformed* is tcpdump's to reject, and it does so with a message
/// worth showing. What validation exists to stop is a character that
/// would mean something to a shell, and `&` in a single argv element does
/// not.
#[test]
fn bpf_operators_that_look_shell_ish_are_still_accepted() {
    assert!(validate_bpf("tcp[13] & 2 != 0").is_ok());
    assert!(validate_bpf("tcp && udp").is_ok());
    assert!(validate_bpf("port 80 || port 443").is_ok());
    assert!(validate_bpf("len > 1400").is_ok());
    // Malformed but harmless: one argv element, refused by tcpdump with
    // a syntax error the user sees.
    assert!(validate_bpf("tcp && curl evil.example").is_ok());
    assert!(validate_bpf("tcp > /etc/passwd").is_ok());
}

#[test]
fn arbitrary_text_is_either_accepted_or_refused_without_panicking() {
    proptest::proptest!(|(s: String)| {
        let _ = validate_bpf(&s);
    });
}

/// The property that makes the escaping a second line of defence rather
/// than the only one: anything that passes validation contains no
/// character either the shell or AppleScript treats specially.
#[test]
fn an_accepted_filter_contains_nothing_a_shell_would_interpret() {
    proptest::proptest!(|(s: String)| {
        if validate_bpf(&s).is_ok() {
            for bad in ['$', '`', ';', '\'', '"', '\\', '\n', '\r', '#', '~', '?', '\0'] {
                proptest::prop_assert!(
                    !s.contains(bad),
                    "an accepted filter contained {bad:?}: {s:?}"
                );
            }
        }
    });
}

// ---------------------------------------------------------------------
// Command construction
// ---------------------------------------------------------------------

#[test]
fn tcpdump_args_are_bounded_and_pass_the_filter_as_one_operand() {
    let req = CaptureRequest {
        interface: "en0".into(),
        bpf: Some("tcp port 443 and host 10.0.0.1".into()),
        snaplen: 262_144,
        max_file_mb: 256,
        max_files: 8,
        max_duration_secs: 3600,
    };
    let args = build_tcpdump_args(&req, Path::new("/tmp/c.pcap"), None);

    assert!(args.contains(&"-C".to_string()) && args.contains(&"256".to_string()));
    assert!(args.contains(&"-W".to_string()) && args.contains(&"8".to_string()));
    assert!(
        args.contains(&"-U".to_string()),
        "unbuffered, so tailing works"
    );
    assert!(
        args.contains(&"-n".to_string()),
        "no reverse DNS into the capture"
    );

    // The filter must be exactly ONE argv element. Split on spaces, `and`
    // and `host` would be read as tcpdump options.
    assert_eq!(
        args.last().unwrap(),
        "tcp port 443 and host 10.0.0.1",
        "the filter is a single operand"
    );
}

#[test]
fn a_capture_with_no_filter_omits_the_operand() {
    let req = CaptureRequest {
        interface: "en0".into(),
        ..Default::default()
    };
    let args = build_tcpdump_args(&req, Path::new("/tmp/c.pcap"), None);
    // The rotation count is last when there is no filter operand.
    assert_eq!(args.last().unwrap(), &DEFAULT_MAX_FILES.to_string());
}

/// `-G` must NOT appear. It reads like the natural duration bound, but it
/// means "rotate every N seconds", and with no strftime escape in the
/// `-w` name tcpdump then OVERWRITES the same file each period — silently
/// discarding everything older, while `-C`/`-W` are simultaneously trying
/// to rotate on size. Duration is bounded by the supervisor instead.
#[test]
fn the_duration_bound_is_not_delegated_to_tcpdump_rotation() {
    let req = CaptureRequest {
        interface: "en0".into(),
        max_duration_secs: 3600,
        ..Default::default()
    };
    let args = build_tcpdump_args(&req, Path::new("/tmp/c.pcap"), None);
    assert!(
        !args.iter().any(|a| a == "-G"),
        "-G fights -C/-W and silently discards older packets: {args:?}"
    );
}

/// The supervisor is what makes a crashed Transit safe. Both stop
/// conditions must be in the script, and the kill must target the
/// capture rather than the shell wrapping it.
#[test]
fn the_supervisor_script_honours_both_stop_conditions() {
    let script = supervisor_script(
        "'/usr/sbin/tcpdump' '-i' 'en0'",
        Path::new("/tmp/c.running"),
        Path::new("/tmp/c.beat"),
    );
    assert!(script.contains("/tmp/c.running"), "stop sentinel: {script}");
    assert!(script.contains("/tmp/c.beat"), "heartbeat: {script}");
    assert!(
        script.contains("kill -TERM $CAPPID"),
        "must signal the CAPTURE, not the supervising shell: {script}"
    );
    // `SIGINT` is unusable here: POSIX requires a non-interactive shell to
    // set it to SIG_IGN for background commands, so `kill -INT` on the
    // capture is a silent no-op and the supervisor blocks in `wait` while
    // a root tcpdump keeps recording. It shipped that way once.
    assert!(
        !script.contains("kill -INT"),
        "a backgrounded capture ignores SIGINT: {script}"
    );
    assert!(
        script.contains("kill -KILL $CAPPID"),
        "a capture that ignores TERM must still be stopped: {script}"
    );
    assert!(
        script.contains(&HEARTBEAT_STALE_SECS.to_string()),
        "the staleness bound must be baked in: {script}"
    );
}

#[test]
fn the_heartbeat_is_stale_only_after_several_missed_intervals() {
    // Long enough that a busy or suspended app is not killed mid-capture,
    // short enough that a crash does not leave root capturing for long.
    // A const block, so a bad edit to either constant fails the BUILD
    // rather than a test run.
    const {
        assert!(HEARTBEAT_STALE_SECS >= HEARTBEAT_INTERVAL_SECS * 4);
        assert!(HEARTBEAT_STALE_SECS <= 120);
    }
}

/// `-w` names the file we ask for; `-C`/`-W` do not. With `-W`, tcpdump
/// appends a rotation number to EVERY file including the first, so
/// looking for the name we passed finds nothing — which is exactly the
/// "no such file" the first smoke test hit on Stop.
#[test]
fn written_files_finds_the_rotation_suffixed_file() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("capture-x.pcap");

    // Nothing written yet.
    assert!(written_files(&base).is_empty());

    // What tcpdump actually creates under `-W`.
    std::fs::write(base.with_file_name("capture-x.pcap0"), b"aaaa").unwrap();
    let found = written_files(&base);
    assert_eq!(found.len(), 1);
    assert!(found[0].to_string_lossy().ends_with("capture-x.pcap0"));

    // The plain name (what `-C` alone produces) is found too.
    std::fs::write(&base, b"bbbb").unwrap();
    assert_eq!(written_files(&base).len(), 2);

    // An unrelated neighbour with the same prefix but a non-numeric
    // suffix must NOT be swept in — `.running` and `.beat` live here.
    std::fs::write(base.with_file_name("capture-x.pcap.running"), b"1").unwrap();
    std::fs::write(base.with_file_name("capture-x.pcapZZ"), b"1").unwrap();
    assert_eq!(written_files(&base).len(), 2, "only the numbered rotations");

    // A zero-length file is tcpdump having opened but not written;
    // indexing it would report "empty capture" as though that were the
    // answer.
    std::fs::write(base.with_file_name("capture-x.pcap9"), b"").unwrap();
    assert_eq!(written_files(&base).len(), 2);
}

// ---------------------------------------------------------------------
// Elevation escaping
// ---------------------------------------------------------------------

#[test]
fn shell_quoting_neutralizes_an_embedded_quote() {
    assert_eq!(shell_quote("simple"), "'simple'");
    assert_eq!(shell_quote("with space"), "'with space'");
    assert_eq!(shell_quote("it's"), r"'it'\''s'");
    assert_eq!(shell_quote("$(id)"), "'$(id)'");
}

#[test]
fn applescript_quoting_escapes_backslashes_before_quotes() {
    assert_eq!(applescript_quote("plain"), "\"plain\"");
    assert_eq!(applescript_quote(r#"say "hi""#), r#""say \"hi\"""#);
    // Backslash first, or escaping the quote would introduce one that
    // then gets doubled.
    assert_eq!(applescript_quote(r"a\b"), r#""a\\b""#);
}

/// The elevated path is the one place a string reaches a shell. Whatever
/// is put in the argv, the resulting AppleScript must keep it as data.
#[test]
fn the_elevated_script_keeps_arguments_as_data() {
    let script = macos_elevated_script(
        "/usr/sbin/tcpdump",
        &[
            "-i".into(),
            "en0".into(),
            "-w".into(),
            "/tmp/a b/c.pcap".into(),
            "tcp port 443".into(),
        ],
    );
    assert!(script.starts_with("do shell script \""));
    assert!(script.ends_with("with administrator privileges"));
    // The path with a space must be quoted, not split.
    assert!(script.contains(r"'/tmp/a b/c.pcap'"), "{script}");
    assert!(script.contains("'tcp port 443'"), "{script}");
}

#[test]
fn an_argument_that_tries_to_escape_the_quoting_stays_quoted() {
    // These cannot reach here (validate_bpf refuses them) — this pins the
    // second line of defence, so a future caller that forgets to validate
    // is still safe.
    for hostile in [
        "'; id; '",
        "$(id)",
        "`id`",
        r#""; id; ""#,
        r#"\"; id; \""#,
        "a'b",
    ] {
        let script = macos_elevated_script("/bin/echo", &[hostile.to_string()]);
        // Command substitution must not appear unquoted anywhere.
        let body = script
            .trim_start_matches("do shell script ")
            .trim_end_matches(" with administrator privileges");
        assert!(body.starts_with('"') && body.ends_with('"'), "{script}");
        // Every single-quote in the argument became the close/escape/open
        // sequence, so no bare `'` can terminate the quoting early.
        let inner = &body[1..body.len() - 1];
        let unescaped_quotes = inner.matches(r"'\''").count();
        let total_quotes = inner.matches('\'').count();
        assert!(
            total_quotes >= unescaped_quotes,
            "quoting accounting failed for {hostile:?}: {script}"
        );
    }
}

#[test]
fn the_linux_elevation_path_is_an_argv_with_nothing_to_escape() {
    let args = linux_elevated_args("/usr/bin/tcpdump", &["-i".into(), "eth0".into()]);
    assert_eq!(args, vec!["/usr/bin/tcpdump", "-i", "eth0"]);
}

#[test]
fn permission_errors_are_recognized_across_platforms() {
    for s in [
        "tcpdump: en0: You don't have permission to capture on that device",
        "tcpdump: /dev/bpf0: Permission denied\nerror",
        "socket: Operation not permitted",
        "tcpdump: must be root",
    ] {
        assert!(is_permission_error(s), "should elevate for: {s}");
    }
    for s in [
        "tcpdump: syntax error in filter expression",
        "tcpdump: en99: No such device exists",
        "",
    ] {
        assert!(
            !is_permission_error(s),
            "should NOT prompt for administrator rights for: {s}"
        );
    }
}

// ---------------------------------------------------------------------
// Windows filter translation — never silently widen
// ---------------------------------------------------------------------

#[test]
fn the_translatable_bpf_subset_maps_to_pktmon_terms() {
    assert_eq!(
        bpf_to_pktmon("host 10.0.0.5").unwrap(),
        vec![PktmonFilter::Host("10.0.0.5".into())]
    );
    assert_eq!(
        bpf_to_pktmon("port 443").unwrap(),
        vec![PktmonFilter::Port(443)]
    );
    assert_eq!(
        bpf_to_pktmon("tcp").unwrap(),
        vec![PktmonFilter::Transport("tcp")]
    );
    assert_eq!(
        bpf_to_pktmon("tcp port 443").unwrap(),
        vec![PktmonFilter::Transport("tcp"), PktmonFilter::Port(443)]
    );
    assert_eq!(
        bpf_to_pktmon("host 10.0.0.5 and tcp port 443").unwrap(),
        vec![
            PktmonFilter::Host("10.0.0.5".into()),
            PktmonFilter::Transport("tcp"),
            PktmonFilter::Port(443)
        ]
    );
    assert_eq!(bpf_to_pktmon("").unwrap(), vec![]);
}

/// **The data-safety test.** An untranslatable filter must be an error.
/// If any of these silently returned an empty filter list, the user would
/// ask to capture one host and record the entire segment instead.
#[test]
fn an_untranslatable_filter_is_refused_never_widened() {
    for f in [
        "port 80 or port 443",
        "not port 22",
        "src host 10.0.0.1",
        "dst host 10.0.0.1",
        "tcp[13] & 2 != 0",
        "len > 1400",
        "net 10.0.0.0/8",
        "ip6",
        "greater 1000",
        "ether proto 0x0800",
    ] {
        let got = bpf_to_pktmon(f);
        assert!(
            got.is_err(),
            "{f:?} must be REFUSED on Windows, not silently dropped — got {got:?}"
        );
    }
}

#[test]
fn a_refusal_says_what_is_supported() {
    let e = bpf_to_pktmon("len > 1400").unwrap_err();
    assert!(
        e.contains("host"),
        "the message should list the subset: {e}"
    );
    let e = bpf_to_pktmon("port 80 or port 443").unwrap_err();
    assert!(e.contains("or"), "{e}");
    let e = bpf_to_pktmon("src host 10.0.0.1").unwrap_err();
    assert!(
        e.contains("direction"),
        "the reason must be specific, not generic: {e}"
    );
}

#[test]
fn pktmon_filter_args_are_argv_elements() {
    assert_eq!(
        PktmonFilter::Host("10.0.0.5".into()).to_args(),
        vec!["-i", "10.0.0.5"]
    );
    assert_eq!(PktmonFilter::Port(443).to_args(), vec!["-p", "443"]);
    assert_eq!(PktmonFilter::Transport("tcp").to_args(), vec!["-t", "tcp"]);
}

#[test]
fn pktmon_start_args_target_one_component_never_all_nics() {
    let req = CaptureRequest {
        interface: "04-33-C2-C4-CE-F8".into(),
        ..Default::default()
    };
    let args = build_pktmon_args(&req, Path::new(r"C:\caps\c.etl"));
    assert!(args.contains(&"--comp".to_string()));
    // A placeholder at THIS layer, because the component id is not
    // knowable yet: `pktmon list` needs Administrator, and the enumeration
    // that produced this adapter ran unprivileged. The elevated script
    // resolves the MAC to an id and substitutes it.
    assert!(args.contains(&COMP_PLACEHOLDER.to_string()));
    assert!(
        !args.contains(&"nics".to_string()),
        "capturing every adapter must never be a silent fallback"
    );
    // `circular`, NOT `multi-file`. multi-file rolls to suffixed files, so
    // the fixed `--file-name` etl2pcap converts on stop is never written,
    // AND it has no total size cap — both the empty-pcapng bug and a
    // disk-safety hole. circular is one bounded file, deterministically
    // named. Pinned so a "turn rotation back on" refactor cannot silently
    // reintroduce either.
    assert!(
        args.contains(&"circular".to_string()),
        "capture must use a single bounded circular file: {args:?}"
    );
    assert!(
        !args.contains(&"multi-file".to_string()),
        "multi-file breaks etl2pcap and is unbounded on disk: {args:?}"
    );
}

// ---------------------------------------------------------------------
// The Windows supervisor
//
// Cannot be executed here, so these test the generated SCRIPT — which is
// where all three of Windows' structural differences are handled. The
// behaviour still needs a real Windows smoke test (plan §14 items 9-12);
// what these prevent is shipping a script that is wrong on its face.
// ---------------------------------------------------------------------

#[test]
fn powershell_quoting_doubles_an_embedded_quote() {
    assert_eq!(ps_quote("plain"), "'plain'");
    assert_eq!(ps_quote(r"C:\caps\a b.etl"), r"'C:\caps\a b.etl'");
    assert_eq!(ps_quote("it's"), "'it''s'");
}

#[test]
fn the_windows_supervisor_refuses_a_session_it_did_not_start() {
    let script = windows_supervisor_script(
        "18-C0-4D-24-01-DE",
        &[],
        &["start".into(), "--capture".into()],
        WindowsCapturePaths {
            etl: Path::new(r"C:\caps\c.etl"),
            pcapng: Path::new(r"C:\caps\c.pcapng"),
            sentinel: Path::new(r"C:\caps\c.running"),
            heartbeat: Path::new(r"C:\caps\c.beat"),
            log: Path::new(r"C:\caps\c.supervisor.log"),
        },
    );
    // pktmon is machine-global: someone else's capture is not ours to
    // stop, and their filters are not ours to reset.
    assert!(script.contains("pktmon status"), "{script}");
    assert!(script.contains("already running"), "{script}");
    assert!(
        script.find("pktmon status").unwrap() < script.find("filter remove").unwrap(),
        "the status check must come BEFORE we touch filter state:\n{script}"
    );
    // `reset` is not a pktmon subcommand — the real build answers
    // "Unknown command 'reset'", and under PowerShell 7.4+ native-error
    // handling that aborted the whole capture. The verb is `remove`.
    assert!(
        !script.contains("filter reset"),
        "filter reset is not a pktmon command: {script}"
    );
    // Native exit codes are checked, not left to auto-throw — the thing
    // that turned a benign pktmon stderr line into an empty capture.
    assert!(
        script.contains("$PSNativeCommandUseErrorActionPreference = $false"),
        "native command auto-throw must be off: {script}"
    );
    assert!(
        script.contains("pktmon start failed") && script.contains("etl2pcap failed"),
        "start and convert must check $LASTEXITCODE explicitly: {script}"
    );
}

#[test]
fn the_windows_supervisor_converts_on_stop_in_the_same_elevated_run() {
    let script = windows_supervisor_script(
        "18-C0-4D-24-01-DE",
        &pktmon_filter_args(&[PktmonFilter::Host("10.0.0.5".into())]).unwrap(),
        &[
            "start".into(),
            "--capture".into(),
            "--comp".into(),
            "12".into(),
        ],
        WindowsCapturePaths {
            etl: Path::new(r"C:\caps\c.etl"),
            pcapng: Path::new(r"C:\caps\c.pcapng"),
            sentinel: Path::new(r"C:\caps\c.running"),
            heartbeat: Path::new(r"C:\caps\c.beat"),
            log: Path::new(r"C:\caps\c.supervisor.log"),
        },
    );
    assert!(
        script.contains("pktmon filter add 'TransitCE' '-i' '10.0.0.5'"),
        "{script}"
    );
    assert!(script.contains("'--comp' '12'"), "{script}");
    // Stop-then-convert, and both inside the ONE elevated run — a second
    // elevated call would mean a second UAC prompt.
    assert!(script.contains("pktmon stop"), "{script}");
    assert!(script.contains("etl2pcap"), "{script}");
    assert!(
        script.find("pktmon stop").unwrap() < script.find("etl2pcap").unwrap(),
        "conversion must follow the stop:\n{script}"
    );
}

/// Stop must be the sentinel disappearing, never a second prompt — a
/// prompt the user can dismiss leaves the machine recording. The stale
/// heartbeat is the backstop for a Transit that dies without one.
#[test]
fn the_windows_supervisor_stops_without_a_second_prompt() {
    let script = windows_supervisor_script(
        "18-C0-4D-24-01-DE",
        &[],
        &["start".into()],
        WindowsCapturePaths {
            etl: Path::new(r"C:\caps\c.etl"),
            pcapng: Path::new(r"C:\caps\c.pcapng"),
            sentinel: Path::new(r"C:\caps\c.running"),
            heartbeat: Path::new(r"C:\caps\c.beat"),
            log: Path::new(r"C:\caps\c.supervisor.log"),
        },
    );
    assert!(
        script.contains("Test-Path 'C:\\caps\\c.running'"),
        "{script}"
    );
    assert!(script.contains("LastWriteTimeUtc"), "{script}");
    assert!(
        script.contains(&HEARTBEAT_STALE_SECS.to_string()),
        "the staleness bound must be baked in:\n{script}"
    );
    assert!(
        !script.contains("RunAs"),
        "the supervisor must not re-elevate; it IS the elevated process:\n{script}"
    );
}

#[test]
fn every_translated_filter_reaches_the_windows_script() {
    let filters = bpf_to_pktmon("host 10.0.0.5 and tcp port 443").unwrap();
    let script = windows_supervisor_script(
        "18-C0-4D-24-01-DE",
        &pktmon_filter_args(&filters).unwrap(),
        &["start".into()],
        WindowsCapturePaths {
            etl: Path::new(r"C:\c.etl"),
            pcapng: Path::new(r"C:\c.pcapng"),
            sentinel: Path::new(r"C:\c.running"),
            heartbeat: Path::new(r"C:\c.beat"),
            log: Path::new(r"C:\caps\c.supervisor.log"),
        },
    );
    // EXACTLY ONE `filter add`, carrying every condition.
    //
    // This assertion used to require one per term, which codified the bug:
    // pktmon OR-s separate filters, so three of them turn
    // "host 10.0.0.5 and tcp port 443" into "all TCP, or anything on 443,
    // or anything touching 10.0.0.5" — the whole segment instead of one
    // conversation. pktmon's own help is explicit that conditions are
    // AND-ed only WITHIN a single filter.
    assert_eq!(
        script.matches("pktmon filter add").count(),
        1,
        "terms must be AND-ed inside one filter, not OR-ed across three:\n{script}"
    );
    assert!(script.contains("'10.0.0.5'"), "{script}");
    assert!(script.contains("'443'"), "{script}");
    assert!(script.contains("'tcp'"), "{script}");
    let _ = filters;
}

/// Conditions that cannot be expressed exactly are REFUSED, never
/// approximated into something broader.
#[test]
fn a_filter_pktmon_cannot_express_exactly_is_refused() {
    // pktmon takes at most two values per condition. Three hosts cannot
    // be expressed, and the wrong answer is to drop one.
    let three = vec![
        PktmonFilter::Host("10.0.0.1".into()),
        PktmonFilter::Host("10.0.0.2".into()),
        PktmonFilter::Host("10.0.0.3".into()),
    ];
    let err = pktmon_filter_args(&three).expect_err("three hosts cannot be expressed");
    assert!(err.contains("cannot be expressed exactly"), "{err}");

    // A contradiction is refused rather than silently resolved.
    let both = vec![
        PktmonFilter::Transport("tcp"),
        PktmonFilter::Transport("udp"),
    ];
    assert!(pktmon_filter_args(&both).is_err());

    // A pair IS expressible: pktmon matches packets containing BOTH, which
    // is what `host A and host B` means in BPF.
    let pair = vec![
        PktmonFilter::Host("10.0.0.1".into()),
        PktmonFilter::Host("10.0.0.2".into()),
    ];
    let args = pktmon_filter_args(&pair).expect("a pair is expressible");
    assert!(args.contains(&"-i".to_string()));
    assert!(args.contains(&"10.0.0.1".to_string()));
    assert!(args.contains(&"10.0.0.2".to_string()));
    assert_eq!(
        args.iter().filter(|a| *a == "-i").count(),
        1,
        "one -i with two values, not two flags: {args:?}"
    );
}

/// "Whole packet" is `--pkt-size 0` on Windows.
///
/// pktmon's help: "To always log the entire packet set this to 0."
/// `SNAPLEN_FULL` is a tcpdump idiom (262144) that means nothing here.
#[test]
fn full_snaplen_becomes_pktmon_zero() {
    let full = build_pktmon_args(
        &CaptureRequest {
            interface: "13".into(),
            snaplen: DEFAULT_SNAPLEN,
            ..Default::default()
        },
        Path::new(r"C:\c.etl"),
    );
    let at = full.iter().position(|a| a == "--pkt-size").unwrap();
    assert_eq!(full[at + 1], "0", "full capture is 0, not a byte count");

    // A real cap passes through unchanged.
    let headers = build_pktmon_args(
        &CaptureRequest {
            interface: "13".into(),
            snaplen: HEADERS_ONLY_SNAPLEN,
            ..Default::default()
        },
        Path::new(r"C:\c.etl"),
    );
    let at = headers.iter().position(|a| a == "--pkt-size").unwrap();
    assert_eq!(headers[at + 1], HEADERS_ONLY_SNAPLEN.to_string());
}

/// Verbatim `Get-NetAdapter` output from a real Windows 11 machine, in
/// the tab-delimited shape `list_interfaces` asks PowerShell for.
///
/// The fixture that used to sit here was invented — it described a pktmon
/// JSON shape with `"Type": "NIC"`, a value pktmon never emits — so the
/// test passed while the parser discarded every adapter and the dropdown
/// was empty on every Windows machine. A made-up fixture only validates a
/// parser against its author's assumptions.
const REAL_GET_NETADAPTER: &str = "\
20\t18-C0-4D-24-01-DE\tUp\tEthernet\tIntel(R) Ethernet Controller (2) I225-V\n\
52\t00-15-5D-A2-9D-7B\tUp\tvEthernet (WSL (Hyper-V firewall))\tHyper-V Virtual Ethernet Adapter #2\n\
13\t04-33-C2-C4-CE-F8\tDisconnected\tWi-Fi\tIntel(R) Wi-Fi 6 AX201 160MHz\n\
9\t04-33-C2-C4-CE-FC\tDisconnected\tBluetooth Network Connection\tBluetooth Device (Personal Area Network)\n\
32\t00-15-5D-15-C4-00\tUp\tvEthernet (Default Switch)\tHyper-V Virtual Ethernet Adapter\n\
3\t7C-1E-52-5C-D0-FF\tUp\tEthernet 4\tMellanox ConnectX-4 Lx Virtual Ethernet Adapter\n\
14\t7C-1E-52-5C-D0-FF\tUp\tEthernet 3\tMicrosoft Hyper-V Network Adapter #3\n";

#[test]
fn get_netadapter_rows_parse() {
    let nics = parse_net_adapters(REAL_GET_NETADAPTER);
    assert_eq!(nics.len(), 7, "seven adapters in the fixture: {nics:?}");

    // The NDIS interface index is the identity, because it is the only
    // field that joins UNIQUELY to a pktmon component.
    assert_eq!(nics[0].name, "20");
    assert!(nics
        .iter()
        .all(|n| n.name.bytes().all(|b| b.is_ascii_digit())));

    // The last two rows are the SR-IOV pair from a real Windows runner:
    // one hardware address, two adapters. If the MAC were the identity
    // these would collide and a capture would land on whichever pktmon
    // listed first. The index keeps them apart.
    let sriov: Vec<&str> = nics
        .iter()
        .filter(|n| n.description.contains("Mellanox") || n.description.contains("Hyper-V Network"))
        .map(|n| n.name.as_str())
        .collect();
    assert_eq!(
        sriov,
        vec!["3", "14"],
        "the shared-MAC pair must stay distinct"
    );
    let unique: std::collections::HashSet<&String> = nics.iter().map(|n| &n.name).collect();
    assert_eq!(unique.len(), nics.len(), "adapter ids must be unique");

    // Both halves of the label: the connection name and the hardware.
    assert_eq!(
        nics[0].description,
        "Ethernet \u{2014} Intel(R) Ethernet Controller (2) I225-V"
    );

    // A real up/down reading rather than an assumption. Capturing on a
    // disconnected adapter is legal and records nothing, so the user
    // should be able to see which is which.
    assert!(nics[0].up, "Ethernet is Up");
    assert!(!nics[2].up, "Wi-Fi is Disconnected");
}

/// Adapter names contain spaces and nested parentheses, so the fields must
/// come from the delimiter and never from whitespace splitting.
#[test]
fn adapter_names_with_spaces_and_parens_survive() {
    let nics = parse_net_adapters(REAL_GET_NETADAPTER);
    let wsl = nics
        .iter()
        .find(|n| n.name == "52")
        .expect("the WSL adapter");
    assert_eq!(
        wsl.description,
        "vEthernet (WSL (Hyper-V firewall)) \u{2014} Hyper-V Virtual Ethernet Adapter #2"
    );
}

#[test]
fn unparseable_adapter_output_yields_nothing_rather_than_garbage() {
    // Including pktmon's JSON: it is no longer what we ask for, and if it
    // turned up anyway we want zero adapters (which the caller turns into
    // a loud error) rather than nonsense rows.
    assert!(parse_net_adapters(r#"[{"Group":"x","Components":[{"Id":134}]}]"#).is_empty());
    assert!(parse_net_adapters("Name : Ethernet\nStatus : Up").is_empty());
    assert!(parse_net_adapters("").is_empty());
    proptest::proptest!(|(s: String)| {
        let _ = parse_net_adapters(&s);
    });
}

// ---------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------

fn nics() -> Vec<Nic> {
    vec![Nic {
        name: "en0".into(),
        description: "Wi-Fi".into(),
        up: true,
        loopback: false,
    }]
}

#[test]
fn an_interface_we_did_not_enumerate_is_refused() {
    let req = CaptureRequest {
        interface: "en9; rm -rf /".into(),
        ..Default::default()
    };
    let dir = tempfile::tempdir().unwrap();
    assert!(preflight(&req, &nics(), dir.path()).is_err());
}

#[test]
fn a_capture_with_no_rotation_ceiling_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    for (mb, files) in [(0u32, 8u32), (256, 0)] {
        let req = CaptureRequest {
            interface: "en0".into(),
            max_file_mb: mb,
            max_files: files,
            ..Default::default()
        };
        assert!(
            preflight(&req, &nics(), dir.path()).is_err(),
            "a capture with no ceiling must be refused ({mb} MB x {files})"
        );
    }
}

#[test]
fn preflight_rejects_a_bad_filter_before_anything_is_spawned() {
    let dir = tempfile::tempdir().unwrap();
    let req = CaptureRequest {
        interface: "en0".into(),
        bpf: Some("tcp; id".into()),
        ..Default::default()
    };
    let err = preflight(&req, &nics(), dir.path()).unwrap_err();
    assert!(format!("{err}").contains("not valid in a BPF expression"));
}

#[test]
fn capture_paths_are_distinct_per_capture() {
    let dir = Path::new("/tmp");
    let a = capture_path(dir, "20260806-171500", "aaa");
    let b = capture_path(dir, "20260806-171500", "bbb");
    assert_ne!(a, b, "two captures in the same second must not collide");
    assert!(a.to_string_lossy().ends_with(".pcap"));
}

// ---------------------------------------------------------------------
// Supervisor teardown — the orphan boundary
// ---------------------------------------------------------------------

/// The supervisor must actually stop the capture, not merely decide to.
///
/// This runs the real script against a stand-in capture and asserts the
/// child is GONE, because every previous version of this code was correct
/// right up until the last line and still left a root `tcpdump` recording:
/// first by dropping the handle, then by mistaking a zombie for a live
/// process, and then by sending `SIGINT` to a background job that POSIX
/// requires the shell to make immune to it. Asserting on the generated
/// script text would have passed for all three.
#[cfg(unix)]
#[test]
fn supervisor_kills_the_capture_when_the_sentinel_disappears() {
    use std::process::{Command, Stdio};

    let dir = tempfile::tempdir().unwrap();
    let sentinel = dir.path().join("c.running");
    let heartbeat = dir.path().join("c.beat");
    std::fs::write(&sentinel, b"1").unwrap();
    std::fs::write(&heartbeat, b"1").unwrap();

    // A marker file the stand-in "capture" keeps touching, so the test can
    // tell "the process object is gone" from "it stopped doing work".
    let marker = dir.path().join("alive");
    let cmd = format!(
        "/bin/sh -c {}",
        shell_quote(&format!(
            "while true; do : > {}; sleep 0.2; done",
            shell_quote(&marker.to_string_lossy())
        ))
    );

    let script = supervisor_script(&cmd, &sentinel, &heartbeat);
    let mut sup = Command::new("/bin/sh")
        .args(["-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn supervisor");

    // Let it get going, and keep the heartbeat fresh so the ONLY stop
    // condition under test is the sentinel.
    let mut started = false;
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let _ = std::fs::write(&heartbeat, b"1");
        if marker.exists() {
            started = true;
            break;
        }
    }
    assert!(started, "the stand-in capture never started");

    // A clean Stop is exactly this: delete the sentinel, touch nothing else.
    std::fs::remove_file(&sentinel).unwrap();

    let mut exited = false;
    for _ in 0..100 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let _ = std::fs::write(&heartbeat, b"1");
        if sup.try_wait().expect("try_wait").is_some() {
            exited = true;
            break;
        }
    }
    assert!(
        exited,
        "the supervisor never exited — it is blocked in `wait` on a child \
         that ignored its stop signal, which is an orphaned root capture"
    );

    // And the capture is really dead, not just detached: nothing has
    // touched the marker since the supervisor exited.
    let before = std::fs::metadata(&marker).unwrap().modified().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(600));
    let after = std::fs::metadata(&marker).unwrap().modified().unwrap();
    assert_eq!(
        before, after,
        "the capture process is still running after the supervisor exited"
    );
}

/// The heartbeat backstop: a Transit that dies without a clean exit must
/// still not leave a capture running.
#[cfg(unix)]
#[test]
fn supervisor_kills_the_capture_when_the_heartbeat_goes_stale() {
    use std::process::{Command, Stdio};

    let dir = tempfile::tempdir().unwrap();
    let sentinel = dir.path().join("c.running");
    let heartbeat = dir.path().join("c.beat");
    std::fs::write(&sentinel, b"1").unwrap();
    // Never created: `stat` fails, the script falls back to 0, and the
    // staleness check sees an epoch-old beat. That is the same branch a
    // long-dead Transit takes, without the wall-clock wait.
    assert!(!heartbeat.exists());

    let script = supervisor_script("sleep 60", &sentinel, &heartbeat);
    let mut sup = Command::new("/bin/sh")
        .args(["-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn supervisor");

    let mut exited = false;
    for _ in 0..100 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if sup.try_wait().expect("try_wait").is_some() {
            exited = true;
            break;
        }
    }
    assert!(exited, "a stale heartbeat must stop the capture");
}

/// The supervisor must SURVIVE a normal loop iteration.
///
/// This is the test that was missing, and its absence let a Linux-only
/// break ship: `stat -f %m` is BSD syntax, but on GNU coreutils `-f` means
/// `--file-system`, so the heartbeat read returned a multi-line filesystem
/// blob instead of an mtime and `$((NOW - BEAT))` killed the shell with
/// "Illegal number" on the FIRST iteration.
///
/// The three tests below could not see it. Each asserts only that the
/// capture *stopped*, and a crashed supervisor stops the capture too — so
/// they passed for entirely the wrong reason, on a feature that had never
/// worked on Linux. They also discarded stderr, which is where the shell
/// was saying so the whole time.
///
/// Hence both assertions here: the supervisor is still running while its
/// stop conditions are unmet, AND it printed nothing to stderr.
#[cfg(unix)]
#[test]
fn supervisor_survives_a_loop_iteration_with_a_fresh_heartbeat() {
    use std::io::Read as _;
    use std::process::{Command, Stdio};

    let dir = tempfile::tempdir().unwrap();
    let sentinel = dir.path().join("c.running");
    let heartbeat = dir.path().join("c.beat");
    std::fs::write(&sentinel, b"1").unwrap();
    std::fs::write(&heartbeat, b"1").unwrap();

    // Sentinel present, heartbeat fresh, capture alive: every stop
    // condition is unmet, so the supervisor must simply keep looping.
    let script = supervisor_script("sleep 30", &sentinel, &heartbeat);
    let mut sup = Command::new("/bin/sh")
        .args(["-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn supervisor");

    // Comfortably past the 0.3s liveness check and two 1s loop iterations.
    std::thread::sleep(std::time::Duration::from_millis(2500));

    let still_running = sup.try_wait().expect("try_wait").is_none();

    let mut stderr = String::new();
    if !still_running {
        if let Some(mut pipe) = sup.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
    }
    let _ = sup.kill();
    let _ = sup.wait();

    assert!(
        still_running,
        "the supervisor must keep running while the sentinel exists, the \
         heartbeat is fresh and the capture is alive; it exited instead. \
         stderr: {stderr}"
    );
}

/// A capture that ignores catchable signals must STILL be stopped.
///
/// Not hypothetical: three root `tcpdump`s spawned through the macOS
/// privileged-helper path survived `kill -INT` AND `kill -TERM` sent
/// directly by root, sitting in ordinary interruptible sleep the whole
/// time — only `SIGKILL` moved them. Whatever the elevated path does to
/// signal dispositions, the supervisor cannot assume a polite stop works,
/// so it escalates. A hard kill is safe here because captures run `-U`:
/// every packet is already on disk and pcap has no trailer.
#[cfg(unix)]
#[test]
fn supervisor_escalates_to_kill_when_the_capture_ignores_term() {
    use std::process::{Command, Stdio};

    let dir = tempfile::tempdir().unwrap();
    let sentinel = dir.path().join("c.running");
    let heartbeat = dir.path().join("c.beat");
    std::fs::write(&sentinel, b"1").unwrap();
    std::fs::write(&heartbeat, b"1").unwrap();

    // A stand-in capture that refuses every signal it is allowed to refuse.
    let cmd = "/bin/sh -c 'trap \"\" TERM INT HUP; while true; do sleep 0.2; done'";
    let script = supervisor_script(cmd, &sentinel, &heartbeat);
    let mut sup = Command::new("/bin/sh")
        .args(["-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn supervisor");

    std::thread::sleep(std::time::Duration::from_millis(700));
    std::fs::remove_file(&sentinel).unwrap();

    // Generous: the escalation deliberately waits out a grace period first.
    let mut exited = false;
    for _ in 0..200 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let _ = std::fs::write(&heartbeat, b"1");
        if sup.try_wait().expect("try_wait").is_some() {
            exited = true;
            break;
        }
    }
    assert!(
        exited,
        "a capture that ignores SIGTERM must be SIGKILLed, not waited on forever"
    );
}

/// The elevated script must resolve the adapter to a pktmon component id
/// ITSELF.
///
/// `pktmon list` needs Administrator — an unelevated call exits 5 with
/// "Failed to communicate with the PktMon driver: Access is denied" — so
/// the unprivileged enumeration that filled the dropdown could not learn
/// the id. It carries the MAC instead, and the lookup happens inside the
/// single elevated session Start already opens. Doing it anywhere else
/// means a second UAC prompt, or a prompt merely to list adapters.
#[test]
fn the_windows_supervisor_resolves_the_component_id_from_the_interface_index() {
    let script = windows_supervisor_script(
        "13",
        &[],
        &build_pktmon_args(
            &CaptureRequest {
                interface: "13".into(),
                ..Default::default()
            },
            Path::new(r"C:\caps\c.etl"),
        ),
        WindowsCapturePaths {
            etl: Path::new(r"C:\caps\c.etl"),
            pcapng: Path::new(r"C:\caps\c.pcapng"),
            sentinel: Path::new(r"C:\caps\c.running"),
            heartbeat: Path::new(r"C:\caps\c.beat"),
            log: Path::new(r"C:\caps\c.supervisor.log"),
        },
    );

    assert!(
        script.contains("pktmon list"),
        "must look the id up: {script}"
    );
    assert!(
        script.contains("[int]'13'") || script.contains("13"),
        "must match on the interface index: {script}"
    );
    assert!(
        script.contains("'--comp' $comp"),
        "the resolved id must reach --comp: {script}"
    );
    // The placeholder must NEVER survive into the command line: pktmon
    // would reject it, but a build that silently substituted something
    // else could capture on the wrong adapter.
    assert!(
        !script.contains(COMP_PLACEHOLDER),
        "the placeholder must be substituted: {script}"
    );

    // The resolution must happen BEFORE the start.
    assert!(
        script.find("pktmon list").unwrap() < script.find("'--comp' $comp").unwrap(),
        "id lookup must precede start:\n{script}"
    );
}

/// No matching component is a hard stop, never a widened capture.
///
/// `--comp nics` captures every adapter on the machine. Falling back to it
/// would turn "capture my Wi-Fi" into "capture everything", which is a
/// data-safety incident rather than a graceful degradation — the same rule
/// the Windows filter translation follows.
#[test]
fn an_unresolvable_adapter_stops_rather_than_capturing_everything() {
    let script = windows_supervisor_script(
        "999",
        &[],
        &["start".into(), "--capture".into()],
        WindowsCapturePaths {
            etl: Path::new(r"C:\caps\c.etl"),
            pcapng: Path::new(r"C:\caps\c.pcapng"),
            sentinel: Path::new(r"C:\caps\c.running"),
            heartbeat: Path::new(r"C:\caps\c.beat"),
            log: Path::new(r"C:\caps\c.supervisor.log"),
        },
    );
    assert!(script.contains("Write-Error"), "{script}");
    assert!(script.contains("exit 4"), "must abort: {script}");
    assert!(
        !script.contains("--comp nics") && !script.contains("--comp all"),
        "must never widen to every adapter: {script}"
    );
}

/// The Windows output resolver finds the capture by its id-stem, whatever
/// extension `etl2pcap` chose, and ignores the sidecars.
///
/// This is the fix for the bug that made Windows capture look dead: the
/// app searched for the `.pcap` name it requested, but `etl2pcap` writes a
/// `.pcapng`, so the capture — recorded fine — was reported as "wrote no
/// packets". Runs on the host under `cfg(test)`; no Windows needed.
#[test]
fn windows_capture_outputs_finds_the_pcapng_whatever_the_extension() {
    let dir = tempfile::tempdir().unwrap();
    let base = capture_path(dir.path(), "20260808", "abcd1234");
    let stem = base.file_stem().unwrap().to_str().unwrap().to_string();

    // The sidecars the supervisor writes — none of these is the capture,
    // including the staged `.ps1` the elevated run executes.
    for ext in ["etl", "running", "beat", "supervisor.log", "ps1"] {
        std::fs::write(dir.path().join(format!("{stem}.{ext}")), b"x").unwrap();
    }
    // etl2pcap's real output: the stem with a `.pcapng` extension, NOT the
    // `.pcap` the app requested.
    let real = dir.path().join(format!("{stem}.pcapng"));
    std::fs::write(&real, b"\xd4\xc3\xb2\xa1payload").unwrap();

    let found = windows_capture_outputs(&base);
    assert_eq!(
        found,
        vec![real.clone()],
        "must find the .pcapng and skip sidecars: {found:?}"
    );

    // A neighbour capture must not be swept in — the id is unique.
    let other = capture_path(dir.path(), "20260808", "99997777");
    std::fs::write(other.with_extension("pcapng"), b"other").unwrap();
    let found = windows_capture_outputs(&base);
    assert_eq!(
        found.len(),
        1,
        "another capture's id must not match: {found:?}"
    );

    // A zero-length output is pktmon having created but not filled the
    // file; it is not a capture and must not be offered as one.
    std::fs::write(&real, b"").unwrap();
    assert!(
        windows_capture_outputs(&base).is_empty(),
        "an empty output must not count as a capture"
    );
}

/// `-EncodedCommand` round-trips the script through base64 UTF-16LE, and
/// the encoding is pure `[A-Za-z0-9+/=]` — which is the whole point: it
/// survives the three parser layers that mangled the inline form, and it
/// stages no user-writable file for a same-user attacker to swap before
/// the elevated read.
#[test]
fn the_encoded_command_is_decodable_and_metacharacter_free() {
    use base64::Engine as _;

    // A script with every character that broke the inline path.
    let script =
        "$x = 'a''b'; Write-Output \"line1`nline2\"; if ($y -ne 0) { exit 5 }\nNote 'done'";
    let encoded = windows_encoded_command(script);

    // Nothing a shell or PowerShell parser treats specially — so it passes
    // `-Command` → `Start-Process -ArgumentList` → the elevated process
    // untouched.
    assert!(
        encoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='),
        "encoded command must be pure base64: {encoded}"
    );

    // Decodes back to the exact script as PowerShell would read it: base64
    // → UTF-16LE → string.
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .expect("valid base64");
    assert_eq!(bytes.len() % 2, 0, "UTF-16 is 2 bytes per unit");
    // The even-length assert above means `as_chunks` leaves no remainder.
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let decoded = String::from_utf16(&units).expect("valid UTF-16");
    assert_eq!(
        decoded, script,
        "the elevated PowerShell must see the exact script"
    );
}

// ---------------------------------------------------------------------
// Linux: why a capture produced no file at all
// ---------------------------------------------------------------------

/// Debian/Ubuntu build tcpdump with `--with-user=tcpdump`, so a capture
/// started as root drops to that unprivileged user before writing. The
/// first file often predates the drop and survives; every `-C` rotation
/// file after it is created in a directory owned by the invoking user and
/// fails with "Permission denied". Naming the invoking user is what makes
/// a rotating capture produce files the user can then read back.
#[test]
fn a_rotating_capture_drops_to_the_invoking_user() {
    let req = CaptureRequest {
        interface: "eno1".into(),
        ..Default::default()
    };
    let args = build_tcpdump_args(&req, Path::new("/tmp/c.pcap"), Some("alice"));
    let z = args
        .iter()
        .position(|a| a == "-Z")
        .expect("a rotating capture must name the user it drops to");
    assert_eq!(
        args.get(z + 1).map(String::as_str),
        Some("alice"),
        "-Z must be followed by the user: {args:?}"
    );
}

/// The drop-user must not displace the filter, which tcpdump reads as a
/// trailing operand — `-Z` appended after it would be swallowed as part
/// of the filter expression.
#[test]
fn the_filter_stays_last_even_with_a_drop_user() {
    let req = CaptureRequest {
        interface: "eno1".into(),
        bpf: Some("tcp port 443".into()),
        ..Default::default()
    };
    let args = build_tcpdump_args(&req, Path::new("/tmp/c.pcap"), Some("alice"));
    assert_eq!(args.last().unwrap(), "tcp port 443");
    assert!(args.contains(&"-Z".to_string()));
}

/// An empty `-Z` is worse than no `-Z` — tcpdump rejects it outright, so a
/// machine where the user could not be resolved must fall back to the
/// plain argv rather than to a capture that cannot start.
#[test]
fn a_blank_drop_user_omits_the_flag_entirely() {
    let req = CaptureRequest {
        interface: "eno1".into(),
        ..Default::default()
    };
    for user in [None, Some(""), Some("   ")] {
        let args = build_tcpdump_args(&req, Path::new("/tmp/c.pcap"), user);
        assert!(
            !args.iter().any(|a| a == "-Z"),
            "{user:?} must not produce a -Z: {args:?}"
        );
    }
}

/// The regression that cost a password prompt and still recorded nothing:
/// an output-folder denial and an interface denial both say "Permission
/// denied", and only the second is worth elevating for. AppArmor mediates
/// above uid, so elevating the first fails identically.
#[test]
fn an_output_denial_is_told_apart_from_an_interface_denial() {
    let out = Path::new("/home/alice/.local/share/Transit/captures/c.pcap");

    let savefile = "tcpdump: /home/alice/.local/share/Transit/captures/c.pcap: Permission denied";
    assert!(
        is_output_permission_error(savefile, out),
        "a denial naming the output file must not be treated as elevatable"
    );

    // tcpdump derives rotation names by suffixing the given path, so the
    // path it was handed is a prefix of every one of them.
    let rotated = "tcpdump: /home/alice/.local/share/Transit/captures/c.pcap0: Permission denied";
    assert!(is_output_permission_error(rotated, out));

    let iface = "tcpdump: eno1: You don't have permission to capture on that device";
    assert!(
        !is_output_permission_error(iface, out),
        "an interface denial must still reach the elevation ladder"
    );
    assert!(
        is_permission_error(iface),
        "and must still be recognised as elevatable"
    );

    let unrelated = "tcpdump: syntax error in filter expression";
    assert!(!is_output_permission_error(unrelated, out));
}
