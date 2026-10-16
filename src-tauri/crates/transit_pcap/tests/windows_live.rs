//! Windows live-capture integration probe.
//!
//! Everything else about the Windows leg is tested by asserting on strings
//! this crate generates — which is not testing, it is re-reading. Three
//! bugs shipped past that: a `Type: "NIC"` filter for a value pktmon never
//! emits, a JSON parser for a shape pktmon does not produce, and an
//! enumeration path that needed Administrator to fill a dropdown. Each had
//! a passing unit test written against a fixture its author invented.
//!
//! These tests run the REAL commands and parse the REAL output. They need
//! an actual Windows machine, so they are `#[ignore]`d by default and run
//! explicitly:
//!
//! ```powershell
//! cargo test -p transit_pcap --test windows_live -- --ignored --nocapture
//! ```
//!
//! `--nocapture` matters: on a failure the printed output IS the diagnosis,
//! and it is the thing no amount of local reasoning can substitute for.
//!
//! GitHub's `windows-latest` runners execute as an administrator, so the
//! privileged half runs there too — but note what that CANNOT cover: the
//! runner is already elevated, so it never exercises the UAC prompt, the
//! unprivileged-first ladder, or a machine where elevation is refused.
//! Those still need real hardware and a real user.

#![cfg(windows)]

use std::process::Command;

use transit_pcap::live;

/// Run a command and return stdout, failing loudly with stderr attached.
fn run(program: &str, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("could not run `{program} {}`: {e}", args.join(" ")));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `Get-NetAdapter` must enumerate adapters WITHOUT elevation, and our
/// parser must find them in what it actually prints.
///
/// This is the pairing that matters: the previous parser was correct about
/// a format nothing produced.
#[test]
#[ignore = "needs a real Windows machine; run with --ignored"]
fn get_netadapter_enumerates_and_parses() {
    // The app's own command, not a copy: a copy drifted from it within
    // the hour and made this test report zero adapters against a working
    // implementation.
    let (ok, stdout, stderr) = run(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            live::GET_NETADAPTER_PS,
        ],
    );
    println!("--- Get-NetAdapter stdout ---\n{stdout}\n--- stderr ---\n{stderr}");
    assert!(ok, "Get-NetAdapter failed: {stderr}");

    let nics = live::parse_net_adapters_for_test(&stdout);
    println!("--- parsed {} adapters ---", nics.len());
    for n in &nics {
        println!("  name={:?} desc={:?} up={}", n.name, n.description, n.up);
    }

    assert!(
        !nics.is_empty(),
        "no adapters parsed from real output — the parser and the format disagree:\n{stdout}"
    );
    // The NDIS interface index is the join key to pktmon, so every entry
    // must carry one, and they must be unique — a MAC is neither.
    let mut seen = std::collections::HashSet::new();
    for n in &nics {
        assert!(
            n.name.bytes().all(|b| b.is_ascii_digit()) && !n.name.is_empty(),
            "adapter id should be an interface index, got {:?}",
            n.name
        );
        assert!(!n.description.is_empty(), "adapter has no label: {n:?}");
        assert!(
            seen.insert(n.name.clone()),
            "duplicate adapter id {:?}",
            n.name
        );
    }
}

/// The async path the app actually calls, end to end and unprivileged.
#[test]
#[ignore = "needs a real Windows machine; run with --ignored"]
fn list_interfaces_succeeds_without_elevation() {
    let nics = tokio::runtime::Runtime::new()
        .expect("tokio runtime")
        .block_on(live::list_interfaces())
        .expect("list_interfaces must succeed unprivileged");
    println!("--- list_interfaces returned {} ---", nics.len());
    for n in &nics {
        println!("  {} — {} (up={})", n.name, n.description, n.up);
    }
    assert!(!nics.is_empty());
}

/// The ifIndex → pktmon component id resolution, against the real data.
///
/// This is the load-bearing half of the Windows design and it lives in
/// PowerShell inside the elevated script, where no unit test can reach it.
/// Here the same lookup runs for real.
///
/// It joins on the NDIS interface index, NOT the MAC, and this test is the
/// reason: a stock Windows runner has a Mellanox virtual function bonded
/// to a synthetic NetVsc adapter, sharing one hardware address across two
/// pktmon components. A MAC join picks whichever was listed first and
/// calls it success.
///
/// Requires Administrator (CI runners have it). Skips loudly when
/// unprivileged rather than failing, because a developer running the suite
/// on their own desktop should not be told the code is broken.
#[test]
#[ignore = "needs a real Windows machine; run with --ignored"]
fn every_adapter_resolves_to_exactly_one_pktmon_component() {
    let (ok, json, stderr) = run("pktmon", &["list", "--json"]);
    if !ok {
        // Exit 5 / "Access is denied" is the unprivileged case — the whole
        // reason enumeration moved to Get-NetAdapter, so seeing it here
        // confirms the premise rather than contradicting it.
        println!(
            "SKIP: pktmon needs Administrator and this process is not elevated \
             — which is exactly why the adapter list comes from Get-NetAdapter.\n{stderr}"
        );
        return;
    }

    let nics = tokio::runtime::Runtime::new()
        .expect("tokio runtime")
        .block_on(live::list_interfaces())
        .expect("adapters");
    println!("--- {} adapters ---", nics.len());

    // Resolve each adapter the way the elevated script does, using
    // PowerShell's own JSON parser rather than a hand-rolled reader — two
    // of those have already been wrong about this output.
    let mut resolved = 0usize;
    for n in &nics {
        let ps = format!(
            "$want = [int]{idx};              $comps = @((Get-Content -Raw '{path}' | ConvertFrom-Json).Components | Where-Object {{                $_.Properties | Where-Object {{ $_.Name -eq 'ifIndex' -and [int]$_.Value -eq $want }} }});              $ids = @($comps | ForEach-Object {{ $_.Id }} | Sort-Object -Unique);              Write-Output ($ids -join ',')",
            idx = n.name,
            path = json_path().display(),
        );
        let (ok, out, err) = run(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", &ps],
        );
        let ids = out.trim().to_string();
        println!(
            "  ifIndex {} ({}) -> component ids {:?}",
            n.name, n.description, ids
        );
        assert!(ok, "resolution failed for {}: {err}", n.name);

        if ids.is_empty() {
            // Not every host adapter has a pktmon component (and vice
            // versa), so a miss is tolerable. Ambiguity is not.
            continue;
        }
        assert!(
            !ids.contains(','),
            "interface index {} maps to MORE THAN ONE component ({ids}) — the capture \
             would land on whichever was listed first",
            n.name
        );
        resolved += 1;
    }

    assert!(
        resolved > 0,
        "no adapter resolved to a pktmon component; the join key is wrong"
    );
    println!(
        "--- {resolved} of {} adapters resolved uniquely ---",
        nics.len()
    );
    let _ = json;
}

/// Stash `pktmon list --json` where PowerShell can read it back, so the
/// resolution runs against the same bytes the script would see.
#[cfg(windows)]
fn json_path() -> std::path::PathBuf {
    let p = std::env::temp_dir().join("transit-pktmon-list.json");
    let (ok, json, _) = run("pktmon", &["list", "--json"]);
    assert!(ok, "pktmon list --json");
    std::fs::write(&p, json).expect("write pktmon json");
    p
}

/// `pktmon status` must be readable before we decide whether a capture is
/// already running — the check that stops Transit commandeering someone
/// else's session (gate item 12).
#[test]
#[ignore = "needs a real Windows machine; run with --ignored"]
fn pktmon_status_is_legible() {
    let (ok, stdout, stderr) = run("pktmon", &["status"]);
    println!("--- pktmon status ---\nok={ok}\n{stdout}\n--- stderr ---\n{stderr}");
    if !ok {
        println!("SKIP: pktmon needs Administrator; not elevated.");
        return;
    }
    // The supervisor decides "already running" from this text. Print it so
    // the match in `windows_supervisor_script` can be checked against
    // reality rather than against what the docs imply.
    assert!(
        !stdout.trim().is_empty(),
        "pktmon status printed nothing; the already-running check has nothing to read"
    );
}

/// Every pktmon flag Transit passes must exist on this build.
///
/// All of them were written from documentation, and documentation is what
/// produced `Type: "NIC"`. `pktmon <command> help` is read-only, so the
/// whole argv surface can be checked without starting anything: if a flag
/// is wrong, it shows up here as a missing string rather than as a capture
/// that fails at the moment a user needs it.
///
/// Deliberately does NOT run the commands — only reads their help.
#[test]
#[ignore = "needs a real Windows machine; run with --ignored"]
fn every_pktmon_flag_we_pass_exists_on_this_build() {
    // `<subcommand>` → the flags Transit gives it.
    let expected: &[(&[&str], &[&str])] = &[
        (
            &["start", "help"],
            &[
                "--capture",
                "--comp",
                "--pkt-size",
                "--file-size",
                "--log-mode",
                "--file-name",
            ],
        ),
        // The five filter terms `bpf_to_pktmon` can produce.
        (&["filter", "add", "help"], &["-i", "-p", "-t", "-v", "-m"]),
        // `remove`, not `reset`: `pktmon filter reset` is "Unknown command"
        // on real builds, and the supervisor clears stale filters with
        // `filter remove`. Probing the verb we actually run.
        (&["filter", "remove", "help"], &[]),
        (&["etl2pcap", "help"], &["--out"]),
        (&["stop", "help"], &[]),
    ];

    let mut missing: Vec<String> = Vec::new();
    for (argv, flags) in expected {
        let (ok, stdout, stderr) = run("pktmon", argv);
        let help = format!("{stdout}\n{stderr}");
        println!("--- pktmon {} ---\n{help}", argv.join(" "));
        if !ok && help.trim().is_empty() {
            missing.push(format!(
                "`pktmon {}` produced no help at all",
                argv.join(" ")
            ));
            continue;
        }
        // A wrong subcommand does not fail with empty output — it prints
        // "Unknown command '<verb>'" and returns non-zero. The earlier,
        // leniency-only check let `filter reset` pass for weeks because its
        // output was non-empty. Treat that phrasing as the failure it is.
        if help.contains("Unknown command") {
            missing.push(format!(
                "`pktmon {}` is not a real command: {}",
                argv.join(" "),
                help.lines()
                    .find(|l| l.contains("Unknown command"))
                    .unwrap_or("")
                    .trim()
            ));
            continue;
        }
        for f in *flags {
            if !help.contains(*f) {
                missing.push(format!("`pktmon {}` does not document {f}", argv.join(" ")));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "Transit passes flags this pktmon does not have:\n  {}",
        missing.join("\n  ")
    );
}

/// `multi-file` must be a value `--log-mode` accepts.
///
/// Rotation is the only thing standing between a forgotten capture and a
/// full disk, so a wrong mode name is a bounded-by-construction claim that
/// is not true.
#[test]
#[ignore = "needs a real Windows machine; run with --ignored"]
fn the_rotation_log_mode_is_a_value_pktmon_accepts() {
    let (_, stdout, stderr) = run("pktmon", &["start", "help"]);
    let help = format!("{stdout}\n{stderr}");
    println!("--- pktmon start help ---\n{help}");
    assert!(
        help.contains("multi-file"),
        "`--log-mode multi-file` is how rotation is requested, and this build \
         does not list it:\n{help}"
    );
}

/// The whole capture pipeline, end to end, on a real elevated Windows
/// machine — the thing that has never once run.
///
/// Enumeration is verified; the AND/OR filter fix is verified in logic;
/// but start → stop → `etl2pcap` → a pcapng our reader can open has never
/// happened, and every "it captures nothing" report has been diagnosed by
/// guessing. This runs the app's REAL supervisor script (not a
/// reimplementation — that lesson is well learned) and reads what it did.
///
/// CI runners are already elevated, so the script runs directly rather
/// than through `Start-Process -Verb RunAs`; that wrapper is only the
/// elevation transport, and the script body is identical.
///
/// Hard assertions are on the PLUMBING — the script exits 0, a pcapng
/// lands where we asked, and our reader opens it — because those are
/// deterministic. Packet COUNT is printed loudly but not asserted: which
/// virtual adapter on a CI runner carries traffic is not guaranteed, and a
/// flaky test teaches people to ignore it. The supervisor log is printed
/// in full either way, because when this fails the log is the diagnosis.
#[test]
#[ignore = "needs a real elevated Windows machine; run with --ignored"]
fn a_real_capture_runs_start_to_pcapng() {
    use std::io::Write;
    use transit_pcap::index::{build, IndexLimits};
    use transit_pcap::live::{
        build_pktmon_args, capture_path, list_interfaces, windows_capture_outputs,
        windows_supervisor_script, CaptureRequest, WindowsCapturePaths,
    };
    use transit_pcap::reader::CaptureFile;

    let rt = tokio::runtime::Runtime::new().expect("tokio");
    let nics = rt.block_on(list_interfaces()).expect("adapters");
    let nic = nics
        .iter()
        .find(|n| n.up)
        .or_else(|| nics.first())
        .expect("at least one adapter");
    println!(
        "--- capturing on ifIndex {} ({}) ---",
        nic.name, nic.description
    );

    // The app's EXACT path derivation, not hand-picked names. The earlier
    // version of this probe used `probe.pcapng` as the --out — a different
    // extension than the app's `capture_path` (which ends in `.pcap`) — so
    // it never reproduced the bug where etl2pcap forces `.pcapng` onto a
    // `.pcap` --out and the app's `.pcap`-shaped search then finds nothing.
    // Faithful to the byte: `out` is a `.pcap` path, `etl` is its `.etl`
    // sibling, and the pcapng target IS `out`, exactly as `spawn_capture`
    // builds them.
    let dir = tempfile::tempdir().unwrap();
    let out = capture_path(dir.path(), "probe", "abcd1234");
    let etl = out.with_extension("etl");
    let sentinel = out.with_extension("running");
    let heartbeat = out.with_extension("beat");
    let log = out.with_extension("supervisor.log");
    std::fs::write(&sentinel, b"1").unwrap();
    std::fs::write(&heartbeat, b"1").unwrap();

    let req = CaptureRequest {
        interface: nic.name.clone(),
        ..Default::default()
    };
    let script = windows_supervisor_script(
        &nic.name,
        &[], // no filter — capture everything the adapter sees
        &build_pktmon_args(&req, &etl),
        WindowsCapturePaths {
            etl: &etl,
            pcapng: &out, // the app passes `out` (a .pcap path) here
            sentinel: &sentinel,
            heartbeat: &heartbeat,
            log: &log,
        },
    );

    // Deliver it exactly as the app does: `-EncodedCommand`, via the same
    // `windows_encoded_command` the app calls — not a copy, and not a
    // `.ps1` the app no longer writes. CI is already elevated, so this
    // skips only the `Start-Process -Verb RunAs` wrapper; the encoding and
    // the script body are the real ones.
    let encoded = live::windows_encoded_command(&script);
    let mut child = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
        .spawn()
        .expect("spawn supervisor");

    // Let pktmon actually start, then make traffic the capture can see.
    std::thread::sleep(std::time::Duration::from_secs(3));
    for _ in 0..2 {
        let _ = std::process::Command::new("ping")
            .args(["-n", "3", "8.8.8.8"])
            .output();
        let _ = std::process::Command::new("nslookup")
            .arg("example.com")
            .output();
    }

    // Stop the way Transit does: delete the sentinel.
    std::fs::remove_file(&sentinel).ok();

    // Wait for the script to finish (stop + convert), bounded.
    let mut status = None;
    for _ in 0..60 {
        if let Some(s) = child.try_wait().expect("try_wait") {
            status = Some(s);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    if status.is_none() {
        let _ = child.kill();
    }

    // The supervisor's own account — printed whatever happened, because it
    // is the diagnosis when the assertions below fail.
    let supervisor_log =
        std::fs::read_to_string(&log).unwrap_or_else(|_| "<no log written>".into());
    println!("--- supervisor log ---\n{supervisor_log}\n--- end log ---");
    std::io::stdout().flush().ok();

    // What etl2pcap ACTUALLY produced — the fact the last probe hid by
    // using a `.pcapng` --out. Print every file so its real name and size
    // are on the record, then resolve it the way the app now does.
    println!("--- capture directory contents ---");
    for e in std::fs::read_dir(dir.path())
        .into_iter()
        .flatten()
        .flatten()
    {
        let len = e.metadata().map(|m| m.len()).unwrap_or(0);
        println!("  {}  ({len} B)", e.file_name().to_string_lossy());
    }

    let status = status.expect("the supervisor script must exit, not hang");
    assert!(
        status.success(),
        "the supervisor script exited {status:?} — see the log above"
    );

    // The app's OWN resolver, against the app's OWN `.pcap` out path. This
    // is the exact call `pcap_capture_stop` makes; if it returns nothing
    // here it returns nothing there, and the "wrote no packets" error is
    // reproduced rather than papered over.
    let outputs = windows_capture_outputs(&out);
    println!(
        "--- windows_capture_outputs found {} file(s): {:?} ---",
        outputs.len(),
        outputs
    );
    let produced = outputs.first().unwrap_or_else(|| {
        panic!(
            "windows_capture_outputs found nothing for {} — etl2pcap's real \
             output name is in the directory listing above",
            out.display()
        )
    });

    // Our own reader must open what pktmon+etl2pcap produced. A capture we
    // cannot read is as useless as no capture.
    let file = CaptureFile::open(produced).expect("our reader must open the produced capture");
    let index = build(&file, IndexLimits::default()).expect("index the capture");
    println!(
        "*** CAPTURED {} PACKETS on {} ***",
        index.packet_count(),
        nic.description
    );
    // Not asserted: a specific CI vNIC may carry no traffic in the window.
    // The plumbing working — script exit 0, pcapng produced, reader opens
    // it — is what this test guarantees.
}
