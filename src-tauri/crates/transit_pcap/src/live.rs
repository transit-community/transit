//! Live capture: driving the operating system's own capture binary.
//!
//! Transit ships **no capture driver and no privileged code of its own**.
//! It spawns `tcpdump` on macOS and Linux (BSD-licensed, already
//! installed) or `pktmon` on Windows (in-box since Windows 10 / Server
//! 2019 1809), owns the resulting file, and does all indexing, dissection
//! and analysis itself.
//!
//! Notably absent: **Npcap**. Its free licence permits five installs and
//! exempts only Nmap, Wireshark and Microsoft Defender, so a commercial
//! subscription product depending on it would need a paid OEM
//! redistribution licence. Driving the binary the OS already ships avoids
//! the question entirely (plan §11).
//!
//! # The elevation ladder
//!
//! ```text
//! Start ──► try unprivileged
//!           ├─ works (a BPF group helper is installed) ──► no prompt at all
//!           └─ permission denied ──► one native admin prompt ──► retry
//! ```
//!
//! Anyone who already has Wireshark has a BPF-group helper, so `/dev/bpf*`
//! is readable and the common case prompts for nothing. We deliberately do
//! **not** widen `/dev/bpf*` ourselves: that would hand every process
//! running as the user permanent raw-capture rights on their machine, a
//! persistent downgrade Transit has no business making unilaterally.
//!
//! # This is the highest-risk code in the feature
//!
//! It builds a command line that runs as root. Three rules, each enforced
//! rather than intended:
//!
//! 1. **Arguments are an argv, never a shell string.** The one exception
//!    is the macOS elevation path, where `osascript` requires a shell
//!    string — so that path escapes for both shells it passes through and
//!    is covered by its own corpus test.
//! 2. **The capture filter is charset-validated before it is used at
//!    all** ([`validate_bpf`]), so the escaping above is a second line of
//!    defence rather than the only one.
//! 3. **The interface must be one we enumerated.** A caller-supplied
//!    interface string never reaches a command line.
//!
//! # Bounded by construction
//!
//! Rotation (`-C`/`-W`), a maximum duration, and a free-space precheck
//! mean a forgotten capture cannot fill a disk.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::error::{PcapError, Result};

/// Longest capture filter we will accept. Real ones are a line.
const MAX_BPF_LEN: usize = 1024;

/// Default per-file size and file count: 256 MB × 8 = a 2 GB ceiling.
pub const DEFAULT_MAX_FILE_MB: u32 = 256;
pub const DEFAULT_MAX_FILES: u32 = 8;
/// Default snaplen. `0` would mean "whole packet" to tcpdump; we spell
/// the real number so the UI can show it.
pub const DEFAULT_SNAPLEN: u32 = 262_144;
/// Headers-only snaplen offered as a one-click privacy option.
pub const HEADERS_ONLY_SNAPLEN: u32 = 128;
/// A capture stops itself after this long even if nobody presses Stop.
pub const DEFAULT_MAX_DURATION_SECS: u64 = 60 * 60;
/// Refuse to start without at least this much free space.
const MIN_FREE_BYTES: u64 = 512 * 1024 * 1024;

/// A network interface a capture can be started on.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Nic {
    /// The name passed to the capture binary. Never user-supplied.
    pub name: String,
    /// Human description, where the platform offers one.
    pub description: String,
    /// Best-effort "this interface is up".
    pub up: bool,
    /// True for loopback, which is worth flagging: capturing it records
    /// only traffic that never left the machine.
    pub loopback: bool,
}

/// What the user asked to capture.
#[derive(Debug, Clone)]
pub struct CaptureRequest {
    /// Must match a [`Nic::name`] from [`list_interfaces`].
    pub interface: String,
    /// BPF capture filter, already validated.
    pub bpf: Option<String>,
    pub snaplen: u32,
    pub max_file_mb: u32,
    pub max_files: u32,
    pub max_duration_secs: u64,
}

impl Default for CaptureRequest {
    fn default() -> Self {
        Self {
            interface: String::new(),
            bpf: None,
            snaplen: DEFAULT_SNAPLEN,
            max_file_mb: DEFAULT_MAX_FILE_MB,
            max_files: DEFAULT_MAX_FILES,
            max_duration_secs: DEFAULT_MAX_DURATION_SECS,
        }
    }
}

/// Where a capture is in its life.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CaptureState {
    Starting,
    /// The unprivileged attempt was refused; the user has been asked for
    /// administrator rights.
    Elevating,
    Running,
    Stopping,
    Stopped,
    Failed {
        reason: String,
    },
}

// ---------------------------------------------------------------------
// Capture-filter validation
// ---------------------------------------------------------------------

/// Validate a BPF capture filter.
///
/// A conservative allowlist rather than a blocklist of shell
/// metacharacters. BPF's own grammar needs letters, digits, dots, colons,
/// slashes, brackets, comparison operators, arithmetic and parentheses —
/// and nothing else. Everything a shell would find interesting (`$`,
/// backtick, `;`, `|`, `&`, quotes, backslash, newline) is simply not in
/// the set, so a filter that passes here has nothing to escape.
///
/// This runs before the string is used in any form, on every platform,
/// including the paths that build an argv and could not be injected
/// anyway. Defence in depth is cheap here and the failure mode is not.
pub fn validate_bpf(filter: &str) -> std::result::Result<(), String> {
    if filter.len() > MAX_BPF_LEN {
        return Err(format!(
            "the capture filter is {} characters; the limit is {MAX_BPF_LEN}",
            filter.len()
        ));
    }
    for (i, c) in filter.chars().enumerate() {
        let ok = c.is_ascii_alphanumeric()
            || matches!(
                c,
                ' ' | '.'
                    | ':'
                    | '/'
                    | '-'
                    | '_'
                    | '('
                    | ')'
                    | '['
                    | ']'
                    | '='
                    | '!'
                    | '<'
                    | '>'
                    | '&'
                    | '|'
                    | '+'
                    | '*'
                    | '%'
                    | ','
            );
        if !ok {
            return Err(format!(
                "the capture filter contains `{c}` at position {}, which is not valid in a BPF \
                 expression",
                i + 1
            ));
        }
    }
    // No further heuristics. An earlier version also refused a lone `&`
    // or `|` between terms on the theory that it was a stray shell idiom
    // — but `tcp[13] & 2 != 0` is perfectly good BPF, so the rule broke
    // real filters to "catch" something that was never dangerous: the
    // expression is passed as ONE argv element and never reaches a shell.
    // A malformed BPF expression is tcpdump's to reject, and it does so
    // cleanly with a message worth showing the user.
    Ok(())
}

// ---------------------------------------------------------------------
// Interface enumeration
// ---------------------------------------------------------------------

/// List capturable interfaces.
///
/// On Unix this shells out to `tcpdump -D`, which is exactly the list
/// tcpdump will accept and needs no privileges to produce. Deriving the
/// list from the same tool that will use it means the UI can never offer
/// an interface the capture would then reject.
#[cfg(unix)]
pub async fn list_interfaces() -> Result<Vec<Nic>> {
    let out = tokio::process::Command::new(tcpdump_path())
        .arg("-D")
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| {
            PcapError::Io(std::io::Error::new(
                e.kind(),
                format!("could not run tcpdump: {e}. Packet capture needs tcpdump installed."),
            ))
        })?;

    if !out.status.success() {
        return Err(interface_listing_failed(
            "tcpdump -D",
            &out.status,
            &out.stderr,
        ));
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut nics = Vec::new();
    for line in text.lines() {
        // `1.en0 [Up, Running]` or `2.lo0 [Up, Running, Loopback]`
        let Some((_, rest)) = line.split_once('.') else {
            continue;
        };
        let (name, flags) = match rest.split_once(' ') {
            Some((n, f)) => (n, f),
            None => (rest, ""),
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let lower = flags.to_ascii_lowercase();
        nics.push(Nic {
            name: name.to_string(),
            description: flags.trim().trim_matches(['[', ']']).to_string(),
            up: lower.contains("up") || lower.contains("running"),
            loopback: lower.contains("loopback") || name.starts_with("lo"),
        });
    }
    Ok(nics)
}

/// The PowerShell that enumerates adapters.
///
/// Tab-delimited rather than JSON or CSV: the fields are ours to choose,
/// an adapter name cannot contain a tab, and it needs no parser that can
/// be wrong about quoting. (A hand-rolled reader for Windows output is
/// exactly what shipped an empty dropdown, twice.)
///
/// Public because the Windows integration probe must run THIS command
/// rather than a copy of it. It briefly had a copy, and the two drifted
/// within the hour — the probe kept asking for the old field order and
/// reported zero adapters while the app worked fine.
pub const GET_NETADAPTER_PS: &str = "Get-NetAdapter | ForEach-Object { \
     [string]$_.InterfaceIndex + [char]9 + $_.MacAddress + [char]9 + $_.Status + \
     [char]9 + $_.Name + [char]9 + $_.InterfaceDescription }";

/// Windows: enumerate adapters with `Get-NetAdapter`, unprivileged.
///
/// # Why not pktmon
///
/// **pktmon needs Administrator for everything, including merely
/// listing.** An unelevated `pktmon comp list` exits 5 with "Failed to
/// communicate with the PktMon driver: Access is denied." Enumerating
/// through pktmon would therefore mean a UAC prompt to populate a
/// dropdown, before the user has asked to capture anything — which is not
/// something an application should do. This is the one place Windows
/// differs structurally from Unix, where `tcpdump -D` enumerates
/// unprivileged and the single prompt belongs to Start.
///
/// `Get-NetAdapter` needs no elevation, so the list comes from there and
/// the pktmon component id is resolved later, INSIDE the one elevated
/// session Start already opens (see [`windows_supervisor_script`]).
///
/// # Why the MAC address is the join key
///
/// The component id is not derivable from anything `Get-NetAdapter`
/// returns. `InterfaceIndex` is a different number in a different
/// namespace — on one laptop Wi-Fi is ifIndex 13 and pktmon component 17.
/// The MAC is rendered identically by both (`04-33-C2-C4-CE-F8`) and is
/// unique per adapter, so it is what [`Nic::name`] carries on Windows and
/// what the elevated script matches on.
#[cfg(windows)]
pub async fn list_interfaces() -> Result<Vec<Nic>> {
    let out = tokio::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            GET_NETADAPTER_PS,
        ])
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| {
            PcapError::Io(std::io::Error::new(
                e.kind(),
                format!("could not run PowerShell to list network adapters: {e}"),
            ))
        })?;

    if !out.status.success() {
        return Err(interface_listing_failed(
            "Get-NetAdapter",
            &out.status,
            &out.stderr,
        ));
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let nics = parse_net_adapters(&text);
    if nics.is_empty() {
        // Succeeded and produced nothing we recognized: the OUTPUT SHAPE
        // is not what the parser expects, which is a very different thing
        // from "this machine has no adapters" — and an empty dropdown
        // reports the second while the first is true.
        return Err(PcapError::Io(std::io::Error::other(format!(
            "`Get-NetAdapter` ran but listed no adapters. Output was: {}",
            crate::sanitize::long_field(text.trim())
        ))));
    }
    Ok(nics)
}

/// Parse the tab-delimited `Get-NetAdapter` rows emitted above:
/// `ifIndex \t MAC \t Status \t Name \t InterfaceDescription`, one per line.
#[cfg(any(windows, test))]
pub(crate) fn parse_net_adapters(text: &str) -> Vec<Nic> {
    let mut nics = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').map(str::trim).collect();
        if f.len() < 5 {
            continue;
        }
        let (ifindex, mac, status, name, desc) = (f[0], f[1], f[2], f[3], f[4]);
        if ifindex.is_empty() || !ifindex.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let _ = mac;
        nics.push(Nic {
            // The NDIS interface index, and it has to be.
            //
            // A MAC is NOT unique: on an SR-IOV machine a synthetic
            // adapter and its virtual function share a hardware address,
            // so one MAC names two pktmon components and the capture
            // silently lands on whichever was listed first. Observed on a
            // stock Windows runner — a Mellanox VF bonded to a NetVsc
            // adapter, both `7C-1E-52-5C-D0-FF`, pktmon ids 3 and 38.
            //
            // The interface index distinguishes them (3 and 14), and
            // pktmon carries the same value as a component property, so
            // the join is exact. Names cannot do this either: Windows
            // calls that adapter "Microsoft Hyper-V Network Adapter #3"
            // and pktmon calls it "Microsoft NetVsc Nic #3".
            name: ifindex.to_string(),
            // Both halves, because neither alone is enough: "Wi-Fi" does
            // not say which card, and "Intel(R) Wi-Fi 6 AX201 160MHz" does
            // not say which connection it is on a machine with two.
            description: if desc.is_empty() || desc == name {
                name.to_string()
            } else {
                format!("{name} \u{2014} {desc}")
            },
            // A real reading at last: Up / Disconnected / Disabled.
            // Capturing on a disconnected adapter is legal and records
            // nothing, so it is worth showing rather than assuming.
            up: status.eq_ignore_ascii_case("up"),
            loopback: name.to_ascii_lowercase().contains("loopback")
                || desc.to_ascii_lowercase().contains("loopback"),
        });
    }
    nics
}

/// One error for "the interface listing command did not work".
///
/// Includes the exit status AND stderr, because the alternative — which
/// this code did until a Windows smoke test found it — is returning an
/// empty list, where "the command failed" and "this machine has no network
/// adapters" are the same empty dropdown.
#[cfg(any(unix, windows))]
fn interface_listing_failed(
    what: &str,
    status: &std::process::ExitStatus,
    stderr: &[u8],
) -> PcapError {
    let err = String::from_utf8_lossy(stderr);
    let err = err.trim();
    let detail = if err.is_empty() {
        format!("exited with {status}")
    } else {
        format!("exited with {status}: {}", crate::sanitize::long_field(err))
    };
    PcapError::Io(std::io::Error::other(format!(
        "could not list network interfaces — `{what}` {detail}"
    )))
}

#[cfg(not(any(unix, windows)))]
pub async fn list_interfaces() -> Result<Vec<Nic>> {
    Ok(Vec::new())
}

// ---------------------------------------------------------------------
// Command construction
// ---------------------------------------------------------------------

/// Gated because Windows drives `pktmon` and never resolves a tcpdump
/// path, so an ungated definition is dead code there — and CI runs clippy
/// with `-D warnings` on every OS, which turns that into a build failure
/// on the Windows leg only.
#[cfg(unix)]
fn tcpdump_path() -> &'static str {
    // macOS ships it here and the absolute path avoids picking up
    // something earlier on a modified PATH; Linux distributions vary, so
    // there we let PATH resolve it.
    if cfg!(target_os = "macos") {
        "/usr/sbin/tcpdump"
    } else {
        "tcpdump"
    }
}

/// Build the tcpdump argv.
///
/// `-U` makes it flush each packet, which is what lets the indexer tail a
/// capture that is still running. `-n` skips reverse DNS, which would
/// otherwise generate traffic *into* the capture.
///
/// `drop_to_user` adds `-Z <user>`, and on Linux it is **required for a
/// rotating capture to produce any file at all**. Debian/Ubuntu build
/// tcpdump with `--with-user=tcpdump`, so a capture started as root drops
/// to the unprivileged `tcpdump` user before it writes anything. The first
/// file usually predates the drop and survives; every `-C` rotation file
/// after it is created *after* the drop, inside a directory owned by the
/// invoking user, and fails with "Permission denied". Naming the invoking
/// user makes the files land owned by the person who asked for them, which
/// is also what lets Transit read the capture back without elevation.
///
/// `None` on macOS deliberately: its tcpdump does not drop privileges, so
/// there is no problem to solve and no reason to alter a path that works.
pub fn build_tcpdump_args(
    req: &CaptureRequest,
    out: &Path,
    drop_to_user: Option<&str>,
) -> Vec<String> {
    let mut args = vec![
        "-i".into(),
        req.interface.clone(),
        "-w".into(),
        out.to_string_lossy().into_owned(),
        "-s".into(),
        req.snaplen.to_string(),
        "-U".into(),
        "-n".into(),
        "-C".into(),
        req.max_file_mb.to_string(),
        "-W".into(),
        req.max_files.to_string(),
    ];
    if let Some(user) = drop_to_user {
        let user = user.trim();
        if !user.is_empty() {
            args.push("-Z".into());
            args.push(user.to_string());
        }
    }
    // NOTE: no `-G`. It looks like the natural way to bound duration, but
    // it means "rotate every N seconds", and with no strftime escape in
    // the `-w` name tcpdump then OVERWRITES the same file each period —
    // silently discarding everything older, while `-C`/`-W` are trying to
    // rotate on size at the same time. The duration bound is enforced by
    // Transit instead (the elevated runner's sentinel loop, `stop_all` on
    // app exit), where it does not fight the size bound.
    if let Some(bpf) = &req.bpf {
        let bpf = bpf.trim();
        if !bpf.is_empty() {
            // The filter is the trailing operand, and it is passed as ONE
            // argv element. Splitting it on spaces would let a filter term
            // be read as an option.
            args.push(bpf.to_string());
        }
    }
    args
}

/// Build the pktmon start argv.
///
/// `--comp <id>` targets the chosen adapter. There is a tempting
/// alternative — `--comp nics`, which captures every adapter — and it is
/// deliberately not used as a fallback: a user who asked to capture one
/// interface and silently got all of them has been handed a data-safety
/// problem, not a degraded feature.
/// Resolve `%IFINDEX%` (an NDIS interface index) to a pktmon component id.
///
/// Held as a plain constant rather than built with `format!` so its
/// PowerShell braces read as PowerShell instead of as doubled escapes.
/// The only substitution is the interface index, which is shell-quoted by
/// the caller and is digits from `Get-NetAdapter` regardless.
const PKTMON_RESOLVE_COMPONENT: &str = concat!(
    "$want = [int]%IFINDEX%;\n",
    "$listing = (pktmon list --json | Out-String);\n",
    "if (-not $listing.Trim()) { Write-Error 'pktmon listed no components'; exit 4 };\n",
    "$comps = @(($listing | ConvertFrom-Json).Components | Where-Object {\n",
    "  $_.Properties | Where-Object { $_.Name -eq 'ifIndex' -and [int]$_.Value -eq $want }\n",
    "});\n",
    "if ($comps.Count -eq 0) {\n",
    "  Write-Error \"no pktmon component has interface index $want\"; exit 4 };\n",
    "$ids = @($comps | ForEach-Object { $_.Id } | Sort-Object -Unique);\n",
    "if ($ids.Count -ne 1) {\n",
    "  Write-Error \"interface index $want maps to components $($ids -join ',')\"; exit 4 };\n",
    "$comp = $ids[0];\n",
);

/// Stands in for the pktmon component id until the elevated script can
/// look it up. Deliberately not a legal component id, so a build that
/// forgot to substitute it fails loudly at pktmon rather than capturing
/// on some arbitrary adapter.
pub const COMP_PLACEHOLDER: &str = "%COMPONENT%";

pub fn build_pktmon_args(req: &CaptureRequest, out: &Path) -> Vec<String> {
    vec![
        "start".into(),
        "--capture".into(),
        "--comp".into(),
        // A placeholder, not the adapter: on Windows the caller only has
        // the MAC at this point, and the component id can only be looked
        // up inside the elevated session. `windows_supervisor_script`
        // substitutes the id it resolves there.
        COMP_PLACEHOLDER.into(),
        "--pkt-size".into(),
        // pktmon's own help: "To always log the entire packet set this to
        // 0." `SNAPLEN_FULL` is a tcpdump idiom (262144) and means nothing
        // here — at best it is a very large byte count, at worst rejected.
        // Anything below it is a real per-packet cap and passes through.
        if req.snaplen >= DEFAULT_SNAPLEN {
            "0".to_string()
        } else {
            req.snaplen.to_string()
        },
        "--file-size".into(),
        req.max_file_mb.to_string(),
        "--log-mode".into(),
        // `circular`, not `multi-file`, and this is a correctness AND a
        // safety fix.
        //
        // Correctness: `multi-file` (pktmon's help: "no limit on number of
        // captured events") rolls to NEW, suffixed files as `--file-size`
        // is reached — so `--file-name probe.etl` does not stay
        // `probe.etl`, and the `pktmon etl2pcap <that exact name>` on stop
        // converts a file that is not there. That is the pipeline
        // producing no pcapng.
        //
        // Safety: `multi-file` has no total cap, which flatly contradicts
        // T44's "bounded by construction, a forgotten capture cannot fill
        // a disk." `circular` is a single file of `--file-size` MB whose
        // oldest events are overwritten — one deterministic name for
        // etl2pcap, and a hard disk bound. It is also pktmon's default, so
        // it is the mode most exercised in the wild.
        "circular".into(),
        "--file-name".into(),
        out.to_string_lossy().into_owned(),
    ]
}

/// A term of a BPF filter that pktmon can express.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PktmonFilter {
    Host(String),
    Port(u16),
    Transport(&'static str),
    Vlan(u16),
    MacHost(String),
}

impl PktmonFilter {
    /// The `pktmon filter add` argv for this term.
    pub fn to_args(&self) -> Vec<String> {
        match self {
            Self::Host(h) => vec!["-i".into(), h.clone()],
            Self::Port(p) => vec!["-p".into(), p.to_string()],
            Self::Transport(t) => vec!["-t".into(), (*t).into()],
            Self::Vlan(v) => vec!["-v".into(), v.to_string()],
            Self::MacHost(m) => vec!["-m".into(), m.clone()],
        }
    }
}

/// Combine AND-ed terms into the argv for a SINGLE `pktmon filter add`.
///
/// This is a correctness boundary, not a tidiness one. pktmon's own help:
/// *"For a packet to be reported, it must match all conditions specified
/// in at least one filter."* Conditions within one filter are AND-ed;
/// separate filters are OR-ed.
///
/// Emitting one `filter add` per term — which this code did — turns
/// `tcp port 443 and host 10.0.0.1` into "all TCP, OR anything on port
/// 443, OR anything touching 10.0.0.1". The user asked to record one
/// conversation and would have recorded the segment. That is the silent
/// widening plan §3a calls a data-safety incident, in the function written
/// to prevent it.
///
/// Where pktmon takes two values for a condition (`-i ip [ip2]`,
/// `-p port [port2]`, `-m mac [mac2]`) it matches packets containing
/// BOTH, which is what `host A and host B` means in BPF — so those pair
/// up exactly. Anything beyond a pair, or a contradiction like two
/// transports, is REFUSED rather than approximated: a filter that cannot
/// be expressed precisely must not become a wider one.
pub fn pktmon_filter_args(filters: &[PktmonFilter]) -> std::result::Result<Vec<String>, String> {
    if filters.is_empty() {
        return Ok(Vec::new());
    }

    let mut ips: Vec<String> = Vec::new();
    let mut ports: Vec<String> = Vec::new();
    let mut macs: Vec<String> = Vec::new();
    let mut vlans: Vec<String> = Vec::new();
    let mut transports: Vec<&str> = Vec::new();

    for f in filters {
        match f {
            PktmonFilter::Host(h) => ips.push(h.clone()),
            PktmonFilter::Port(p) => ports.push(p.to_string()),
            PktmonFilter::MacHost(m) => macs.push(m.clone()),
            PktmonFilter::Vlan(v) => vlans.push(v.to_string()),
            PktmonFilter::Transport(t) => {
                if !transports.contains(t) {
                    transports.push(t);
                }
            }
        }
    }

    let too_many = |what: &str, n: usize| {
        format!(
            "a capture filter with {n} {what} conditions cannot be expressed exactly on \
             Windows (pktmon takes at most two) — narrow the filter, or capture wider and \
             use the view filter afterwards"
        )
    };
    if ips.len() > 2 {
        return Err(too_many("host", ips.len()));
    }
    if ports.len() > 2 {
        return Err(too_many("port", ports.len()));
    }
    if macs.len() > 2 {
        return Err(too_many("MAC", macs.len()));
    }
    if vlans.len() > 1 {
        return Err(too_many("VLAN", vlans.len()));
    }
    if transports.len() > 1 {
        return Err(format!(
            "a capture filter cannot require {} at the same time",
            transports.join(" and ")
        ));
    }

    // A name, so `pktmon filter list` shows whose filter this is on a
    // machine an administrator is inspecting.
    let mut args: Vec<String> = vec!["TransitCE".into()];
    if let Some(t) = transports.first() {
        args.push("-t".into());
        args.push((*t).into());
    }
    if !ips.is_empty() {
        args.push("-i".into());
        args.extend(ips);
    }
    if !ports.is_empty() {
        args.push("-p".into());
        args.extend(ports);
    }
    if !macs.is_empty() {
        args.push("-m".into());
        args.extend(macs);
    }
    if let Some(v) = vlans.first() {
        args.push("-v".into());
        args.push(v.clone());
    }
    Ok(args)
}

/// Translate the BPF subset pktmon can express.
///
/// **Anything outside the subset is refused by name.** This is the rule
/// that matters: a user who writes `host 10.0.0.5` and silently gets the
/// whole segment recorded has a data-safety incident, not a feature gap.
/// Refusing loudly is the only acceptable failure here (plan §3a).
pub fn bpf_to_pktmon(bpf: &str) -> std::result::Result<Vec<PktmonFilter>, String> {
    let bpf = bpf.trim();
    if bpf.is_empty() {
        return Ok(Vec::new());
    }
    let lower = bpf.to_ascii_lowercase();
    // Only `and`-joined terms translate. `or` would need pktmon's
    // multiple-filter semantics (filters are OR-ed, terms within one are
    // AND-ed), which inverts the nesting and is easy to get subtly wrong.
    if lower.contains(" or ") || lower.contains("||") {
        return Err("`or` in a capture filter is not supported on Windows — \
                    use a single `and`-joined expression, or filter after capture."
            .into());
    }
    if lower.contains(" not ") || lower.starts_with("not ") || lower.contains('!') {
        return Err("`not` in a capture filter is not supported on Windows — \
                    filter after capture instead."
            .into());
    }

    let mut out = Vec::new();
    for term in lower.split(" and ").flat_map(|t| t.split("&&")) {
        let term = term.trim();
        if term.is_empty() {
            continue;
        }
        let words: Vec<&str> = term.split_whitespace().collect();
        match words.as_slice() {
            ["tcp"] => out.push(PktmonFilter::Transport("tcp")),
            ["udp"] => out.push(PktmonFilter::Transport("udp")),
            ["icmp"] => out.push(PktmonFilter::Transport("icmp")),
            ["host", h] | ["src", "host", h] | ["dst", "host", h] => {
                // pktmon does not distinguish direction, so `src host` is
                // translated as `host` and the difference is stated rather
                // than silently applied.
                if words[0] != "host" {
                    return Err(format!(
                        "`{}` is not supported on Windows — pktmon cannot filter by direction. \
                         Use `host {h}` and filter by direction after capture.",
                        words[..2].join(" ")
                    ));
                }
                out.push(PktmonFilter::Host((*h).to_string()));
            }
            ["port", p] => {
                let port: u16 = p
                    .parse()
                    .map_err(|_| format!("`{p}` is not a port number"))?;
                out.push(PktmonFilter::Port(port));
            }
            ["tcp", "port", p] | ["udp", "port", p] => {
                let port: u16 = p
                    .parse()
                    .map_err(|_| format!("`{p}` is not a port number"))?;
                out.push(PktmonFilter::Transport(if words[0] == "tcp" {
                    "tcp"
                } else {
                    "udp"
                }));
                out.push(PktmonFilter::Port(port));
            }
            ["vlan", v] => {
                let vlan: u16 = v.parse().map_err(|_| format!("`{v}` is not a VLAN id"))?;
                out.push(PktmonFilter::Vlan(vlan));
            }
            ["ether", "host", m] => out.push(PktmonFilter::MacHost((*m).to_string())),
            _ => {
                return Err(format!(
                    "`{term}` cannot be translated to a Windows capture filter. Supported forms \
                     are: `host <ip>`, `port <n>`, `tcp`, `udp`, `icmp`, `tcp port <n>`, \
                     `udp port <n>`, `vlan <id>`, `ether host <mac>`, joined with `and`."
                ));
            }
        }
    }
    if out.len() > 32 {
        return Err("pktmon supports at most 32 filter terms".into());
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// Elevation
// ---------------------------------------------------------------------

/// Escape a string for embedding in an AppleScript string literal.
fn applescript_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', r"\\").replace('"', "\\\""))
}

/// The full `osascript -e` program that runs `argv` as root, with one
/// native authentication prompt.
///
/// The string passes through two layers — AppleScript's literal syntax
/// and then `sh` — so it is escaped for both, in that order. The capture
/// filter has already been charset-validated to contain nothing either
/// layer treats specially, making this the second line of defence.
pub fn macos_elevated_script(program: &str, argv: &[String]) -> String {
    let mut command = shell_quote(program);
    for a in argv {
        command.push(' ');
        command.push_str(&shell_quote(a));
    }
    format!(
        "do shell script {} with administrator privileges",
        applescript_quote(&command)
    )
}

/// The Linux capture argv: `<program> <args…>`, unchanged.
///
/// An argv throughout — no shell is involved, so nothing needs escaping.
///
/// ⚠️ Despite the name this does NOT elevate, and nothing in production
/// calls it — the real Linux elevation is `pkexec /bin/sh -c <script>` in
/// `transit_app::pcap::spawn_elevated`. The previous doc comment claimed
/// this returned `pkexec <program> …`, which sent a Linux capture
/// investigation down the wrong path; the name and the comment are kept
/// honest here rather than the function deleted, because its one caller is
/// a test that pins the argv shape.
pub fn linux_elevated_args(program: &str, argv: &[String]) -> Vec<String> {
    let mut out = vec![program.to_string()];
    out.extend(argv.iter().cloned());
    out
}

/// Does this error text mean "you are not allowed to capture"?
///
/// tcpdump's wording varies by platform and version, so this matches on
/// the recognizable fragments rather than an exact string. A false
/// negative here costs an unnecessary error message; a false positive
/// costs a spurious password prompt, so the patterns are specific.
pub fn is_permission_error(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    s.contains("permission denied")
        || s.contains("operation not permitted")
        || s.contains("you don't have permission")
        || s.contains("must be root")
        || (s.contains("/dev/bpf") && s.contains("error"))
        || s.contains("socket: operation not permitted")
}

/// Does this error mean "I cannot create the capture FILE" rather than "I
/// cannot capture on this interface"?
///
/// The distinction decides whether elevating is worth a password prompt.
/// Both failures say "Permission denied", so [`is_permission_error`] alone
/// cannot tell them apart — and it is reached first on the unprivileged
/// attempt, which is how an unwritable output folder came to raise a
/// pkexec prompt whose elevated retry then failed exactly the same way.
/// The user saw a password dialog, granted it, and got an empty capture.
///
/// Elevation cannot fix this class, because on Linux the refusal need not
/// come from the filesystem at all. Debian/Ubuntu confine tcpdump with an
/// AppArmor profile that carries
/// `audit deny @{HOME}/.*/** mrwkl` — an explicit deny, which in AppArmor
/// beats every allow rule — so no file may be created anywhere beneath a
/// hidden folder in the user's home directory. AppArmor mediates above
/// uid, so running as root changes nothing: the denial is identical, and
/// the audit record reads `operation="mknod" denied_mask="c" fsuid=0`.
///
/// Matching is anchored on the output path, which tcpdump echoes verbatim
/// in this message (`tcpdump: /path/out.pcap: Permission denied`). The
/// given path is also a prefix of every `-C` rotation name it derives from
/// it (`out.pcap0`, `out.pcap1`, …), so one `contains` covers both.
pub fn is_output_permission_error(stderr: &str, out: &Path) -> bool {
    let s = stderr.to_ascii_lowercase();
    if !s.contains("permission denied") {
        return false;
    }
    let out = out.to_string_lossy().to_ascii_lowercase();
    !out.is_empty() && s.contains(&out)
}

// ---------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------

/// Refuse to start a capture that cannot possibly work, before prompting
/// the user for anything.
pub fn preflight(req: &CaptureRequest, nics: &[Nic], out_dir: &Path) -> Result<()> {
    if !nics.iter().any(|n| n.name == req.interface) {
        return Err(PcapError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "`{}` is not a capturable interface on this machine",
                req.interface
            ),
        )));
    }
    if let Some(bpf) = &req.bpf {
        if let Err(e) = validate_bpf(bpf) {
            return Err(PcapError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                e,
            )));
        }
    }
    if req.max_file_mb == 0 || req.max_files == 0 {
        return Err(PcapError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "a capture needs a non-zero rotation size and file count",
        )));
    }
    // A capture with no ceiling is how a laptop fills its disk overnight.
    let ceiling = u64::from(req.max_file_mb) * u64::from(req.max_files) * 1_000_000;
    if let Some(free) = free_space(out_dir) {
        if free < MIN_FREE_BYTES {
            return Err(PcapError::Io(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                format!(
                    "only {} MB free where captures are stored; at least {} MB is needed",
                    free / 1_000_000,
                    MIN_FREE_BYTES / 1_000_000
                ),
            )));
        }
        if ceiling > free {
            return Err(PcapError::Io(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                format!(
                    "this capture could grow to {} MB but only {} MB is free — reduce the file \
                     size or count",
                    ceiling / 1_000_000,
                    free / 1_000_000
                ),
            )));
        }
    }
    Ok(())
}

/// Free bytes on the filesystem holding `path`, if we can tell.
///
/// Best-effort by design: `df` is not worth an FFI dependency, and a
/// missing answer means the precheck is skipped rather than the capture
/// refused.
fn free_space(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        let out = std::process::Command::new("df")
            .arg("-k")
            .arg(path)
            .stdin(Stdio::null())
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let line = text.lines().nth(1)?;
        let kb: u64 = line.split_whitespace().nth(3)?.parse().ok()?;
        Some(kb * 1024)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Where a capture's files are written.
pub fn capture_path(dir: &Path, stamp: &str, id: &str) -> PathBuf {
    // The id keeps two captures started in the same second apart; the
    // stamp makes the directory browsable by a human.
    dir.join(format!("capture-{stamp}-{id}.pcap"))
}

/// How often Transit touches a running capture's heartbeat file.
pub const HEARTBEAT_INTERVAL_SECS: u64 = 5;

/// How stale a heartbeat may get before the supervised runner concludes
/// Transit is gone and stops the capture itself.
///
/// Six intervals: long enough that a busy or suspended app is not killed
/// mid-capture, short enough that a crash does not leave a root capture
/// recording for long.
pub const HEARTBEAT_STALE_SECS: u64 = HEARTBEAT_INTERVAL_SECS * 6;

/// The shell program that supervises a capture on behalf of Transit.
///
/// Every capture runs under this, privileged or not, and the reason is
/// the failure this function exists to prevent: a Transit that dies
/// WITHOUT a clean exit — a crash, a force-quit, a `tauri dev` rebuild —
/// never runs its own teardown, so a directly-spawned `tcpdump` is simply
/// reparented to init and keeps recording the network as root until the
/// machine reboots. Observed in the wild during the first smoke test.
///
/// Two independent stop conditions, so no single failure leaves a capture
/// running:
///
/// 1. **The stop sentinel disappears.** That is a clean Stop, and on the
///    elevated path it means stopping costs an unprivileged file delete
///    rather than a second password prompt.
/// 2. **The heartbeat goes stale.** Transit touches it every few seconds
///    while it lives; if it stops being touched, Transit is gone and the
///    capture stops itself.
///
/// `$!` is the capture's pid, so the `kill` targets the capture rather
/// than the shell — killing the supervisor alone would leave `tcpdump`
/// behind, which is the whole problem restated.
///
/// **The stop signal is `TERM`, and it must not be `INT`.** POSIX requires
/// a non-interactive shell to set `SIGINT` (and `SIGQUIT`) to `SIG_IGN`
/// for commands it starts in the background, and `tcpdump` here is exactly
/// that — `cmd & CAPPID=$!` inside `sh -c`. So `kill -INT $CAPPID` is a
/// silent no-op: the supervisor correctly notices the sentinel is gone,
/// fires a signal the child is immune to, and then blocks in `wait`
/// forever while `tcpdump` keeps recording as root. That is precisely the
/// orphan this whole function exists to prevent, reintroduced one line
/// from the end. Verified on macOS: `sh -c 'sleep 30 & kill -INT $!'`
/// leaves `sleep` running; `-TERM` kills it.
pub fn supervisor_script(capture_cmd: &str, sentinel: &Path, heartbeat: &Path) -> String {
    let sentinel = shell_quote(&sentinel.to_string_lossy());
    let heartbeat = shell_quote(&heartbeat.to_string_lossy());
    format!(
        // `alive` uses `ps -o state=`, NOT `kill -0`, and that distinction
        // is the whole reason this helper exists: `kill -0` succeeds for a
        // ZOMBIE. A capture that dies instantly — which is what a
        // permission error looks like — leaves a zombie the shell has not
        // reaped, so `kill -0` reports it alive, the loop runs once and
        // blocks on `sleep 1`, and the supervisor survives ~1015 ms. The
        // caller's "did it fail immediately?" window is shorter than that,
        // so the failure was invisible: no elevation prompt, no packets,
        // and a capture that silently recorded nothing. An empty state
        // means gone; `Z` means gone but unreaped. Both are dead.
        //
        // The heartbeat read tries `stat -c %Y` (GNU) BEFORE `stat -f %m`
        // (BSD), and that order is load-bearing — the reverse shipped and
        // broke Linux capture entirely. On GNU coreutils `-f` is
        // `--file-system`, NOT a format flag: `stat -f %m FILE` fails on
        // `%m` but still prints a multi-line filesystem report for FILE to
        // stdout and exits non-zero, so the `||` fallback ran too and
        // appended the real mtime. `BEAT` became a blob, `$((NOW - BEAT))`
        // died with "Illegal number", and dash took the whole supervisor
        // with it on the FIRST iteration — before `kill -TERM`, which is
        // how the orphaned-root-tcpdump this heartbeat exists to prevent
        // could come back. macOS is unaffected either way: BSD `stat` has
        // no `-c`, so it fails cleanly to stderr with no stdout and falls
        // through to `-f %m`.
        //
        // The `case` guard is defence in depth. A non-numeric BEAT must
        // degrade to "stale" (0), never kill the shell — the failure mode
        // it prevents is severe enough to be worth a line of shell.
        "alive() {{ s=$(ps -o state= -p $1 2>/dev/null | head -1); \
           case \"$s\" in ''|Z*) return 1;; *) return 0;; esac; }}; \
         {capture_cmd} & CAPPID=$!; \
         sleep 0.3; \
         alive $CAPPID || {{ wait $CAPPID; exit 3; }}; \
         while alive $CAPPID; do \
           [ -e {sentinel} ] || break; \
           NOW=$(date +%s); \
           BEAT=$(stat -c %Y {heartbeat} 2>/dev/null || stat -f %m {heartbeat} 2>/dev/null || echo 0); \
           case \"$BEAT\" in *[!0-9]*|'') BEAT=0;; esac; \
           [ $((NOW - BEAT)) -lt {stale} ] || break; \
           sleep 1; \
         done; \
         kill -TERM $CAPPID 2>/dev/null; \
         n=0; \
         while alive $CAPPID && [ $n -lt {grace} ]; do n=$((n + 1)); sleep 1; done; \
         alive $CAPPID && kill -KILL $CAPPID 2>/dev/null; \
         wait $CAPPID 2>/dev/null",
        stale = HEARTBEAT_STALE_SECS,
        grace = STOP_GRACE_SECS
    )
}

/// How long the supervisor waits for a `SIGTERM`ed capture to exit before
/// it escalates to `SIGKILL`.
///
/// Public because `transit_app`'s own stop timeout is derived from it —
/// waiting less than the supervisor's escalation budget would time out
/// mid-escalation.
///
/// A hard kill cannot truncate a record, because captures run with `-U`
/// (packet-buffered): every packet is already written by the time the next
/// one arrives, and the pcap format has no trailer, so any prefix is a
/// valid file. The reader tolerates a short final record regardless
/// (`ScanSummary::truncated_tail`).
pub const STOP_GRACE_SECS: u64 = 5;

/// Quote one argument for a POSIX shell using single quotes.
///
/// Public so `transit_app` builds its supervisor command with the same
/// quoting the elevation path uses — one implementation, not two that can
/// drift.
pub fn shell_quote(arg: &str) -> String {
    // A single quote inside single quotes is closed, escaped, reopened.
    format!("'{}'", arg.replace('\'', r"'\''"))
}

/// Join a program and its arguments into a shell command string.
pub fn shell_join(program: &str, args: &[String]) -> String {
    let mut out = shell_quote(program);
    for a in args {
        out.push(' ');
        out.push_str(&shell_quote(a));
    }
    out
}

/// Quote one argument for PowerShell using single quotes.
///
/// PowerShell escapes an embedded single quote by doubling it. Only the
/// Windows supervisor needs this; every other Windows path is an argv.
pub fn ps_quote(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "''"))
}

/// Encode a PowerShell script for `powershell -EncodedCommand`.
///
/// This is how the elevated supervisor script is delivered, and the choice
/// is both a robustness and a SECURITY one.
///
/// Robustness: the script is multi-line and full of `$`, quotes and
/// braces, and it crosses three parsers before it runs (the launcher's
/// `-Command`, `Start-Process -ArgumentList` splitting, the elevated
/// process's own parsing). Passing it inline as text did not survive that
/// — the elevated PowerShell got a mangled script and wrote nothing at
/// all. Base64 is `[A-Za-z0-9+/=]` only, so it passes every layer
/// untouched.
///
/// Security: the obvious alternative — staging the script to a `.ps1` and
/// running `-File` — writes a user-writable file and then executes it with
/// elevation. A process already running as the user could swap that file
/// between the write and the elevated read and have its code run as admin
/// (a TOCTOU local privilege escalation), and it is inconsistent with the
/// macOS/Linux paths, which pass the script inline and stage nothing.
/// `-EncodedCommand` keeps the script off disk entirely.
///
/// PowerShell expects base64 of the script's UTF-16 **little-endian**
/// bytes.
pub fn windows_encoded_command(script: &str) -> String {
    use base64::Engine as _;
    let utf16le: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(utf16le)
}
/// The five files one Windows capture touches.
///
/// Grouped because they travel together and are easy to transpose when
/// passed positionally — and swapping `etl` with `pcapng` would produce a
/// capture that converts the wrong file and reports success.
#[derive(Debug, Clone, Copy)]
pub struct WindowsCapturePaths<'a> {
    /// What pktmon writes while recording.
    pub etl: &'a Path,
    /// What `etl2pcap` produces, and what Transit then indexes.
    pub pcapng: &'a Path,
    /// Deleted by Transit to request a stop, without a second UAC prompt.
    pub sentinel: &'a Path,
    /// Touched while Transit lives; going stale stops the capture.
    pub heartbeat: &'a Path,
    /// Where the elevated script records what it did.
    pub log: &'a Path,
}

/// The PowerShell supervisor that runs a `pktmon` capture.
///
/// Windows differs from the Unix path in three ways that are structural
/// rather than cosmetic (plan §3a), and this script is where all three
/// are handled:
///
/// 1. **`pktmon` is machine-global and stateful.** One capture session
///    for the whole OS, and filters that persist between invocations. The
///    script therefore refuses to start over a session it did not start,
///    rather than commandeering one — someone else's capture is not ours
///    to stop, and their filters are not ours to reset.
/// 2. **Capture is stop-then-convert.** `pktmon` writes ETL while
///    running; pcapng only exists after `etl2pcap`. The conversion is
///    part of the supervisor rather than a second elevated call, because
///    a second call means a second UAC prompt.
/// 3. **Stop must not need a prompt.** A dismissable prompt on the way
///    out leaves the machine recording. Stop is the sentinel
///    disappearing, and the stale heartbeat is the backstop for a Transit
///    that dies without one.
pub fn windows_supervisor_script(
    adapter_ifindex: &str,
    filter_args: &[String],
    start_args: &[String],
    paths: WindowsCapturePaths<'_>,
) -> String {
    let WindowsCapturePaths {
        etl,
        pcapng,
        sentinel,
        heartbeat,
        log,
    } = paths;
    let mut s = String::new();

    // EVERY step writes to a log, and that is not tidiness.
    //
    // The elevated child runs `-WindowStyle Hidden` — it has no console
    // anyone could read — and every command here used to be piped to
    // `Out-Null`. So when a capture produced nothing, no artefact existed
    // anywhere on the machine explaining why: no message, no exit code,
    // nothing. "Recording… 0 B" was the entire diagnosis available, for a
    // script running as Administrator doing six distinct things any of
    // which could fail. Transit reads this file back and surfaces it when
    // a capture writes no packets.
    s.push_str(&format!(
        "$ErrorActionPreference='Stop';\n\
         $PSNativeCommandUseErrorActionPreference = $false;\n\
         $log = {log};\n{helper}\nNote 'supervisor starting';\ntry {{\n",
        log = ps_quote(&log.to_string_lossy()),
        helper = PS_NOTE_HELPER,
    ));
    // `$PSNativeCommandUseErrorActionPreference = $false` is load-bearing.
    //
    // On PowerShell 7.4+ that preference defaults
    // to true, which makes a NATIVE command's non-zero exit throw a
    // terminating error under `$ErrorActionPreference='Stop'`. pktmon is a
    // native exe that returns non-zero for benign reasons and writes to
    // stderr routinely, so with auto-throw ON the FIRST such line aborted
    // the entire capture into the catch — the empty-pcapng symptom. Native
    // exit codes are now checked explicitly, at the two steps where they
    // actually mean failure (start, convert), rather than blanketing every
    // pktmon invocation with a hair trigger.

    // pktmon is machine-global and single-session: someone else's capture
    // is not ours to stop, and their filters are not ours to reset. The
    // status check therefore comes BEFORE we touch filter state, always.
    s.push_str(PS_REFUSE_FOREIGN_SESSION);
    // `filter remove`, NOT `filter reset` — `reset` is "Unknown command"
    // on real pktmon builds (there is no such subcommand; `reset` is a
    // TOP-LEVEL verb for counters). Clearing stale filters is best-effort
    // hygiene: a fresh machine has none, and a failure here must not abort
    // the capture, which is why native auto-throw is off above.
    s.push_str("Note 'clearing stale filters'; pktmon filter remove *>> $log;\n");

    // ONE `filter add` carrying every condition, never one per term.
    // Separate pktmon filters are OR-ed, so a term-per-filter loop widens
    // `tcp port 443 and host 10.0.0.1` into three independent matches.
    if !filter_args.is_empty() {
        let quoted: Vec<String> = filter_args.iter().map(|a| ps_quote(a)).collect();
        s.push_str(&format!(
            "Note 'adding filter'; pktmon filter add {} *>> $log;\n",
            quoted.join(" ")
        ));
    }

    // Resolve the adapter to a pktmon component id HERE, inside the one
    // elevated session: `pktmon list` needs Administrator and the
    // unprivileged enumeration that filled the dropdown could not run it.
    s.push_str(&PKTMON_RESOLVE_COMPONENT.replace("%IFINDEX%", &ps_quote(adapter_ifindex)));

    let start: Vec<String> = start_args
        .iter()
        .map(|a| {
            if a == COMP_PLACEHOLDER {
                "$comp".to_string()
            } else {
                ps_quote(a)
            }
        })
        .collect();
    s.push_str(&format!(
        "Note \"starting capture on component $comp\";\n\
         pktmon {} *>> $log;\n\
         if ($LASTEXITCODE -ne 0) {{ Note \"pktmon start failed (exit $LASTEXITCODE)\"; exit 5 }};\n\
         Note 'capture started';\n",
        start.join(" ")
    ));

    // Poll: stop when the sentinel goes, or when the heartbeat goes stale.
    s.push_str(&format!(
        "{poll}\n",
        poll = PS_STOP_POLL
            .replace("%SENTINEL%", &ps_quote(&sentinel.to_string_lossy()))
            .replace("%HEARTBEAT%", &ps_quote(&heartbeat.to_string_lossy()))
            .replace("%STALE%", &HEARTBEAT_STALE_SECS.to_string()),
    ));

    s.push_str("Note 'stopping'; pktmon stop *>> $log;\n");
    s.push_str(&format!(
        "Note 'converting to pcapng'; pktmon etl2pcap {etl} --out {out} *>> $log;\n\
         if ($LASTEXITCODE -ne 0) {{ Note \"etl2pcap failed (exit $LASTEXITCODE)\"; exit 6 }};\n\
         Note 'done';\n",
        etl = ps_quote(&etl.to_string_lossy()),
        out = ps_quote(&pcapng.to_string_lossy()),
    ));

    // A failure anywhere above lands here rather than vanishing, and the
    // machine's global filter state is put back — a failed run must not
    // leave pktmon configured as Transit set it.
    s.push_str(PS_CATCH);
    s
}

/// Appends a timestamped line to the elevated script's log.
const PS_NOTE_HELPER: &str = r#"function Note($m) { "[$(Get-Date -Format o)] $m" | Out-File -FilePath $log -Append -Encoding utf8 }"#;

/// Refuse to touch a pktmon session Transit did not start.
const PS_REFUSE_FOREIGN_SESSION: &str = concat!(
    "$st = (pktmon status 2>&1 | Out-String);\n",
    "Note \"pktmon status: $st\";\n",
    "if ($st -match 'Logging: on' -or $st -match 'is running') {\n",
    "  Note 'refusing: a capture is already running'; exit 2 };\n",
);

/// Stop when the sentinel disappears, or when Transit's heartbeat goes stale.
const PS_STOP_POLL: &str = concat!(
    "while (Test-Path %SENTINEL%) {\n",
    "  $b = (Get-Item %HEARTBEAT% -ErrorAction SilentlyContinue).LastWriteTimeUtc;\n",
    "  if (-not $b -or ((Get-Date).ToUniversalTime() - $b).TotalSeconds -gt %STALE%) {\n",
    "    Note 'heartbeat went stale; stopping'; break };\n",
    "  Start-Sleep -Seconds 1;\n",
    "};",
);

/// Record the failure and put pktmon's global state back.
const PS_CATCH: &str = concat!(
    "} catch {\n",
    "  Note \"FAILED: $($_.Exception.Message)\";\n",
    "  Note \"at: $($_.InvocationInfo.PositionMessage)\";\n",
    "  try { pktmon stop *>> $log } catch { };\n",
    "  try { pktmon filter remove *>> $log } catch { };\n",
    "  exit 9;\n",
    "}\n",
);

/// Find the file(s) `tcpdump` actually wrote for `base`.
///
/// **`-w` names the file you asked for; `-C`/`-W` do not.** With `-W`,
/// tcpdump appends a rotation number to *every* file including the first
/// — so asking for `capture.pcap` gets you `capture.pcap0`, and looking
/// for the name you passed finds nothing. (Without `-W` but with `-C`,
/// the first file keeps the plain name and later ones gain a suffix, so
/// both shapes have to be handled.)
///
/// Returns newest-first, so the caller can index the most recent segment
/// and say how many others exist. Empty means the capture wrote nothing
/// at all — which is a real outcome worth reporting as itself, not as a
/// missing file.
pub fn written_files(base: &Path) -> Vec<PathBuf> {
    let Some(dir) = base.parent() else {
        return Vec::new();
    };
    let Some(stem) = base.file_name().and_then(|s| s.to_str()) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };

    let mut found: Vec<(std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let name = name.to_str()?;
            // `capture-x.pcap` itself, or `capture-x.pcap0`, `…1`, `…07`.
            // The suffix is always digits, so this cannot pick up an
            // unrelated file that merely starts with the same text.
            if name != stem
                && !(name.starts_with(stem)
                    && name[stem.len()..].chars().all(|c| c.is_ascii_digit()))
            {
                return None;
            }
            let meta = e.metadata().ok()?;
            // A zero-length file is tcpdump having opened but not written
            // — indexing it would report an empty capture as though that
            // were the answer.
            if meta.len() == 0 {
                return None;
            }
            Some((meta.modified().ok()?, e.path()))
        })
        .collect();

    found.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified));
    found.into_iter().map(|(_, p)| p).collect()
}

/// The capture file a Windows run produced, found by its unique id-stem
/// rather than by an assumed extension.
///
/// This exists because `written_files` above is tcpdump-shaped — it looks
/// for the exact name plus rotation-number suffixes — and Windows does not
/// work that way. `etl2pcap --out capture-<stamp>-<id>.pcap` does NOT
/// necessarily produce that exact name: pktmon appends/forces a `.pcapng`,
/// so the real file is `capture-<stamp>-<id>.pcapng` (or `….pcap.pcapng`).
/// `written_files` searched for `….pcap[digits]`, matched nothing, and the
/// app reported "wrote no packets" over a capture that was sitting on disk.
/// That divergence is exactly why the CI probe (which used a `.pcapng`
/// `--out`) passed while the app (a `.pcap` `--out`) did not.
///
/// So match on the id-bearing stem and accept any extension, excluding the
/// known sidecars. The `<id>` is a UUID prefix, unique per capture, so this
/// cannot pick up a neighbour. Newest-first, non-empty only.
#[cfg(any(windows, test))]
pub fn windows_capture_outputs(base: &Path) -> Vec<PathBuf> {
    let Some(dir) = base.parent() else {
        return Vec::new();
    };
    // `capture-<stamp>-<id>` without the `.pcap` we appended — the part
    // every candidate name shares regardless of what etl2pcap did to the
    // extension.
    let Some(stem) = base.file_stem().and_then(|s| s.to_str()) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };

    // Anything that shares the capture stem but is not the capture. The
    // `.ps1` is defensive: the supervisor is delivered via `-EncodedCommand`
    // now and stages no script, but excluding it costs nothing and means a
    // stray one could never be mistaken for a capture.
    let is_sidecar = |name: &str| {
        name.ends_with(".etl")
            || name.ends_with(".running")
            || name.ends_with(".beat")
            || name.ends_with(".supervisor.log")
            || name.ends_with(".ps1")
    };

    let mut found: Vec<(std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let name = name.to_str()?;
            if !name.starts_with(stem) || is_sidecar(name) {
                return None;
            }
            let meta = e.metadata().ok()?;
            // A zero-length file is pktmon having created but not populated
            // the output — indexing it would report an empty capture as if
            // that were the answer.
            if meta.len() == 0 {
                return None;
            }
            Some((meta.modified().ok()?, e.path()))
        })
        .collect();

    found.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified));
    found.into_iter().map(|(_, p)| p).collect()
}

#[cfg(test)]
#[path = "live_tests.rs"]
mod tests;

/// `parse_net_adapters`, reachable from the Windows integration probe.
///
/// The probe lives in `tests/` so it can run the real commands, which puts
/// it outside the crate — and the point of it is to feed GENUINE
/// `Get-NetAdapter` output through the very function the app uses, rather
/// than through a copy that could drift from it.
#[cfg(windows)]
pub fn parse_net_adapters_for_test(text: &str) -> Vec<Nic> {
    parse_net_adapters(text)
}
