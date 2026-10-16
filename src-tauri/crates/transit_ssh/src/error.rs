use std::path::{Path, PathBuf};

use thiserror::Error;

/// Classified errors the connection / session layer can surface.
/// The variants are designed to be stringified into actionable
/// messages by the UI — pick a variant for each failure shape the
/// user can reasonably do something about.
#[derive(Error, Debug)]
pub enum SshError {
    /// The server's host key fingerprint does not match what we
    /// previously recorded. Surfaced when the user DECLINES the
    /// changed-key warning dialog — or when the dialog could not be
    /// shown (connect cancelled mid-prompt, confirm channel gone).
    /// Replacing the pin happens only through that dialog's explicit
    /// verify-and-replace flow, never automatically, and persists
    /// only after auth also succeeds — defense against
    /// social-engineering "just trust it" pressure on a
    /// possibly-compromised network path (threat model T11).
    /// `device_id` leads the message on purpose: since v6.5.7 pins are
    /// scoped per device, and two devices legitimately sharing an address
    /// is the common case this scoping exists for — "the key for
    /// 192.168.1.1 changed" would not say WHICH device is affected.
    #[error(
        "host key for device '{device_id}' ({host}:{port}) changed since last \
         connect — expected {expected}, got {got}. If the change is legitimate \
         (device re-imaged or re-keyed), reconnect and approve the \
         replacement in the warning dialog. Pins are stored in {known_hosts}."
    )]
    HostKeyMismatch {
        device_id: String,
        host: String,
        port: u16,
        expected: String,
        got: String,
        /// `Box<Path>` rather than `PathBuf`: this path is stored and
        /// displayed, never mutated, and the eight bytes it saves keep
        /// `SshError` under clippy's `result_large_err` threshold now that
        /// the host-key variants also carry a device id.
        known_hosts: Box<Path>,
    },

    /// First-connect dialog: user clicked Cancel.
    #[error("user declined to trust the host key for device '{device_id}' ({host}:{port})")]
    HostKeyRejected {
        device_id: String,
        host: String,
        port: u16,
    },

    /// Authentication failed (bad password, key not authorized, etc.).
    #[error("authentication failed for user '{user}': {detail}")]
    AuthFailed { user: String, detail: String },

    /// The server advertised no `server-sig-algs` (RFC 8308) and rejected
    /// the RSA key signed with the modern `rsa-sha2-512`, while still
    /// offering public-key auth — the signature it will accept is almost
    /// certainly the legacy SHA-1 `ssh-rsa`. This is the user-auth analogue
    /// of [`Self::CipherUnsupported`]: the connect flow routes it to the
    /// SAME per-device weak-crypto opt-in (retry with `allow_weak_crypto`,
    /// which signs `ssh-rsa`), never a silent downgrade (T20).
    ///
    /// It arises specifically on gear with a MODERN key exchange (so the
    /// KEX-triggered opt-in never fires) that nonetheless only accepts the
    /// SHA-1 user-key signature — e.g. default-config IOS-XE 17.x
    /// (field report, 2026-09-03; reproduced against a lab C9300-class
    /// device at 192.0.2.56). KEX strength and user-auth signature
    /// capability are independent, which is why this needs its own trigger.
    #[error(
        "device {host}:{port} requires the legacy SHA-1 ssh-rsa key signature \
         for user '{user}' (it advertised no rsa-sha2 support)"
    )]
    WeakSignatureRequired {
        user: String,
        host: String,
        port: u16,
    },

    /// Server only offered ciphers / KEX / MACs outside our strict
    /// allowlist.
    ///
    /// `kind` is the russh negotiation slot that didn't converge
    /// (`Kex`, `Cipher`, `Mac`, `Key`); `offered` is the server's
    /// advertised list for that slot, captured verbatim from
    /// `russh::Error::NoCommonAlgo.theirs`. The UI uses both to
    /// render the [`WeakCryptoConfirmDialog`] — if the user opts
    /// in, the connection is retried with [`legacy_client_config`].
    ///
    /// `detail` is kept for backward compatibility with non-dialog
    /// log paths and CLI error rendering; it duplicates the
    /// structured fields formatted as a single string.
    ///
    /// [`WeakCryptoConfirmDialog`]: ../../../../../../src/components/dialogs/WeakCryptoConfirmDialog.tsx
    /// [`legacy_client_config`]: crate::ciphers::legacy_client_config
    #[error(
        "server at {host}:{port} only offered weak crypto: {detail}. \
         Transit requires modern SSH ciphers; opt in via the warning \
         dialog (this device only), upgrade firmware, or use a jumphost."
    )]
    CipherUnsupported {
        host: String,
        port: u16,
        kind: String,
        offered: Vec<String>,
        detail: String,
    },

    /// The SSH handshake was interrupted before algorithm negotiation
    /// produced a structured result — the server dropped the
    /// connection or sent an unexpected packet during key exchange, so
    /// russh surfaced `KexInit` / `Disconnect` rather than a
    /// `NoCommonAlgo`. This is the shape legacy gear takes when it
    /// can't agree on Transit's algorithms and closes the connection
    /// instead of advertising its (weak) list: Cisco small-business
    /// switches (SG300/SG500) surface it as `KexInit`, FS.com switches
    /// as `Disconnect`. It is NOT always pre-KEXINIT: a GEX-only
    /// server that can't satisfy the client's group-size request
    /// disconnects mid-key-exchange and lands here too (v2.3.3).
    ///
    /// Because it happens strictly pre-auth (russh's `connect_stream`
    /// returns before authentication), the connect flow treats it as a
    /// weak-crypto *candidate* and offers the same per-device opt-in as
    /// [`Self::CipherUnsupported`] — never an auto-downgrade. The
    /// variant is deliberately distinct from `CipherUnsupported`: there
    /// is no negotiated `kind`/`offered` list to show (the server never
    /// sent one), and the cause is ambiguous (it can also be an ACL
    /// drop or a TCP reset), so the legacy retry re-attempts and, if it
    /// also fails, surfaces the real error rather than masking it.
    /// `detail` is the underlying russh reason — enriched with the
    /// server's own `SSH_MSG_DISCONNECT` text when it sent one
    /// (`ConnectHandler::disconnected`).
    ///
    /// Display-text note: this message only ever reaches the user
    /// AFTER the legacy retry also failed (or on a connect where the
    /// device's remembered `allow_weak_crypto` was already in force) —
    /// the strict-path occurrence is consumed by the weak-crypto
    /// dialog, and a decline surfaces its own error. So the guidance
    /// speaks to the post-opt-in reality instead of telling the user
    /// to opt into what they already allowed (the pre-v2.3.3 wording).
    #[error(
        "ssh handshake with {host}:{port} was interrupted before algorithm \
         negotiation completed ({detail}) — the device would not complete the \
         handshake even with Transit's legacy algorithms allowed. It may \
         require algorithms Transit does not support, or a firewall/ACL may \
         be dropping the connection. Check the device's SSH settings and \
         firmware."
    )]
    HandshakeInterrupted {
        host: String,
        port: u16,
        detail: String,
    },

    /// The device sent an SSH handshake packet Transit could not parse
    /// because a protocol field carried bytes that are not valid
    /// ASCII/UTF-8. russh surfaces this as `Error::SshEncoding`
    /// (`ssh_encoding::Error::CharacterEncoding`) — most commonly a
    /// `SSH_MSG_KEXINIT` algorithm name-list, which RFC 4253 requires to
    /// be US-ASCII; russh decodes each name-list as a strict UTF-8
    /// `String` (`negotiation::read_kex` → `NameList::decode`), so one
    /// stray non-ASCII byte aborts the whole handshake before algorithm
    /// selection.
    ///
    /// This is a firmware-level defect in the device's SSH server, not
    /// a client configuration or a weak-crypto case (it happens before
    /// any algorithm is negotiated, so the legacy opt-in cannot help).
    /// Observed on an FS S5500-48T8SP on one specific firmware build
    /// while sibling units on other builds connect cleanly — 2026-07-05.
    /// The guidance is a firmware update; there is no in-app remedy
    /// because the malformed bytes arrive before Transit can act.
    #[error(
        "the device at {host}:{port} sent an SSH handshake Transit could not \
         parse — a protocol field contained characters that are not valid \
         ASCII/UTF-8, which the SSH standard does not permit. This is a \
         firmware-level defect in the device's SSH server; updating the \
         device firmware typically resolves it."
    )]
    HandshakeEncoding { host: String, port: u16 },

    /// Underlying network error (DNS, TCP, TLS, etc.).
    #[error("network error connecting to {host}:{port}: {source}")]
    Network {
        host: String,
        port: u16,
        #[source]
        source: std::io::Error,
    },

    /// Connection / handshake / auth didn't complete in time.
    #[error("timeout connecting to {host}:{port}")]
    Timeout { host: String, port: u16 },

    /// Reading, parsing, or writing the `known_hosts.toml` store
    /// failed. The detail field is pre-classified (`parse`, `write`,
    /// `io`) plus the underlying error message, so the UI can
    /// surface a useful banner.
    #[error("known_hosts I/O at {path}: {detail}")]
    KnownHostsIo { path: PathBuf, detail: String },

    /// `HostKeyStore::insert` was called for a DEVICE that already has a
    /// pin. The connection flow should always call `lookup` first; this
    /// variant exists to catch a buggy caller before it silently
    /// overwrites a TOFU pin.
    ///
    /// Note the conflict is on the device, not the address — two devices
    /// sharing `host:port` is expected and must not error.
    #[error("known_hosts already contains a pin for device '{device_id}' ({host}:{port})")]
    KnownHostsConflict {
        device_id: String,
        host: String,
        port: u16,
    },

    /// A named SSH **subsystem** could not be started on a session
    /// channel — the v5.0.0 Files pane's `sftp` request
    /// ([`crate::Connection::open_subsystem_stream`]).
    ///
    /// This is its own variant because the remedy is device-side
    /// configuration, not anything Transit can retry: the SSH login
    /// itself succeeded (host key trusted, credentials accepted) and
    /// only the subsystem is missing. Newer Junos ships with the SFTP
    /// server off, which is by far the most common cause on lab gear,
    /// so the message names the exact knob.
    ///
    /// `detail` carries the underlying reason (an explicit
    /// `SSH_MSG_CHANNEL_FAILURE`, a channel-open error, or "the device
    /// never replied") so a log line can distinguish them.
    #[error(
        "the SSH server at {host}:{port} would not start the '{name}' subsystem \
         ({detail}) — file transfer needs an SFTP server enabled on the device. \
         On Junos: `set system services ssh sftp-server`; on Linux/BSD check \
         sshd_config's `Subsystem sftp` line."
    )]
    SubsystemUnavailable {
        host: String,
        port: u16,
        name: String,
        detail: String,
    },

    /// The jump host refused (or failed) to open the `direct-tcpip`
    /// tunnel toward the target (v6.5.0, T52) — its own variant for
    /// the same reason as [`SshError::SubsystemUnavailable`]: the jump
    /// LOGIN succeeded, and the remedy is jump-side configuration or
    /// jump-side reachability, not anything Transit can retry. Both
    /// ends are named so a chain failure is attributable at a glance;
    /// `detail` carries the SSH channel-open failure reason (an
    /// `administratively prohibited` here is `AllowTcpForwarding no`
    /// on the jump's sshd) or the transport-level cause.
    #[error(
        "jump host {jump_host}:{jump_port} would not open a tunnel to \
         {target_host}:{target_port} ({detail}) — check the jump's sshd \
         allows TCP forwarding (`AllowTcpForwarding yes`) and that the \
         target is reachable FROM the jump host."
    )]
    JumpTunnelRefused {
        jump_host: String,
        jump_port: u16,
        target_host: String,
        target_port: u16,
        detail: String,
    },

    /// Generic wrapper for russh-side errors that don't fit a more
    /// specific classification. Keep these rare — every new failure
    /// shape that's user-actionable should get a dedicated variant.
    #[error("ssh error: {detail}")]
    Other { detail: String },
}
