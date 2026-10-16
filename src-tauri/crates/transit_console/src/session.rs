//! [`Session`] — live serial-console connection.
//!
//! Mirrors `transit_ssh::Session`'s actor pattern so the Tauri side
//! can treat both transports uniformly. The reader task pushes
//! bytes into a shared [`ScrollbackRing`] and a `broadcast` channel;
//! the writer task pulls FIFO from an `mpsc`. The split-ownership
//! model means keystrokes can never race with anything else for
//! access to the port handle.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, watch, Notify};
use tokio_serial::{SerialPort, SerialPortBuilderExt, SerialPortType, SerialStream};
use tracing::{debug, error, info, warn};
use transit_core::inventory::Vendor;
use transit_core::scrollback::ScrollbackRing;
use transit_core::session::TerminalSession;

use crate::error::ConsoleError;
use crate::types::{ConnectParams, SerialPortInfo, UsbPortDetails};

/// Broadcast channel size. Holds bursts of unprocessed bytes for the
/// slowest live subscriber. Identical sizing to the SSH crate.
pub const OUTPUT_CHANNEL_SIZE: usize = 256;

/// Keystroke channel size. Generous so a long paste never blocks.
/// Identical to `transit_ssh::session::INPUT_CHANNEL_SIZE`.
pub const INPUT_CHANNEL_SIZE: usize = 256;

/// Reader buffer size. 4 KiB matches typical USB-to-serial bulk
/// endpoints (FTDI ships 64-byte packets up to 4 KiB latency-tuned
/// buffers; CP210x similar). Larger than 4 KiB doesn't help — the
/// kernel still hands us short reads.
const READ_BUF_SIZE: usize = 4096;

/// Per-session metadata. Cheap to clone — strings are short and
/// `OffsetDateTime` is `Copy`.
#[derive(Debug, Clone)]
pub struct SessionMeta {
    pub port_path: String,
    pub baud: u32,
    /// Vendor declared at connect time. Drives `transit_app`'s
    /// `propose_command` adjudication against `transit_policy`,
    /// identical to the SSH path. This crate stores it but never
    /// reads it.
    pub vendor: Vendor,
    pub opened_at: time::OffsetDateTime,
}

/// Live serial-console session. Drop or [`close`] to tear down the
/// port handle and kill the background tasks.
///
/// [`close`]: Session::close
pub struct Session {
    /// 32K lines / 4 MiB rolling buffer. Read by the frontend on tab
    /// attach and by the agent's `read_scrollback` tool.
    pub scrollback: Arc<ScrollbackRing>,
    /// Internal command channel. Wrapped in `Option` so
    /// [`Session::close`] can `take()` it and drop the sender
    /// (forcing the writer's `recv` to return None) without
    /// conflicting with the `Drop` impl.
    cmd_tx: Option<mpsc::Sender<SessionCmd>>,
    /// Output broadcast. Use [`Self::subscribe`] for a receiver.
    output_tx: broadcast::Sender<Bytes>,
    /// Fires when the reader task exits — i.e., the cable was
    /// unplugged, the OS yanked the device node, or read failed.
    /// Kept for the `TerminalSession::ended_notify` surface; new
    /// consumers should prefer [`Self::closed_rx`] — `Notify` is
    /// edge-triggered, so a notification fired before (or between)
    /// `notified()` registrations is lost forever.
    ended: Arc<Notify>,
    /// Level-triggered twin of `ended`: flips to `true` when the
    /// reader task exits and STAYS true, so a subscriber that checks
    /// late (e.g. the IPC output bridge task scheduled after the
    /// cable already vanished) still observes the close. Receivers
    /// also observe sender-drop (reader task aborted) as a close.
    closed_rx: watch::Receiver<bool>,
    meta: SessionMeta,
    reader_handle: Option<tokio::task::JoinHandle<()>>,
    writer_handle: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Debug)]
enum SessionCmd {
    Data(Bytes),
    /// Assert a serial BREAK, then release — interrupt a boot sequence or
    /// reach ROMMON on the attached device.
    Break,
    Close,
}

impl Session {
    /// Open `params.port_path` and spawn reader + writer tasks.
    /// Returns once the port is configured; data starts flowing
    /// immediately (the device will typically emit a `login:` prompt
    /// or fragmentary banner depending on its state).
    pub fn open(params: ConnectParams) -> Result<Self, ConsoleError> {
        let stream = build_stream(&params)?;
        info!(
            port = %params.port_path,
            baud = params.baud,
            vendor = params.vendor.as_str(),
            "console session opened"
        );

        // Clone a blocking handle to the same port for BREAK signaling
        // BEFORE the split (the async read/write halves don't expose the
        // SerialPort control ioctls). Best-effort: if the OS refuses the
        // clone, BREAK is simply unavailable for this session.
        let break_port = stream.try_clone().ok();
        let (read_half, write_half) = tokio::io::split(stream);

        let scrollback = Arc::new(ScrollbackRing::new());
        let (output_tx, _) = broadcast::channel(OUTPUT_CHANNEL_SIZE);
        let (cmd_tx, cmd_rx) = mpsc::channel(INPUT_CHANNEL_SIZE);
        let ended = Arc::new(Notify::new());
        let (closed_tx, closed_rx) = watch::channel(false);

        let reader_handle = tokio::spawn(reader_loop(
            read_half,
            Arc::clone(&scrollback),
            output_tx.clone(),
            Arc::clone(&ended),
            closed_tx,
            params.port_path.clone(),
        ));

        let writer_handle = tokio::spawn(writer_loop(
            write_half,
            break_port,
            cmd_rx,
            params.port_path.clone(),
        ));

        let meta = SessionMeta {
            port_path: params.port_path,
            baud: params.baud,
            vendor: params.vendor,
            opened_at: time::OffsetDateTime::now_utc(),
        };

        Ok(Self {
            scrollback,
            cmd_tx: Some(cmd_tx),
            output_tx,
            ended,
            closed_rx,
            meta,
            reader_handle: Some(reader_handle),
            writer_handle: Some(writer_handle),
        })
    }

    pub fn meta(&self) -> &SessionMeta {
        &self.meta
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Bytes> {
        self.output_tx.subscribe()
    }

    /// Edge-triggered "session ended" signal, kept for the
    /// `TerminalSession` trait surface. Prefer [`Self::closed_rx`].
    pub fn ended_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.ended)
    }

    /// Level-triggered "session ended" signal: reads `true` once the
    /// reader task has exited, no matter when the caller looks.
    /// `changed().await` wakes on the flip; a receiver error (sender
    /// dropped — reader task aborted) also means the session is
    /// gone. Consumed by `transit_app::ssh::spawn_output_bridge`.
    pub fn closed_rx(&self) -> watch::Receiver<bool> {
        self.closed_rx.clone()
    }

    /// Send keystrokes / paste bytes to the device.
    pub async fn send_input(&self, bytes: Bytes) -> Result<(), ConsoleError> {
        let tx = self.cmd_tx.as_ref().ok_or(ConsoleError::SessionClosed)?;
        tx.send(SessionCmd::Data(bytes))
            .await
            .map_err(|_| ConsoleError::SessionClosed)
    }

    /// Assert a serial BREAK on the line (interrupt a boot sequence /
    /// reach ROMMON), then release. The writer task performs the
    /// set-break → hold → clear-break sequence.
    pub async fn send_break(&self) -> Result<(), ConsoleError> {
        let tx = self.cmd_tx.as_ref().ok_or(ConsoleError::SessionClosed)?;
        tx.send(SessionCmd::Break)
            .await
            .map_err(|_| ConsoleError::SessionClosed)
    }

    /// Graceful close. The writer task drains in FIFO order, then
    /// exits; the reader task is aborted (its blocking read on the
    /// port has no other way to wake).
    ///
    /// Bounded: a wedged writer (full cmd channel, port that never
    /// completes a write) must not turn close into a hang. `try_send`
    /// skips the Close marker if the channel is full — dropping the
    /// sender ends the writer's `recv` loop anyway — and the join is
    /// capped at 2s before the task is aborted (a dropped
    /// `JoinHandle` would merely detach the task, leaking it).
    pub async fn close(mut self) -> Result<(), ConsoleError> {
        if let Some(tx) = self.cmd_tx.take() {
            let _ = tx.try_send(SessionCmd::Close);
            drop(tx);
        }
        if let Some(mut h) = self.writer_handle.take() {
            if tokio::time::timeout(Duration::from_secs(2), &mut h)
                .await
                .is_err()
            {
                warn!("console close: writer task did not drain within 2s; aborting");
                h.abort();
            }
        }
        if let Some(h) = self.reader_handle.take() {
            h.abort();
        }
        Ok(())
    }
}

#[async_trait]
impl TerminalSession for Session {
    fn subscribe(&self) -> broadcast::Receiver<Bytes> {
        self.output_tx.subscribe()
    }

    async fn send_input(&self, bytes: Bytes) -> Result<(), String> {
        Session::send_input(self, bytes)
            .await
            .map_err(|e| e.to_string())
    }

    fn ended_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.ended)
    }

    fn scrollback(&self) -> Arc<ScrollbackRing> {
        Arc::clone(&self.scrollback)
    }

    fn vendor(&self) -> Vendor {
        self.meta.vendor.clone()
    }

    fn opened_at(&self) -> time::OffsetDateTime {
        self.meta.opened_at
    }

    fn transport_label(&self) -> &'static str {
        "console"
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Belt-and-braces: even if the user mem::drops without
        // calling close(), abort the tasks so they don't outlive the
        // (now-dropped) port handle.
        if let Some(h) = self.reader_handle.take() {
            h.abort();
        }
        if let Some(h) = self.writer_handle.take() {
            h.abort();
        }
    }
}

// ---------------------------------------------------------------------
// Port enumeration
// ---------------------------------------------------------------------

/// One-shot snapshot of currently-attached **USB-to-serial cables**.
/// The hot-plug watcher (C17) uses this for its initial `current()`
/// view and for the Win/Linux fallback that emits no events.
///
/// Two filters are applied:
///
/// 1. **USB-only.** The OS enumerates plenty of non-cable serial
///    devices — built-in modems, Bluetooth-Incoming-Port on macOS,
///    `/dev/ttyS*` (legacy RS-232 ports) on Linux. Only ports the OS
///    classifies as USB are surfaced to the user.
/// 2. **macOS cu./tty. dedup.** Each physical port on macOS appears
///    twice: as `/dev/cu.foo` (call-out, non-blocking) and
///    `/dev/tty.foo` (the legacy DCD-blocking variant). Always
///    prefer `cu.*`; the `tty.*` sibling is the wrong device to
///    open for an interactive console (it would hang the open
///    until carrier-detect asserts, which a network device's
///    console port never does).
///
/// Errors from `tokio_serial::available_ports` are mapped to an empty
/// `Vec` — a watcher that returns "no cables" is correct behavior on
/// a host that hasn't granted serial-device access yet, and the user
/// will see the empty sidebar section rather than a startup crash.
pub fn list_available_ports() -> Vec<SerialPortInfo> {
    let raw = match tokio_serial::available_ports() {
        Ok(ports) => ports,
        Err(e) => {
            warn!(
                ?e,
                "tokio_serial::available_ports failed; returning empty list"
            );
            return Vec::new();
        }
    };

    let mapped: Vec<SerialPortInfo> = raw.into_iter().map(serialize_port_info).collect();
    filter_cables(mapped)
}

/// Apply the USB-only + macOS dedup filters. Split out from
/// [`list_available_ports`] so it's unit-testable against synthetic
/// inputs without an actual OS call.
fn filter_cables(ports: Vec<SerialPortInfo>) -> Vec<SerialPortInfo> {
    // Pass 1: drop non-USB entries.
    let usb_only: Vec<SerialPortInfo> = ports.into_iter().filter(|p| p.usb.is_some()).collect();

    // Pass 2: macOS dedup — for each `/dev/tty.NAME`, drop it if
    // `/dev/cu.NAME` is also present.
    let cu_paths: std::collections::HashSet<String> = usb_only
        .iter()
        .filter_map(|p| p.port_path.strip_prefix("/dev/cu."))
        .map(|s| s.to_string())
        .collect();

    usb_only
        .into_iter()
        .filter(|p| {
            if let Some(tty_suffix) = p.port_path.strip_prefix("/dev/tty.") {
                !cu_paths.contains(tty_suffix)
            } else {
                true
            }
        })
        .collect()
}

fn serialize_port_info(info: tokio_serial::SerialPortInfo) -> SerialPortInfo {
    let usb = match info.port_type {
        SerialPortType::UsbPort(u) => Some(UsbPortDetails {
            vid: u.vid,
            pid: u.pid,
            manufacturer: u.manufacturer,
            product: u.product,
            serial_number: u.serial_number,
        }),
        // PCI / Bluetooth / Unknown — no USB metadata.
        _ => None,
    };
    SerialPortInfo {
        port_path: info.port_name,
        usb,
    }
}

// ---------------------------------------------------------------------
// Stream construction
// ---------------------------------------------------------------------

fn build_stream(params: &ConnectParams) -> Result<SerialStream, ConsoleError> {
    let builder = tokio_serial::new(&params.port_path, params.baud)
        .data_bits(params.data_bits.into())
        .parity(params.parity.into())
        .stop_bits(params.stop_bits.into())
        .flow_control(params.flow_control.into())
        // Read timeout is irrelevant for tokio-serial's async mode —
        // reads are driven by the OS readiness signal — but the
        // builder requires it. Set to a token value.
        .timeout(Duration::from_millis(10));

    builder.open_native_async().map_err(|e| {
        // tokio-serial classifies "no such file" + "permission
        // denied" + "device busy" as `Io` variants of its `Error`.
        // We map "device busy" to InvalidConfig since the user
        // recovery is different (another app holds the port — kill
        // that app or pick a different cable), and everything else
        // to OpenFailed.
        let detail = e.to_string();
        if detail.contains("Device or resource busy") || detail.contains("Access is denied") {
            ConsoleError::InvalidConfig {
                path: params.port_path.clone(),
                detail,
            }
        } else {
            ConsoleError::OpenFailed {
                path: params.port_path.clone(),
                detail,
            }
        }
    })
}

// ---------------------------------------------------------------------
// Background tasks
// ---------------------------------------------------------------------

async fn reader_loop(
    mut read_half: tokio::io::ReadHalf<SerialStream>,
    scrollback: Arc<ScrollbackRing>,
    output_tx: broadcast::Sender<Bytes>,
    ended: Arc<Notify>,
    closed_tx: watch::Sender<bool>,
    port_path: String,
) {
    let mut buf = vec![0u8; READ_BUF_SIZE];
    loop {
        match read_half.read(&mut buf).await {
            Ok(0) => {
                debug!(port = %port_path, "console reader: EOF");
                break;
            }
            Ok(n) => {
                let chunk = Bytes::copy_from_slice(&buf[..n]);
                scrollback.push(&chunk);
                // `send` errors only when there are zero subscribers,
                // which is fine — the bytes still made it into
                // scrollback. Frontend (re)subscribes get the full
                // history via the snapshot path.
                let _ = output_tx.send(chunk);
            }
            Err(e) => {
                // USB unplug surfaces as a read error here (ENXIO /
                // EIO depending on platform). Treat any read error
                // as session-ended — the user sees "ended" on the
                // tab and can review scrollback before closing.
                warn!(port = %port_path, ?e, "console reader: read failed");
                break;
            }
        }
    }
    // Level-triggered flip first (a bridge that checks late still
    // sees `true`); the Notify stays for `TerminalSession`.
    closed_tx.send_replace(true);
    ended.notify_waiters();
}

async fn writer_loop(
    mut write_half: tokio::io::WriteHalf<SerialStream>,
    mut break_port: Option<Box<dyn SerialPort>>,
    mut cmd_rx: mpsc::Receiver<SessionCmd>,
    port_path: String,
) {
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            SessionCmd::Data(bytes) => {
                if let Err(e) = write_half.write_all(&bytes).await {
                    error!(port = %port_path, ?e, "console writer: write failed");
                    break;
                }
                if let Err(e) = write_half.flush().await {
                    error!(port = %port_path, ?e, "console writer: flush failed");
                    break;
                }
            }
            SessionCmd::Break => match break_port.as_mut() {
                Some(port) => {
                    // Hold BREAK ~300ms (enough to interrupt a boot / reach
                    // ROMMON), then release. Other writes wait for the
                    // duration — a break is a deliberate interrupt.
                    if let Err(e) = port.set_break() {
                        error!(port = %port_path, ?e, "console break: set_break failed");
                    } else {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        if let Err(e) = port.clear_break() {
                            error!(port = %port_path, ?e, "console break: clear_break failed");
                        }
                    }
                }
                None => warn!(port = %port_path, "console break requested but no break handle"),
            },
            SessionCmd::Close => {
                let _ = write_half.shutdown().await;
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Round-trip-via-pty test is deferred to C24 (socat-backed CI
    // harness). A naive `tokio_serial::SerialStream::pair()` test
    // hangs on macOS because the pty slave end won't deliver bytes
    // to the master without specific termios setup, which we don't
    // want to bake into a unit test. C24 wires real socat-spawned
    // virtual ports and exercises the full reader/writer pipeline.

    #[test]
    fn serialize_port_info_maps_usb_metadata() {
        let info = tokio_serial::SerialPortInfo {
            port_name: "/dev/cu.usbserial-A99BCXAG".into(),
            port_type: SerialPortType::UsbPort(tokio_serial::UsbPortInfo {
                vid: 0x0403,
                pid: 0x6001,
                manufacturer: Some("FTDI".into()),
                product: Some("FT232R USB UART".into()),
                serial_number: Some("A99BCXAG".into()),
            }),
        };
        let out = serialize_port_info(info);
        assert_eq!(out.port_path, "/dev/cu.usbserial-A99BCXAG");
        let usb = out.usb.expect("usb metadata present");
        assert_eq!(usb.vid, 0x0403);
        assert_eq!(usb.serial_number.as_deref(), Some("A99BCXAG"));
    }

    #[test]
    fn serialize_port_info_drops_non_usb_classification() {
        let info = tokio_serial::SerialPortInfo {
            port_name: "/dev/cu.Bluetooth-Incoming-Port".into(),
            port_type: SerialPortType::BluetoothPort,
        };
        let out = serialize_port_info(info);
        assert!(out.usb.is_none());
    }

    #[test]
    fn build_stream_rejects_nonexistent_path() {
        let params = ConnectParams::defaults_for("/nope/no/such/device", Vendor::Junos);
        match build_stream(&params) {
            Err(ConsoleError::OpenFailed { path, .. }) => {
                assert_eq!(path, "/nope/no/such/device");
            }
            other => panic!("expected OpenFailed, got {other:?}"),
        }
    }

    fn usb_port(path: &str) -> SerialPortInfo {
        SerialPortInfo {
            port_path: path.into(),
            usb: Some(UsbPortDetails {
                vid: 0x0403,
                pid: 0x6001,
                ..Default::default()
            }),
        }
    }

    fn non_usb_port(path: &str) -> SerialPortInfo {
        SerialPortInfo {
            port_path: path.into(),
            usb: None,
        }
    }

    #[test]
    fn filter_drops_non_usb_ports() {
        // macOS exposes built-in Bluetooth-Incoming-Port and
        // debug-console as serial devices. They aren't USB cables
        // and shouldn't appear in the sidebar.
        let input = vec![
            non_usb_port("/dev/cu.Bluetooth-Incoming-Port"),
            non_usb_port("/dev/cu.debug-console"),
            usb_port("/dev/cu.usbserial-A99BCXAG"),
        ];
        let out = filter_cables(input);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].port_path, "/dev/cu.usbserial-A99BCXAG");
    }

    #[test]
    fn filter_drops_tty_sibling_of_cu_port() {
        // macOS exposes every serial port twice: /dev/cu.NAME and
        // /dev/tty.NAME. Only cu.* is the right device for an
        // interactive console — tty.* blocks the open call on DCD.
        let input = vec![
            usb_port("/dev/cu.usbserial-A99BCXAG"),
            usb_port("/dev/tty.usbserial-A99BCXAG"),
        ];
        let out = filter_cables(input);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].port_path, "/dev/cu.usbserial-A99BCXAG");
    }

    #[test]
    fn filter_keeps_orphan_tty_port() {
        // A /dev/tty.NAME with no /dev/cu.NAME sibling is unusual
        // but not impossible. Pass it through rather than swallow
        // a port the user might actually want to use.
        let input = vec![usb_port("/dev/tty.lonely-port")];
        let out = filter_cables(input);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn filter_keeps_linux_and_windows_paths_untouched() {
        // Neither platform exposes the cu./tty. duplication. Both
        // names must pass through unchanged.
        let input = vec![
            usb_port("/dev/ttyUSB0"),
            usb_port("/dev/ttyACM0"),
            usb_port("COM3"),
        ];
        let out = filter_cables(input);
        assert_eq!(out.len(), 3);
    }
}
