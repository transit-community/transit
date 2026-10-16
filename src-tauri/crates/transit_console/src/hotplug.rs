//! Hot-plug discovery for USB-to-serial cables.
//!
//! v1 implementation: polls `tokio_serial::available_ports()` once a
//! second on a dedicated OS thread, diffs against the previous
//! snapshot, and broadcasts [`HotplugEvent::Added`] /
//! [`HotplugEvent::Removed`] events to subscribers.
//!
//! # Why polling and not IOKit / udev / WMI
//!
//! Real OS notification APIs deliver events with ~10 ms latency
//! versus polling's 1 s worst-case. For Transit's UX — a human
//! plugging a cable in and looking at the sidebar — the difference
//! is imperceptible: by the time the eye saccades from the USB
//! port to the screen, 1 s has elapsed. The polling path works on
//! all three platforms with a single code path; we trade a small
//! latency cost for shipping the feature one or two days faster.
//!
//! IOKit (macOS via `IOServiceAddMatchingNotification` on
//! `IOSerialBSDClient` matches), udev (Linux via libudev's monitor
//! socket), and WMI (Windows via `Win32_PnPEntity`) are all
//! tracked as Phase 7b follow-ups. They produce the same
//! `HotplugEvent` shape so swapping them in is a self-contained
//! change.
//!
//! # Lifecycle
//!
//! [`start`] returns a [`HotplugWatcher`] holding a `broadcast::Sender`
//! and a shared snapshot. The watcher's `current()` is synchronous —
//! the Tauri side calls it from the IPC handler that seeds the
//! sidebar query. `subscribe()` hands out fresh `Receiver`s that pick
//! up events emitted after subscription.
//!
//! The poller thread runs for the process lifetime. There's no
//! `stop()`; the OS reaps it on app exit.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::broadcast;
use tracing::debug;

use crate::session::list_available_ports;
use crate::types::SerialPortInfo;

/// Poll interval. 1 s is the trade-off — fast enough that a human
/// plugging a cable in doesn't notice the latency, slow enough that
/// the ioreg / sysfs / WMI walk doesn't cost CPU.
const POLL_INTERVAL: Duration = Duration::from_millis(1_000);

/// Event channel capacity. 64 is generous — events fire at most once
/// per second per cable change, so the only way to overflow is if a
/// subscriber stalls for over a minute. In that case `Lagged` is the
/// right signal; resubscribing reads `current()` for the truth.
const EVENT_CHANNEL_SIZE: usize = 64;

/// One change in the set of attached cables.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", content = "port", rename_all = "lowercase")]
pub enum HotplugEvent {
    /// Cable appeared at this path. The full [`SerialPortInfo`] is
    /// included so subscribers don't need to round-trip another
    /// `current()` call to render the sidebar row.
    Added(SerialPortInfo),
    /// Cable disappeared. The full info from the prior snapshot is
    /// included so the UI can identify and remove the matching row
    /// without re-querying.
    Removed(SerialPortInfo),
}

/// Read-only handle to the hot-plug watcher.
#[derive(Clone)]
pub struct HotplugWatcher {
    tx: broadcast::Sender<HotplugEvent>,
    /// Latest snapshot, refreshed on every poll tick. Read by
    /// [`Self::current`].
    snapshot: Arc<Mutex<Vec<SerialPortInfo>>>,
}

impl HotplugWatcher {
    /// Current set of attached cables. Synchronous — reads the
    /// cached snapshot, no I/O.
    pub fn current(&self) -> Vec<SerialPortInfo> {
        self.snapshot
            .lock()
            .expect("hotplug snapshot mutex poisoned")
            .clone()
    }

    /// Subscribe to add/remove events. Each subscriber gets events
    /// emitted after the subscription was created; history is in
    /// [`Self::current`].
    pub fn subscribe(&self) -> broadcast::Receiver<HotplugEvent> {
        self.tx.subscribe()
    }
}

/// Start the watcher. Spawns a dedicated OS thread that seeds the
/// snapshot, then polls every [`POLL_INTERVAL`] and broadcasts diffs.
///
/// `start()` itself does no I/O: it's called on the Tauri setup path
/// (main thread), and `tokio_serial::available_ports()` walks
/// ioreg / sysfs / the registry — hundreds of ms on a busy USB bus.
/// The seed runs as the poller thread's first act instead, so
/// `current()` may return an empty list for the first few hundred
/// milliseconds after startup; the UI's cable query lands well after
/// that (webview load), and every later poll tick converges anyway.
pub fn start() -> HotplugWatcher {
    let (tx, _rx0) = broadcast::channel(EVENT_CHANNEL_SIZE);
    let snapshot = Arc::new(Mutex::new(Vec::new()));

    let tx_for_thread = tx.clone();
    let snapshot_for_thread = Arc::clone(&snapshot);

    thread::Builder::new()
        .name("transit-console-hotplug".into())
        .spawn(move || run_poller(tx_for_thread, snapshot_for_thread))
        .expect("spawn hotplug poller thread");

    HotplugWatcher { tx, snapshot }
}

fn run_poller(tx: broadcast::Sender<HotplugEvent>, snapshot: Arc<Mutex<Vec<SerialPortInfo>>>) {
    // Seed pass — store without emitting events (the baseline, same
    // semantics the old synchronous seed had; subscribers learn the
    // initial set from `current()`, not from Added events).
    let initial = list_available_ports();
    *snapshot.lock().expect("hotplug snapshot mutex poisoned") = initial;

    loop {
        thread::sleep(POLL_INTERVAL);

        let now = list_available_ports();
        let prev = {
            let g = snapshot.lock().expect("hotplug snapshot mutex poisoned");
            g.clone()
        };

        let events = diff_ports(&prev, &now);
        if events.is_empty() {
            continue;
        }

        for ev in &events {
            debug!(?ev, "hotplug");
            // `send` returns Err if there are zero subscribers — not
            // an error condition, just means no one cares yet.
            let _ = tx.send(ev.clone());
        }

        *snapshot.lock().expect("hotplug snapshot mutex poisoned") = now;
    }
}

/// Compute Add/Remove events between two snapshots. Order is
/// deterministic — `Removed` events first (so the UI clears stale
/// rows before adding new ones, avoiding a momentary duplicate when
/// a cable is replugged in the same poll window).
fn diff_ports(prev: &[SerialPortInfo], now: &[SerialPortInfo]) -> Vec<HotplugEvent> {
    let mut events = Vec::new();
    for p in prev {
        if !now.iter().any(|q| q.port_path == p.port_path) {
            events.push(HotplugEvent::Removed(p.clone()));
        }
    }
    for q in now {
        if !prev.iter().any(|p| p.port_path == q.port_path) {
            events.push(HotplugEvent::Added(q.clone()));
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::UsbPortDetails;

    fn port(path: &str) -> SerialPortInfo {
        SerialPortInfo {
            port_path: path.into(),
            usb: Some(UsbPortDetails {
                vid: 0x0403,
                pid: 0x6001,
                ..Default::default()
            }),
        }
    }

    #[test]
    fn empty_to_empty_is_quiet() {
        assert!(diff_ports(&[], &[]).is_empty());
    }

    #[test]
    fn add_event_when_port_appears() {
        let events = diff_ports(&[], &[port("/dev/cu.A")]);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], HotplugEvent::Added(_)));
    }

    #[test]
    fn remove_event_when_port_disappears() {
        let events = diff_ports(&[port("/dev/cu.A")], &[]);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], HotplugEvent::Removed(_)));
    }

    #[test]
    fn no_event_when_set_unchanged() {
        let same = vec![port("/dev/cu.A"), port("/dev/cu.B")];
        assert!(diff_ports(&same, &same).is_empty());
    }

    #[test]
    fn removed_emits_before_added_within_one_tick() {
        // A path swap within one poll window: the UI clears the old
        // row before adding the new one so a momentary duplicate
        // can't appear.
        let prev = vec![port("/dev/cu.OLD")];
        let now = vec![port("/dev/cu.NEW")];
        let events = diff_ports(&prev, &now);
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], HotplugEvent::Removed(_)));
        assert!(matches!(events[1], HotplugEvent::Added(_)));
    }

    #[tokio::test]
    async fn start_seeds_snapshot_from_poller_thread() {
        // The seed now runs as the poller thread's first act (so
        // `start()` does no I/O on the Tauri setup path). Confirm
        // current() converges to list_available_ports() within a
        // generous bound — the seed needs no poll tick, just the
        // thread's first enumeration pass.
        let watcher = start();
        let direct = list_available_ports();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let cur = watcher.current();
            // Compare by length as a sanity check (a real hotplug
            // mid-test is vanishingly unlikely).
            if cur.len() == direct.len() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "hotplug seed did not converge within 5s: \
                 current()={} ports, direct={} ports",
                cur.len(),
                direct.len()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[test]
    fn hotplug_event_serializes_with_kind_discriminator() {
        // The frontend expects `{ kind: "added", port: {...} }` so
        // the Tauri event handler can switch on `.kind`.
        let ev = HotplugEvent::Added(port("/dev/cu.A"));
        let json = serde_json::to_value(&ev).expect("serialize");
        assert_eq!(json["kind"], "added");
        assert!(json.get("port").is_some());
    }
}
