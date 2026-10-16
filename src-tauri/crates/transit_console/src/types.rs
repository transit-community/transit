//! Wire types for the console-cable transport.
//!
//! These mirror — by intent, not by re-export — the configuration
//! enums from `serialport`. Wrapping them lets us:
//!
//! 1. Keep a stable public surface even if we swap serialport for a
//!    different backend (POSIX `termios` direct, IOKit's serial APIs,
//!    Windows `OVERLAPPED` I/O) in a later phase.
//! 2. Add `serde::{Serialize, Deserialize}` so they can cross the
//!    Tauri IPC boundary without an adapter layer.
//! 3. Pick sensible defaults (8-N-1, no flow control) that match
//!    every network device's factory console.

use serde::{Deserialize, Serialize};

use transit_core::inventory::Vendor;

/// Default baud for network-device consoles. 9600 8-N-1 is what every
/// Cisco / Juniper / Arista box ships with from the factory.
pub const DEFAULT_BAUD: u32 = 9600;

/// Number of data bits per byte. 8 is universal on modern gear;
/// 7 still exists on some serial printers but no network device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataBits {
    Five,
    Six,
    Seven,
    #[default]
    Eight,
}

impl From<DataBits> for tokio_serial::DataBits {
    fn from(value: DataBits) -> Self {
        match value {
            DataBits::Five => tokio_serial::DataBits::Five,
            DataBits::Six => tokio_serial::DataBits::Six,
            DataBits::Seven => tokio_serial::DataBits::Seven,
            DataBits::Eight => tokio_serial::DataBits::Eight,
        }
    }
}

/// Parity bit configuration. Network consoles default to `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Parity {
    #[default]
    None,
    Odd,
    Even,
}

impl From<Parity> for tokio_serial::Parity {
    fn from(value: Parity) -> Self {
        match value {
            Parity::None => tokio_serial::Parity::None,
            Parity::Odd => tokio_serial::Parity::Odd,
            Parity::Even => tokio_serial::Parity::Even,
        }
    }
}

/// Number of stop bits. 1 is universal on network gear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StopBits {
    #[default]
    One,
    Two,
}

impl From<StopBits> for tokio_serial::StopBits {
    fn from(value: StopBits) -> Self {
        match value {
            StopBits::One => tokio_serial::StopBits::One,
            StopBits::Two => tokio_serial::StopBits::Two,
        }
    }
}

/// Flow-control discipline. `None` is the network-console default —
/// hardware flow control (RTS/CTS) needs all 9 pins of the DB-9 wired,
/// which the typical RJ-45-to-DB-9 console adapter doesn't carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowControl {
    #[default]
    None,
    Software,
    Hardware,
}

impl From<FlowControl> for tokio_serial::FlowControl {
    fn from(value: FlowControl) -> Self {
        match value {
            FlowControl::None => tokio_serial::FlowControl::None,
            FlowControl::Software => tokio_serial::FlowControl::Software,
            FlowControl::Hardware => tokio_serial::FlowControl::Hardware,
        }
    }
}

/// Parameters for opening a console-cable session.
///
/// `port_path` is the OS-specific device path:
/// - macOS: `/dev/cu.usbserial-XXXXXXXX` (NEVER `/dev/tty.*` — that
///   variant blocks on carrier-detect until DCD asserts).
/// - Linux: `/dev/ttyUSB0` (FTDI) or `/dev/ttyACM0` (CDC-ACM).
/// - Windows: `COM3`, `COM4`, etc.
///
/// `vendor` is required at connect time — see plan §"Locked
/// decisions" #8. Console cables only meaningfully terminate at
/// network gear whose CLI we know.
///
/// `Deserialize` only — this is IPC input from the frontend. The
/// in-production `Vendor` enum (`transit_core::inventory`) is
/// deliberately `Deserialize`-only outside `#[cfg(test)]` builds,
/// so a `Serialize` derive here would force a downstream change
/// to that contract.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ConnectParams {
    pub port_path: String,
    pub baud: u32,
    #[serde(default)]
    pub data_bits: DataBits,
    #[serde(default)]
    pub parity: Parity,
    #[serde(default)]
    pub stop_bits: StopBits,
    #[serde(default)]
    pub flow_control: FlowControl,
    pub vendor: Vendor,
}

impl ConnectParams {
    /// Convenience: 9600 8-N-1, no flow control. Matches every
    /// network-device factory console — the Configure-Console
    /// dialog's defaults reduce to this struct.
    pub fn defaults_for(port_path: impl Into<String>, vendor: Vendor) -> Self {
        Self {
            port_path: port_path.into(),
            baud: DEFAULT_BAUD,
            data_bits: DataBits::Eight,
            parity: Parity::None,
            stop_bits: StopBits::One,
            flow_control: FlowControl::None,
            vendor,
        }
    }
}

/// Subset of `serialport::UsbPortInfo` exposed to callers. We keep
/// only the fields the sidebar actually displays, plus the USB serial
/// number (which is the stable per-cable identifier — what we'll use
/// when remembering per-cable preferences in a future phase).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UsbPortDetails {
    pub vid: u16,
    pub pid: u16,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    /// USB iSerial descriptor. Stable across replug for FTDI and CP21x
    /// chips programmed with a unique serial at the factory.
    pub serial_number: Option<String>,
}

/// Enumerated entry from `list_available_ports` — also the payload of
/// hot-plug events in C17.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerialPortInfo {
    /// OS path: `/dev/cu.usbserial-A99BCXAG`, `COM3`, etc.
    pub port_path: String,
    /// `Some(details)` when the OS classified it as USB-CDC or
    /// USB-FTDI; `None` for built-in / unknown classifications
    /// (Bluetooth modems, PCI cards, etc., which we surface anyway
    /// but with no USB metadata).
    pub usb: Option<UsbPortDetails>,
}

impl SerialPortInfo {
    /// Sidebar label heuristic. Uses the manufacturer/product fields
    /// when present (`FTDI FT232R USB UART`), otherwise the bare
    /// path. The USB serial number is appended in parens when known
    /// so multiple identical cables are still distinguishable.
    pub fn sidebar_label(&self) -> String {
        if let Some(usb) = &self.usb {
            let chip = match (usb.manufacturer.as_deref(), usb.product.as_deref()) {
                (Some(m), Some(p)) => format!("{m} {p}"),
                (None, Some(p)) => p.to_string(),
                (Some(m), None) => m.to_string(),
                (None, None) => "USB serial".to_string(),
            };
            match &usb.serial_number {
                Some(sn) if !sn.is_empty() => format!("{chip} ({sn})"),
                _ => chip,
            }
        } else {
            self.port_path.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_factory_console() {
        let p = ConnectParams::defaults_for("/dev/cu.usbserial-A99BCXAG", Vendor::Junos);
        assert_eq!(p.baud, 9600);
        assert_eq!(p.data_bits, DataBits::Eight);
        assert_eq!(p.parity, Parity::None);
        assert_eq!(p.stop_bits, StopBits::One);
        assert_eq!(p.flow_control, FlowControl::None);
    }

    #[test]
    fn sidebar_label_uses_manufacturer_and_product() {
        let info = SerialPortInfo {
            port_path: "/dev/cu.usbserial-A99BCXAG".into(),
            usb: Some(UsbPortDetails {
                vid: 0x0403,
                pid: 0x6001,
                manufacturer: Some("FTDI".into()),
                product: Some("FT232R USB UART".into()),
                serial_number: Some("A99BCXAG".into()),
            }),
        };
        assert_eq!(info.sidebar_label(), "FTDI FT232R USB UART (A99BCXAG)");
    }

    #[test]
    fn sidebar_label_handles_missing_usb_metadata() {
        let info = SerialPortInfo {
            port_path: "/dev/cu.Bluetooth-Incoming-Port".into(),
            usb: None,
        };
        assert_eq!(info.sidebar_label(), "/dev/cu.Bluetooth-Incoming-Port");
    }

    #[test]
    fn sidebar_label_omits_empty_serial_number() {
        // Some FTDI chips have a serial of empty string after a bad
        // EEPROM write — fall back to the manufacturer/product label
        // alone rather than rendering `FTDI FT232R ()`.
        let info = SerialPortInfo {
            port_path: "/dev/cu.usbserial".into(),
            usb: Some(UsbPortDetails {
                vid: 0x0403,
                pid: 0x6001,
                manufacturer: Some("FTDI".into()),
                product: Some("FT232R USB UART".into()),
                serial_number: Some(String::new()),
            }),
        };
        assert_eq!(info.sidebar_label(), "FTDI FT232R USB UART");
    }

    #[test]
    fn config_enums_map_to_tokio_serial() {
        // Spot-check that the From impls don't crash and cover all
        // variants — the actual byte semantics are tokio-serial's job.
        let _: tokio_serial::DataBits = DataBits::Eight.into();
        let _: tokio_serial::Parity = Parity::None.into();
        let _: tokio_serial::StopBits = StopBits::One.into();
        let _: tokio_serial::FlowControl = FlowControl::None.into();
    }

    #[test]
    fn connect_params_deserializes_from_frontend_shape() {
        // Mirrors the JSON the Tauri command will receive from the
        // ConsoleConnectDialog. `#[serde(default)]` on the optional
        // fields means the dialog can omit the Advanced section
        // entirely.
        let json = r#"{
            "port_path": "/dev/cu.usbserial-A99BCXAG",
            "baud": 9600,
            "vendor": "junos"
        }"#;
        let p: ConnectParams = serde_json::from_str(json).expect("deserialize");
        assert_eq!(p.port_path, "/dev/cu.usbserial-A99BCXAG");
        assert_eq!(p.data_bits, DataBits::Eight);
        assert_eq!(p.parity, Parity::None);
    }
}
