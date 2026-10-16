//! Detect USB-to-serial chips present on the bus but missing their
//! VCP (Virtual COM Port) driver.
//!
//! Some macOS users plug in an FTDI / SiLabs / Prolific cable and see
//! nothing in the sidebar because the vendor's VCP driver isn't
//! loaded. The kernel sees the chip on the USB bus, but no
//! `/dev/cu.usbserial-*` node appears. Without a banner explaining
//! the situation, the user assumes the cable is broken.
//!
//! This module enumerates USB devices via `system_profiler` (macOS
//! built-in, no FFI), matches against a known-chip vendor/product
//! table, and reports any chips not represented in the current
//! `list_available_ports()` snapshot.
//!
//! Linux / Windows fall back to empty: the equivalent stories there
//! are dialout-group membership (Linux) and built-in WinUSB
//! detection (Windows), tracked as separate follow-ups (C23 +
//! future Windows checkpoint).

use serde::Serialize;

/// A known USB-to-serial chip the OS sees on the bus but has no
/// matching `/dev/cu.*` port node for. The frontend renders one
/// banner per chip family — typically zero or one entries.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MissingDriver {
    /// Human-readable chip family ("FTDI FT232", "SiLabs CP210x", …).
    pub chip: String,
    /// USB vendor id, hex string like "0x0403".
    pub vid: String,
    /// USB product id, hex string like "0x6001".
    pub pid: String,
    /// User-facing instruction. Includes a link the user can follow
    /// to install the driver, and a mention of System Settings →
    /// Privacy & Security for the DriverKit approval flow.
    pub instruction: String,
}

/// Overall status returned to the frontend.
#[derive(Debug, Clone, Serialize, Default)]
pub struct DriverStatus {
    pub missing_drivers: Vec<MissingDriver>,
}

/// Public entry point: scan and report missing drivers.
pub fn status() -> DriverStatus {
    #[cfg(target_os = "macos")]
    {
        macos::status_impl()
    }
    #[cfg(not(target_os = "macos"))]
    {
        DriverStatus::default()
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::process::Command;

    use crate::session::list_available_ports;

    /// Known chip families. Vendor id + an instruction stem; the
    /// product-id check is a presence test (any device with the matching
    /// vendor counts — vendor-specific product variations are accounted
    /// for by the chip-family label).
    struct KnownChip {
        vendor_id: u16,
        chip: &'static str,
        instruction: &'static str,
    }

    const KNOWN_CHIPS: &[KnownChip] = &[
        KnownChip {
            vendor_id: 0x0403,
            chip: "FTDI",
            instruction:
                "Install the FTDI VCP driver from https://ftdichip.com/drivers/vcp-drivers/, \
                 then approve it in System Settings → Privacy & Security.",
        },
        KnownChip {
            vendor_id: 0x10C4,
            chip: "SiLabs CP210x",
            instruction: "Install the SiLabs CP210x VCP driver from \
                 https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers, \
                 then approve it in System Settings → Privacy & Security.",
        },
        KnownChip {
            vendor_id: 0x067B,
            chip: "Prolific PL2303",
            instruction: "Install the Prolific PL2303 VCP driver from the vendor's site, \
                 then approve it in System Settings → Privacy & Security.",
        },
        KnownChip {
            vendor_id: 0x1A86,
            chip: "WCH CH340/CH341",
            instruction: "Install the WCH CH340 VCP driver from \
                 https://www.wch.cn/downloads/CH341SER_MAC_ZIP.html, \
                 then approve it in System Settings → Privacy & Security.",
        },
    ];

    pub(super) fn status_impl() -> DriverStatus {
        // Already-attached cables with their VIDs — used to filter
        // out chips whose driver IS working (port present means
        // driver loaded).
        let live_vids: std::collections::HashSet<u16> = list_available_ports()
            .into_iter()
            .filter_map(|p| p.usb.map(|u| u.vid))
            .collect();

        let usb_devices = match enumerate_usb_macos() {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(?e, "driver_status: USB enumeration failed");
                return DriverStatus::default();
            }
        };

        let mut missing: Vec<MissingDriver> = Vec::new();
        for dev in usb_devices {
            let Some(chip) = KNOWN_CHIPS.iter().find(|c| c.vendor_id == dev.vendor_id) else {
                continue;
            };
            // Driver IS working — already-attached cable list has
            // a port from this vendor.
            if live_vids.contains(&dev.vendor_id) {
                continue;
            }
            // Avoid duplicate banners when multiple chips of the
            // same family are present.
            if missing.iter().any(|m| m.chip == chip.chip) {
                continue;
            }
            missing.push(MissingDriver {
                chip: chip.chip.into(),
                vid: format!("0x{:04X}", dev.vendor_id),
                pid: format!("0x{:04X}", dev.product_id),
                instruction: chip.instruction.into(),
            });
        }

        DriverStatus {
            missing_drivers: missing,
        }
    }

    #[derive(Debug)]
    struct UsbDevice {
        vendor_id: u16,
        product_id: u16,
    }

    /// Enumerate USB devices via `system_profiler SPUSBDataType -json`.
    /// Apple's `system_profiler` is preinstalled on every macOS; no
    /// FFI or extra deps required.
    fn enumerate_usb_macos() -> Result<Vec<UsbDevice>, String> {
        let output = Command::new("system_profiler")
            .args(["-json", "SPUSBDataType"])
            .output()
            .map_err(|e| format!("system_profiler spawn: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "system_profiler exited {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)
            .map_err(|e| format!("system_profiler JSON parse: {e}"))?;
        let mut out = Vec::new();
        if let Some(roots) = value.get("SPUSBDataType").and_then(|v| v.as_array()) {
            for root in roots {
                collect_usb_devices(root, &mut out);
            }
        }
        Ok(out)
    }

    /// system_profiler's USB tree is nested ("_items" arrays inside
    /// each hub/device). Walk it recursively.
    fn collect_usb_devices(node: &serde_json::Value, out: &mut Vec<UsbDevice>) {
        if let (Some(vid_str), Some(pid_str)) = (
            node.get("vendor_id").and_then(|v| v.as_str()),
            node.get("product_id").and_then(|v| v.as_str()),
        ) {
            // system_profiler reports vid/pid as strings like
            // "0x0403  (Future Technology Devices...)". Parse the
            // hex prefix only.
            if let (Some(vid), Some(pid)) = (parse_hex_prefix(vid_str), parse_hex_prefix(pid_str)) {
                out.push(UsbDevice {
                    vendor_id: vid,
                    product_id: pid,
                });
            }
        }
        if let Some(items) = node.get("_items").and_then(|v| v.as_array()) {
            for child in items {
                collect_usb_devices(child, out);
            }
        }
    }

    fn parse_hex_prefix(s: &str) -> Option<u16> {
        let trimmed = s.trim_start_matches("0x");
        let hex_end = trimmed
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(trimmed.len());
        u16::from_str_radix(&trimmed[..hex_end], 16).ok()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_hex_prefix_strips_trailing_label() {
            assert_eq!(parse_hex_prefix("0x0403"), Some(0x0403));
            assert_eq!(
                parse_hex_prefix("0x0403  (Future Technology Devices...)"),
                Some(0x0403)
            );
            assert_eq!(parse_hex_prefix("0xabcd"), Some(0xabcd));
        }

        #[test]
        fn parse_hex_prefix_rejects_garbage() {
            assert_eq!(parse_hex_prefix("garbage"), None);
            assert_eq!(parse_hex_prefix(""), None);
        }

        #[test]
        fn collect_usb_devices_walks_nested_tree() {
            // Synthetic snippet mirroring system_profiler's shape.
            let json: serde_json::Value = serde_json::from_str(
                r#"{
                    "_items": [
                        { "vendor_id": "0x0403", "product_id": "0x6001" },
                        {
                            "_items": [
                                { "vendor_id": "0x10c4", "product_id": "0xea60  (some label)" }
                            ]
                        }
                    ]
                }"#,
            )
            .unwrap();
            let mut out = Vec::new();
            collect_usb_devices(&json, &mut out);
            assert_eq!(out.len(), 2);
            assert_eq!(out[0].vendor_id, 0x0403);
            assert_eq!(out[1].vendor_id, 0x10c4);
            assert_eq!(out[1].product_id, 0xea60);
        }
    }
}
