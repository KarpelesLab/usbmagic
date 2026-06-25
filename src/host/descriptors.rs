//! Lenient, **forensic** USB descriptor parsing and a parsed device model.
//!
//! Unlike a normal USB stack, parsing here never fails on malformed input: a
//! truncated, over-long, or out-of-order descriptor is recorded (in
//! [`UsbDeviceModel::anomalies`], or surfaced as a short/raw descriptor) rather
//! than rejected. The goal is to faithfully represent whatever a device actually
//! sent — including things a compliant device never would.
//!
//! SPDX-License-Identifier: BSD-3-Clause

use std::collections::BTreeMap;

use crate::capture::Speed;
use crate::host::{descriptor_type, DeviceDescriptor};

/// One descriptor as it appears in a descriptor blob: its declared length and
/// type plus the actual bytes captured for it (which may be shorter than
/// `length` claims, if the blob was truncated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDescriptor {
    /// `bLength` as declared in byte 0.
    pub length: u8,
    /// `bDescriptorType` (byte 1), or 0 if the descriptor was too short to have one.
    pub descriptor_type: u8,
    /// The bytes actually present for this descriptor (≤ `length`).
    pub bytes: Vec<u8>,
    /// True if fewer than `length` bytes were available (the blob was truncated here).
    pub truncated: bool,
}

/// Walk a descriptor blob into its constituent descriptors by `bLength`.
///
/// Tolerates a zero `bLength` (which would otherwise loop forever) and a final
/// descriptor that runs past the end of the buffer, marking the latter
/// `truncated`. A trailing partial descriptor (1 byte) is still reported.
pub fn walk(blob: &[u8]) -> Vec<RawDescriptor> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < blob.len() {
        let length = blob[i];
        let descriptor_type = if i + 1 < blob.len() { blob[i + 1] } else { 0 };
        // A bLength of 0 is illegal and would never advance — record one byte and
        // stop walking (the rest can't be framed).
        if length == 0 {
            out.push(RawDescriptor {
                length: 0,
                descriptor_type,
                bytes: vec![blob[i]],
                truncated: true,
            });
            break;
        }
        let end = i + length as usize;
        let (slice_end, truncated) = if end > blob.len() {
            (blob.len(), true)
        } else {
            (end, false)
        };
        out.push(RawDescriptor {
            length,
            descriptor_type,
            bytes: blob[i..slice_end].to_vec(),
            truncated,
        });
        i = end; // advance by the *declared* length even if truncated (then loop ends)
    }
    out
}

/// Parsed standard **configuration descriptor** (9 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigurationDescriptor {
    pub total_length: u16,
    pub num_interfaces: u8,
    pub configuration_value: u8,
    pub configuration_index: u8,
    pub attributes: u8,
    pub max_power: u8,
}

impl ConfigurationDescriptor {
    /// Parse the first 9 bytes; returns `None` if there aren't enough bytes.
    pub fn parse(b: &[u8]) -> Option<ConfigurationDescriptor> {
        if b.len() < 9 {
            return None;
        }
        Some(ConfigurationDescriptor {
            total_length: u16::from_le_bytes([b[2], b[3]]),
            num_interfaces: b[4],
            configuration_value: b[5],
            configuration_index: b[6],
            attributes: b[7],
            max_power: b[8],
        })
    }
}

/// Parsed standard **interface descriptor** (9 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceDescriptor {
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub num_endpoints: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub interface_index: u8,
}

impl InterfaceDescriptor {
    pub fn parse(b: &[u8]) -> Option<InterfaceDescriptor> {
        if b.len() < 9 {
            return None;
        }
        Some(InterfaceDescriptor {
            interface_number: b[2],
            alternate_setting: b[3],
            num_endpoints: b[4],
            class: b[5],
            subclass: b[6],
            protocol: b[7],
            interface_index: b[8],
        })
    }
}

/// Endpoint transfer type (`bmAttributes` bits 0–1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferType {
    Control,
    Isochronous,
    Bulk,
    Interrupt,
}

/// Parsed standard **endpoint descriptor** (7 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointDescriptor {
    pub address: u8,
    pub attributes: u8,
    pub max_packet_size: u16,
    pub interval: u8,
}

impl EndpointDescriptor {
    pub fn parse(b: &[u8]) -> Option<EndpointDescriptor> {
        if b.len() < 7 {
            return None;
        }
        Some(EndpointDescriptor {
            address: b[2],
            attributes: b[3],
            max_packet_size: u16::from_le_bytes([b[4], b[5]]),
            interval: b[6],
        })
    }

    /// Endpoint number (low 4 bits of `bEndpointAddress`).
    pub fn number(self) -> u8 {
        self.address & 0x0F
    }
    /// True if this is an IN endpoint (bit 7 of `bEndpointAddress`).
    pub fn is_in(self) -> bool {
        self.address & 0x80 != 0
    }
    /// Transfer type from `bmAttributes`.
    pub fn transfer_type(self) -> TransferType {
        match self.attributes & 0x03 {
            0 => TransferType::Control,
            1 => TransferType::Isochronous,
            2 => TransferType::Bulk,
            _ => TransferType::Interrupt,
        }
    }
}

/// A decoded USB **string descriptor**.
pub struct StringDescriptor;

impl StringDescriptor {
    /// Decode a UTF-16LE string descriptor body (bytes after the 2-byte header).
    /// Lossy: invalid surrogate pairs become U+FFFD rather than erroring.
    pub fn decode(b: &[u8]) -> String {
        if b.len() < 2 || b[1] != descriptor_type::STRING {
            return String::new();
        }
        let units: Vec<u16> = b[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    }

    /// Parse the LANGID list from string descriptor index 0.
    pub fn parse_langids(b: &[u8]) -> Vec<u16> {
        if b.len() < 2 || b[1] != descriptor_type::STRING {
            return Vec::new();
        }
        b[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect()
    }
}

/// One interface (alternate setting) with its endpoints and any class-specific
/// descriptors that followed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub descriptor: InterfaceDescriptor,
    pub endpoints: Vec<EndpointDescriptor>,
    /// Descriptors between this interface and its endpoints / the next interface
    /// that aren't standard endpoints (HID, CDC, audio, vendor, …).
    pub class_specific: Vec<RawDescriptor>,
}

/// A configuration with its interfaces (one entry per interface descriptor,
/// including alternate settings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Configuration {
    pub descriptor: ConfigurationDescriptor,
    pub interfaces: Vec<Interface>,
    /// Descriptors before the first interface (e.g. an IAD) or otherwise
    /// unattributed, kept raw.
    pub other: Vec<RawDescriptor>,
}

impl Configuration {
    /// Parse a full configuration blob (config descriptor + interfaces +
    /// endpoints + class-specific descriptors). Lenient; unknown descriptors are
    /// attached to the current interface (or `other`) as [`RawDescriptor`]s.
    pub fn parse(blob: &[u8]) -> Option<Configuration> {
        let descriptor = ConfigurationDescriptor::parse(blob)?;
        let mut interfaces: Vec<Interface> = Vec::new();
        let mut other: Vec<RawDescriptor> = Vec::new();
        for d in walk(blob).into_iter().skip(1) {
            match d.descriptor_type {
                descriptor_type::INTERFACE => {
                    if let Some(id) = InterfaceDescriptor::parse(&d.bytes) {
                        interfaces.push(Interface {
                            descriptor: id,
                            endpoints: Vec::new(),
                            class_specific: Vec::new(),
                        });
                    } else if let Some(iface) = interfaces.last_mut() {
                        iface.class_specific.push(d);
                    } else {
                        other.push(d);
                    }
                }
                descriptor_type::ENDPOINT => match (interfaces.last_mut(), EndpointDescriptor::parse(&d.bytes)) {
                    (Some(iface), Some(ep)) => iface.endpoints.push(ep),
                    (Some(iface), None) => iface.class_specific.push(d),
                    (None, _) => other.push(d),
                },
                _ => match interfaces.last_mut() {
                    Some(iface) => iface.class_specific.push(d),
                    None => other.push(d),
                },
            }
        }
        Some(Configuration {
            descriptor,
            interfaces,
            other,
        })
    }
}

/// The result of [`UsbHost::examine`](crate::host::UsbHost::examine): everything
/// learned about an attached device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbDeviceModel {
    /// Address the device is answering at.
    pub address: u8,
    /// Speed detected at reset, if known.
    pub speed: Option<Speed>,
    /// Parsed device descriptor.
    pub device_descriptor: DeviceDescriptor,
    /// Raw device descriptor bytes.
    pub raw_device_descriptor: Vec<u8>,
    /// Parsed configurations (one per `bNumConfigurations`, as far as readable).
    pub configurations: Vec<Configuration>,
    /// String descriptors read, keyed by `(index, langid)`.
    pub strings: BTreeMap<(u8, u16), String>,
    /// Non-fatal oddities seen while examining (truncated descriptors, STALLs,
    /// count mismatches, …) — the forensic record.
    pub anomalies: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> Vec<u8> {
        // Config (9) + interface 0 (9) + 2 endpoints (7 each) = 32 bytes.
        let mut b = vec![
            9, 2, 0, 0, 1, 1, 4, 0xC0, 50, // config: total_length filled below
            9, 4, 0, 0, 2, 0xFF, 0x00, 0x00, 5, // interface 0, vendor class, iface str 5
            7, 5, 0x81, 0x02, 0x40, 0x00, 0x00, // EP1 IN bulk, 64
            7, 5, 0x01, 0x02, 0x40, 0x00, 0x00, // EP1 OUT bulk, 64
        ];
        let total = b.len() as u16;
        b[2..4].copy_from_slice(&total.to_le_bytes());
        b
    }

    #[test]
    fn walk_basic_and_truncated() {
        let b = sample_config();
        let ds = walk(&b);
        assert_eq!(ds.len(), 4);
        assert_eq!(ds[0].descriptor_type, descriptor_type::CONFIGURATION);
        assert!(ds.iter().all(|d| !d.truncated));
        // Truncate mid-endpoint.
        let ds = walk(&b[..b.len() - 3]);
        assert!(ds.last().unwrap().truncated);
        // A zero bLength must not loop forever.
        assert_eq!(walk(&[0, 2, 9, 9]).len(), 1);
    }

    #[test]
    fn configuration_tree() {
        let cfg = Configuration::parse(&sample_config()).unwrap();
        assert_eq!(cfg.descriptor.num_interfaces, 1);
        assert_eq!(cfg.interfaces.len(), 1);
        let iface = &cfg.interfaces[0];
        assert_eq!(iface.descriptor.class, 0xFF);
        assert_eq!(iface.endpoints.len(), 2);
        assert_eq!(iface.endpoints[0].number(), 1);
        assert!(iface.endpoints[0].is_in());
        assert_eq!(iface.endpoints[0].transfer_type(), TransferType::Bulk);
        assert_eq!(iface.endpoints[0].max_packet_size, 64);
    }

    #[test]
    fn class_specific_preserved() {
        // Config + interface + a HID descriptor (type 0x21) + endpoint.
        let mut b = vec![
            9, 2, 0, 0, 1, 1, 4, 0x80, 50, //
            9, 4, 0, 0, 1, 3, 0, 0, 0, // HID interface
            9, 0x21, 0x11, 1, 0, 1, 0x22, 0x3F, 0, // HID descriptor (class-specific)
            7, 5, 0x81, 0x03, 0x08, 0x00, 0x0A, // EP1 IN interrupt
        ];
        let total = b.len() as u16;
        b[2..4].copy_from_slice(&total.to_le_bytes());
        let cfg = Configuration::parse(&b).unwrap();
        let iface = &cfg.interfaces[0];
        assert_eq!(iface.class_specific.len(), 1);
        assert_eq!(iface.class_specific[0].descriptor_type, 0x21);
        assert_eq!(iface.endpoints.len(), 1);
        assert_eq!(iface.endpoints[0].transfer_type(), TransferType::Interrupt);
    }

    #[test]
    fn string_decode_and_langids() {
        // "Hi" as a string descriptor: len, type, 'H',0, 'i',0.
        let s = [6, descriptor_type::STRING, b'H', 0, b'i', 0];
        assert_eq!(StringDescriptor::decode(&s), "Hi");
        // LANGID list with 0x0409 (en-US).
        let l = [4, descriptor_type::STRING, 0x09, 0x04];
        assert_eq!(StringDescriptor::parse_langids(&l), vec![0x0409]);
        // Not a string descriptor → empty.
        assert_eq!(StringDescriptor::decode(&[2, 1]), "");
    }
}
