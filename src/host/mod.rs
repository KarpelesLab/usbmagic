//! USB **host** capability: driving a device under test (DUT) directly, the way
//! the Cynthion will once host gateware exists.
//!
//! This module is deliberately **forensics-first**: alongside the convenient
//! high-level operations ([`UsbHost::control_transfer`], [`UsbHost::enumerate`])
//! it exposes a low-level [`UsbHost::raw_transaction`] that can emit deliberately
//! non-compliant traffic (bad/absent CRC, forced data toggle, no retry) and a
//! [`WireEvent`] stream that records exactly what happened on the bus — including
//! errors a compliant host would hide.
//!
//! The types here are transport-agnostic. A concrete implementation talks to the
//! gateware over the CONTROL port (see `docs/PROTOCOL.md`); [`crate::mock`]
//! provides a software implementation for development and tests. See
//! `docs/FORENSICS.md` for the full "normally not allowed" matrix.
//!
//! ```
//! use usbmagic::{UsbHost, UsbForensics, host::descriptor_type};
//! use usbmagic::mock::MockHost;
//!
//! let mut host = MockHost::new();
//! host.set_vbus(true)?;
//! let dev = host.enumerate()?;
//!
//! // Analyze: full descriptor/interface/string model.
//! let model = host.examine(dev.address)?;
//! assert_eq!(model.device_descriptor.vendor_id, 0x1209);
//! assert_eq!(model.configurations[0].interfaces[0].endpoints.len(), 2);
//!
//! // Misbehave: ask for far more than the descriptor holds, see the short packet.
//! let r = host.get_descriptor_oversized(dev.address, descriptor_type::DEVICE, 0, 4096)?;
//! assert!(r.errors.iter().any(|e| matches!(e, usbmagic::BusError::ShortPacket)));
//! # Ok::<(), usbmagic::Error>(())
//! ```

use crate::capture::Speed;
use crate::error::{Error, Result};

pub mod descriptors;
pub mod forensics;

pub use descriptors::{
    Configuration, ConfigurationDescriptor, EndpointDescriptor, Interface, InterfaceDescriptor,
    RawDescriptor, StringDescriptor, TransferType, UsbDeviceModel,
};
pub use forensics::UsbForensics;

/// USB packet identifier (the 4-bit PID value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pid {
    // Token
    Out,
    In,
    Sof,
    Setup,
    // Data
    Data0,
    Data1,
    Data2,
    MData,
    // Handshake
    Ack,
    Nak,
    Stall,
    Nyet,
    // Special
    Pre, // also ERR (same value)
    Split,
    Ping,
    Reserved,
}

impl Pid {
    /// The 4-bit PID value as it appears in the low nibble on the wire.
    pub fn value(self) -> u8 {
        match self {
            Pid::Out => 0x1,
            Pid::In => 0x9,
            Pid::Sof => 0x5,
            Pid::Setup => 0xD,
            Pid::Data0 => 0x3,
            Pid::Data1 => 0xB,
            Pid::Data2 => 0x7,
            Pid::MData => 0xF,
            Pid::Ack => 0x2,
            Pid::Nak => 0xA,
            Pid::Stall => 0xE,
            Pid::Nyet => 0x6,
            Pid::Pre => 0xC,
            Pid::Split => 0x8,
            Pid::Ping => 0x4,
            Pid::Reserved => 0x0,
        }
    }

    /// Decode a 4-bit PID value (low nibble).
    pub fn from_value(v: u8) -> Pid {
        match v & 0x0F {
            0x1 => Pid::Out,
            0x9 => Pid::In,
            0x5 => Pid::Sof,
            0xD => Pid::Setup,
            0x3 => Pid::Data0,
            0xB => Pid::Data1,
            0x7 => Pid::Data2,
            0xF => Pid::MData,
            0x2 => Pid::Ack,
            0xA => Pid::Nak,
            0xE => Pid::Stall,
            0x6 => Pid::Nyet,
            0xC => Pid::Pre,
            0x8 => Pid::Split,
            0x4 => Pid::Ping,
            _ => Pid::Reserved,
        }
    }

    /// The full PID byte on the wire: low nibble = PID, high nibble = its complement.
    pub fn wire_byte(self) -> u8 {
        let p = self.value();
        p | ((!p & 0x0F) << 4)
    }
}

/// Transfer direction relative to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Device-to-host.
    In,
    /// Host-to-device.
    Out,
}

/// A USB control SETUP packet (the 8 bytes of `bmRequestType…wLength`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setup {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

impl Setup {
    /// Serialize to the 8 on-the-wire bytes (little-endian fields).
    pub fn to_bytes(self) -> [u8; 8] {
        let [vl, vh] = self.value.to_le_bytes();
        let [il, ih] = self.index.to_le_bytes();
        let [ll, lh] = self.length.to_le_bytes();
        [self.request_type, self.request, vl, vh, il, ih, ll, lh]
    }

    /// True if the data stage flows device-to-host (bit 7 of `bmRequestType`).
    pub fn is_in(self) -> bool {
        self.request_type & 0x80 != 0
    }
}

/// Handshake observed (or, for IN transfers, sent) at the end of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handshake {
    Ack,
    Nak,
    Stall,
    Nyet,
    /// No handshake (e.g. isochronous, or a timeout).
    None,
}

/// A bus-level anomaly observed during a transaction or on the wire.
///
/// A forensics host records these rather than silently retrying or hiding them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusError {
    /// No response within the bus turnaround timeout.
    Timeout,
    /// Token CRC5 mismatch.
    Crc5,
    /// Data CRC16 mismatch.
    Crc16,
    /// Bit-stuffing violation.
    BitStuff,
    /// Packet longer than the endpoint's maximum (babble).
    Babble,
    /// PID check nibble did not match its complement.
    PidCheck,
    /// A PID other than the protocol allowed at this point.
    UnexpectedPid(u8),
    /// Fewer bytes than expected.
    ShortPacket,
    /// Receive FIFO overran (the known HS bulk hazard).
    Overflow,
    /// Anything else, described.
    Other(String),
}

/// Forensic controls for a single [`RawTransaction`].
///
/// Defaults are all "behave compliantly".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TxFlags {
    /// Do not retry on NAK/timeout — report exactly what happened, once.
    pub no_retry: bool,
    /// Append a deliberately corrupted CRC.
    pub corrupt_crc: bool,
    /// Send no CRC at all (raw bytes only).
    pub no_crc: bool,
    /// Force the data toggle: `Some(false)` = DATA0, `Some(true)` = DATA1.
    /// `None` uses the tracked per-endpoint toggle.
    pub force_toggle: Option<bool>,
    /// The handshake the caller expects (recorded/asserted); `None` accepts any.
    pub expect: Option<Handshake>,
    /// Corrupt the PID's check nibble (the high-nibble complement) — an illegal
    /// packet a compliant host would never send.
    pub bad_pid_check: bool,
    /// Send a deliberately wrong token CRC5.
    pub crc5_error: bool,
    /// Send this exact data PID (DATA0/DATA1/DATA2/MDATA) regardless of the
    /// tracked toggle — to provoke or study toggle handling.
    pub force_data_pid: Option<Pid>,
    /// Append this many extra junk bytes past the declared length (babble).
    pub extra_bytes: usize,
    /// Cut the data packet short (drop its trailing byte) — a short/runt packet.
    pub truncate: bool,
}

/// Stage-level forensic controls for a [`control transfer`](UsbHost::control_raw),
/// independent of the SETUP bytes themselves. Defaults are all compliant.
///
/// The SETUP packet (8 bytes) is passed separately and may itself be arbitrary
/// (illegal `bmRequestType`, mismatched `wLength`, reserved requests…); these
/// options control how the *stages* are driven around it.
#[derive(Debug, Clone, Default)]
pub struct ControlForensics {
    /// Drive the data stage for exactly this many bytes instead of the SETUP's
    /// `wLength` — to under/over-run on purpose (e.g. `wLength`=64 but read 0).
    pub data_len_override: Option<usize>,
    /// Skip the status stage entirely (a transfer with no handshake close).
    pub skip_status: bool,
    /// Drive the status stage in the wrong direction (IN where OUT is required,
    /// or vice-versa).
    pub status_wrong_dir: bool,
    /// Per-transaction wire violations applied to the data stage.
    pub flags: TxFlags,
}

/// A single low-level USB transaction (token + optional data + handshake).
///
/// This is the forensic primitive: full control over address/endpoint/PID/data
/// and the ability to violate the spec via [`TxFlags`].
#[derive(Debug, Clone)]
pub struct RawTransaction {
    /// Token PID (`Setup`/`In`/`Out`/`Ping`/`Sof`).
    pub pid: Pid,
    /// Device address (0–127).
    pub address: u8,
    /// Endpoint number (0–15).
    pub endpoint: u8,
    /// Payload for OUT/SETUP tokens (ignored for IN).
    pub data: Vec<u8>,
    /// Forensic flags.
    pub flags: TxFlags,
}

/// Outcome of a [`RawTransaction`] or bulk/interrupt transfer.
#[derive(Debug, Clone)]
pub struct TransactionResult {
    /// Handshake received (OUT/SETUP) or sent (IN).
    pub handshake: Handshake,
    /// Payload received (IN); empty otherwise.
    pub data: Vec<u8>,
    /// Capture timestamp (ns) when the transaction started.
    pub start_ns: u64,
    /// Wall duration of the transaction (ns).
    pub duration_ns: u64,
    /// Any anomalies observed.
    pub errors: Vec<BusError>,
}

/// Outcome of a complete control transfer (setup + data + status stages).
#[derive(Debug, Clone)]
pub struct ControlResult {
    /// IN data returned by the device (empty for OUT transfers).
    pub data: Vec<u8>,
    /// The device STALLed the request.
    pub stalled: bool,
    /// Anomalies observed across the stages.
    pub errors: Vec<BusError>,
    /// Total duration (ns).
    pub duration_ns: u64,
}

/// State of the target port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortStatus {
    /// A device is attached (line state / pull-up detected).
    pub connected: bool,
    /// Detected speed, if known.
    pub speed: Option<Speed>,
    /// Measured VBUS (mV), if available.
    pub vbus_mv: Option<u32>,
    /// A bus reset is currently being driven.
    pub reset_in_progress: bool,
}

/// One entry in the host's timestamped wire log.
#[derive(Debug, Clone)]
pub struct WireEvent {
    /// Capture timestamp in nanoseconds (same 60 MHz timebase as capture).
    pub timestamp_ns: u64,
    pub kind: WireEventKind,
}

/// Kind of a [`WireEvent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireEventKind {
    /// A packet seen on the bus (raw bytes include the PID byte).
    Packet { pid: Pid, data: Vec<u8> },
    /// A handshake packet.
    Handshake(Handshake),
    /// Start-of-frame with its frame number.
    Sof(u16),
    /// Host drove a bus reset.
    BusReset,
    /// Device connected (with detected speed if known).
    Connect(Option<Speed>),
    /// Device disconnected.
    Disconnect,
    /// A bus anomaly.
    Error(BusError),
    Suspend,
    Resume,
}

// --- Standard USB request / descriptor constants used by enumerate() ---

/// `bRequest` values for standard requests.
pub mod request {
    pub const GET_STATUS: u8 = 0;
    pub const CLEAR_FEATURE: u8 = 1;
    pub const SET_FEATURE: u8 = 3;
    pub const SET_ADDRESS: u8 = 5;
    pub const GET_DESCRIPTOR: u8 = 6;
    pub const SET_DESCRIPTOR: u8 = 7;
    pub const GET_CONFIGURATION: u8 = 8;
    pub const SET_CONFIGURATION: u8 = 9;
}

/// `bDescriptorType` values.
pub mod descriptor_type {
    pub const DEVICE: u8 = 1;
    pub const CONFIGURATION: u8 = 2;
    pub const STRING: u8 = 3;
    pub const INTERFACE: u8 = 4;
    pub const ENDPOINT: u8 = 5;
}

/// Parsed standard USB **device descriptor** (18 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceDescriptor {
    pub usb_version: u16,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub max_packet_size0: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_version: u16,
    pub manufacturer_index: u8,
    pub product_index: u8,
    pub serial_index: u8,
    pub num_configurations: u8,
}

impl DeviceDescriptor {
    /// Parse the 18-byte device descriptor.
    pub fn parse(b: &[u8]) -> Result<DeviceDescriptor> {
        if b.len() < 18 {
            return Err(Error::Protocol(format!(
                "device descriptor too short: {} bytes",
                b.len()
            )));
        }
        if b[1] != descriptor_type::DEVICE {
            return Err(Error::Protocol(format!(
                "not a device descriptor (bDescriptorType = {:#04x})",
                b[1]
            )));
        }
        Ok(DeviceDescriptor {
            usb_version: u16::from_le_bytes([b[2], b[3]]),
            class: b[4],
            subclass: b[5],
            protocol: b[6],
            max_packet_size0: b[7],
            vendor_id: u16::from_le_bytes([b[8], b[9]]),
            product_id: u16::from_le_bytes([b[10], b[11]]),
            device_version: u16::from_le_bytes([b[12], b[13]]),
            manufacturer_index: b[14],
            product_index: b[15],
            serial_index: b[16],
            num_configurations: b[17],
        })
    }
}

/// Result of a successful enumeration.
#[derive(Debug, Clone)]
pub struct EnumeratedDevice {
    /// Address assigned during enumeration.
    pub address: u8,
    /// Speed detected at reset.
    pub speed: Option<Speed>,
    /// Parsed device descriptor.
    pub device_descriptor: DeviceDescriptor,
    /// Raw device descriptor bytes.
    pub raw_device_descriptor: Vec<u8>,
}

/// A magic device acting as a USB host that drives a downstream device.
///
/// High-level methods are convenient; [`raw_transaction`](UsbHost::raw_transaction)
/// and [`poll_events`](UsbHost::poll_events) are the forensic core.
pub trait UsbHost {
    /// Enable or disable VBUS to the target port.
    fn set_vbus(&mut self, on: bool) -> Result<()>;

    /// Read the current target-port status.
    fn port_status(&mut self) -> Result<PortStatus>;

    /// Drive a USB bus reset; returns the speed detected afterwards.
    fn bus_reset(&mut self) -> Result<Option<Speed>>;

    /// Perform a control transfer from **raw SETUP bytes** with stage-level
    /// forensic control — the low-level control primitive.
    ///
    /// `setup` is the 8 SETUP bytes exactly as they go on the wire (any value,
    /// including illegal `bmRequestType` / mismatched `wLength`). `opts` controls
    /// the data and status stages (see [`ControlForensics`]). For a compliant
    /// transfer, prefer [`control_transfer`](UsbHost::control_transfer).
    fn control_raw(
        &mut self,
        address: u8,
        setup: [u8; 8],
        data_out: &[u8],
        opts: ControlForensics,
    ) -> Result<ControlResult>;

    /// Perform a full, compliant control transfer to the device at `address`.
    ///
    /// For IN transfers `data_out` is ignored and the returned [`ControlResult::data`]
    /// holds the device's response; for OUT transfers `data_out` is the payload.
    /// Defaults to [`control_raw`](UsbHost::control_raw) with compliant options.
    fn control_transfer(
        &mut self,
        address: u8,
        setup: Setup,
        data_out: &[u8],
    ) -> Result<ControlResult> {
        self.control_raw(address, setup.to_bytes(), data_out, ControlForensics::default())
    }

    /// Perform a bulk or interrupt transfer on `endpoint`.
    fn transfer(
        &mut self,
        address: u8,
        endpoint: u8,
        dir: Direction,
        data: &[u8],
        max_len: usize,
    ) -> Result<TransactionResult>;

    /// Issue one low-level transaction with full forensic control.
    fn raw_transaction(&mut self, tx: RawTransaction) -> Result<TransactionResult>;

    /// Drain any pending wire-log events (non-blocking).
    fn poll_events(&mut self) -> Result<Vec<WireEvent>>;

    /// Enumerate the attached device: reset, read the descriptor head at address 0,
    /// assign an address, then read the full device descriptor.
    ///
    /// Built entirely on the methods above; override only if the device needs a
    /// non-standard sequence.
    fn enumerate(&mut self) -> Result<EnumeratedDevice> {
        let speed = self.bus_reset()?;

        // Read the first 8 bytes at address 0 to learn bMaxPacketSize0.
        let head = self.control_transfer(
            0,
            Setup {
                request_type: 0x80,
                request: request::GET_DESCRIPTOR,
                value: (u16::from(descriptor_type::DEVICE)) << 8,
                index: 0,
                length: 8,
            },
            &[],
        )?;
        if head.stalled || head.data.len() < 8 {
            return Err(Error::Protocol(
                "device did not return descriptor head at address 0".into(),
            ));
        }

        // Assign address 1 (single-device bring-up).
        let address = 1u8;
        let set_addr = self.control_transfer(
            0,
            Setup {
                request_type: 0x00,
                request: request::SET_ADDRESS,
                value: u16::from(address),
                index: 0,
                length: 0,
            },
            &[],
        )?;
        if set_addr.stalled {
            return Err(Error::Protocol("SET_ADDRESS was STALLed".into()));
        }

        // Read the full 18-byte device descriptor at the new address.
        let full = self.control_transfer(
            address,
            Setup {
                request_type: 0x80,
                request: request::GET_DESCRIPTOR,
                value: (u16::from(descriptor_type::DEVICE)) << 8,
                index: 0,
                length: 18,
            },
            &[],
        )?;
        if full.stalled || full.data.len() < 18 {
            return Err(Error::Protocol(
                "device did not return full device descriptor".into(),
            ));
        }

        Ok(EnumeratedDevice {
            address,
            speed,
            device_descriptor: DeviceDescriptor::parse(&full.data)?,
            raw_device_descriptor: full.data,
        })
    }

    /// `GET_DESCRIPTOR` for an arbitrary descriptor type/index/language, asking
    /// for `len` bytes. Returns the raw bytes the device sent (which may be
    /// shorter, or — forensically — longer if you asked for more than exists).
    fn get_descriptor(
        &mut self,
        address: u8,
        desc_type: u8,
        index: u8,
        lang: u16,
        len: u16,
    ) -> Result<Vec<u8>> {
        let r = self.control_transfer(
            address,
            Setup {
                request_type: 0x80,
                request: request::GET_DESCRIPTOR,
                value: (u16::from(desc_type) << 8) | u16::from(index),
                index: lang,
                length: len,
            },
            &[],
        )?;
        Ok(r.data)
    }

    /// Read and decode a string descriptor at `index` in `lang` (UTF-16LE).
    /// `index` 0 conventionally returns the LANGID list; this decodes it as text
    /// anyway (use [`descriptors::StringDescriptor::parse_langids`] for langids).
    fn get_string(&mut self, address: u8, index: u8, lang: u16) -> Result<String> {
        let raw = self.get_descriptor(address, descriptor_type::STRING, index, lang, 255)?;
        Ok(descriptors::StringDescriptor::decode(&raw))
    }

    /// Read configuration `cfg_index` in full (9-byte header to learn
    /// `wTotalLength`, then the whole blob) and parse it into a [`Configuration`].
    fn read_configuration(&mut self, address: u8, cfg_index: u8) -> Result<Configuration> {
        let head = self.get_descriptor(address, descriptor_type::CONFIGURATION, cfg_index, 0, 9)?;
        let total = ConfigurationDescriptor::parse(&head)
            .map(|c| c.total_length)
            .unwrap_or(head.len() as u16);
        let blob = self.get_descriptor(
            address,
            descriptor_type::CONFIGURATION,
            cfg_index,
            0,
            total,
        )?;
        Configuration::parse(&blob)
            .ok_or_else(|| Error::Protocol("configuration descriptor too short".into()))
    }

    /// **Analyze** the device at `address`: read the device descriptor, every
    /// configuration, and the referenced string descriptors into a
    /// [`UsbDeviceModel`]. Lenient — oddities are collected in
    /// [`UsbDeviceModel::anomalies`] instead of aborting.
    fn examine(&mut self, address: u8) -> Result<UsbDeviceModel> {
        let mut anomalies = Vec::new();
        let raw_dd = self.get_descriptor(address, descriptor_type::DEVICE, 0, 0, 18)?;
        if raw_dd.len() < 18 {
            anomalies.push(format!("device descriptor was {} bytes (<18)", raw_dd.len()));
        }
        let device_descriptor = DeviceDescriptor::parse(&raw_dd)?;
        let speed = self.port_status().ok().and_then(|p| p.speed);

        // Pick a language for strings: first LANGID, else en-US.
        let langids = descriptors::StringDescriptor::parse_langids(
            &self
                .get_descriptor(address, descriptor_type::STRING, 0, 0, 255)
                .unwrap_or_default(),
        );
        let lang = langids.first().copied().unwrap_or(0x0409);

        let mut configurations = Vec::new();
        for cfg in 0..device_descriptor.num_configurations {
            match self.read_configuration(address, cfg) {
                Ok(c) => configurations.push(c),
                Err(e) => anomalies.push(format!("configuration {cfg}: {e}")),
            }
        }

        // Collect string indices referenced by the descriptors.
        let mut strings = std::collections::BTreeMap::new();
        let mut want: Vec<u8> = vec![
            device_descriptor.manufacturer_index,
            device_descriptor.product_index,
            device_descriptor.serial_index,
        ];
        for c in &configurations {
            want.push(c.descriptor.configuration_index);
            for i in &c.interfaces {
                want.push(i.descriptor.interface_index);
            }
        }
        want.retain(|&i| i != 0);
        want.sort_unstable();
        want.dedup();
        for idx in want {
            match self.get_string(address, idx, lang) {
                Ok(s) => {
                    strings.insert((idx, lang), s);
                }
                Err(e) => anomalies.push(format!("string {idx}: {e}")),
            }
        }

        Ok(UsbDeviceModel {
            address,
            speed,
            device_descriptor,
            raw_device_descriptor: raw_dd,
            configurations,
            strings,
            anomalies,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_wire_byte_complement() {
        assert_eq!(Pid::Setup.value(), 0xD);
        assert_eq!(Pid::Setup.wire_byte(), 0x2D); // 0xD | (~0xD & 0xF)<<4
        assert_eq!(Pid::In.wire_byte(), 0x69);
        for p in [Pid::Out, Pid::In, Pid::Setup, Pid::Ack, Pid::Data0, Pid::Data1] {
            assert_eq!(Pid::from_value(p.value()), p);
        }
    }

    #[test]
    fn setup_serialization() {
        let s = Setup {
            request_type: 0x80,
            request: request::GET_DESCRIPTOR,
            value: 0x0100,
            index: 0,
            length: 18,
        };
        assert_eq!(s.to_bytes(), [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00]);
        assert!(s.is_in());
    }

    #[test]
    fn device_descriptor_parse() {
        let mut b = [0u8; 18];
        b[0] = 18;
        b[1] = descriptor_type::DEVICE;
        b[7] = 64;
        b[8] = 0x09;
        b[9] = 0x12; // VID 0x1209
        b[10] = 0x01;
        b[11] = 0x00; // PID 0x0001
        b[17] = 1;
        let d = DeviceDescriptor::parse(&b).unwrap();
        assert_eq!(d.vendor_id, 0x1209);
        assert_eq!(d.product_id, 0x0001);
        assert_eq!(d.max_packet_size0, 64);
        assert!(DeviceDescriptor::parse(&b[..4]).is_err());
    }
}
