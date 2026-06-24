//! Backend for the Great Scott Gadgets **Cynthion** running the USB Analyzer
//! gateware (USB ID `1d50:615b`).
//!
//! The analyzer is controlled with vendor control requests directed at the
//! capture interface, and streams captured traffic over a bulk IN endpoint as a
//! sequence of 16-bit-aligned records.
//!
//! # Attribution
//!
//! The control protocol (vendor request numbers and the State register
//! bitfield), the captured-record stream format, and [`clk_to_ns`] are derived
//! from Great Scott Gadgets' Packetry (<https://github.com/greatscottgadgets/packetry>),
//! BSD-3-Clause, Copyright (c) 2022-2024 Great Scott Gadgets. See the project
//! `LICENSE` file; the original copyright is retained as required.

use std::io::Read;
use std::time::Duration;

use nusb::transfer::{Bulk, ControlIn, ControlOut, ControlType, In, Recipient};
use nusb::{Interface, MaybeFuture};

use crate::backend::Backend;
use crate::capture::{
    CaptureData, CaptureItem, CaptureOptions, CaptureSource, CaptureStream, Speed, StopFn,
};
use crate::device::{describe, Capabilities, DeviceDescription, MagicDevice, State};
use crate::error::{Error, Result};

const VID: u16 = 0x1d50;
const PID: u16 = 0x615b;
/// Vendor-specific class of the analyzer capture interface.
const CLASS: u8 = 0xff;
/// Subclass identifying the analyzer capture interface.
const SUBCLASS: u8 = 0x10;
/// Bulk IN endpoint carrying the capture stream.
const ENDPOINT: u8 = 0x81;
/// Size of each bulk read.
const READ_LEN: usize = 0x4000;
/// Control transfer timeout.
const TIMEOUT: Duration = Duration::from_secs(1);

// Vendor request numbers (recipient = interface).
const REQ_GET_STATE: u8 = 0;
const REQ_SET_STATE: u8 = 1;
const REQ_GET_SPEEDS: u8 = 2;
const REQ_GET_VERSION: u8 = 4;

/// The Cynthion analyzer backend.
pub struct Cynthion;

/// Singleton instance registered in [`crate::backend::BACKENDS`].
pub static CYNTHION: Cynthion = Cynthion;

impl Backend for Cynthion {
    fn name(&self) -> &'static str {
        "cynthion"
    }

    fn matches(&self, info: &nusb::DeviceInfo) -> bool {
        info.vendor_id() == VID
            && info.product_id() == PID
            && info
                .interfaces()
                .any(|i| i.class() == CLASS && i.subclass() == SUBCLASS)
    }

    fn open(&self, info: nusb::DeviceInfo) -> Result<Box<dyn MagicDevice>> {
        let iface_num = info
            .interfaces()
            .find(|i| i.class() == CLASS && i.subclass() == SUBCLASS)
            .map(|i| i.interface_number())
            .ok_or(Error::Unsupported("no analyzer interface on device"))?;

        let description = describe(self.name(), &info);
        let device = info.open().wait()?;
        let interface = device.claim_interface(iface_num).wait()?;

        let speeds_byte = read_register(&interface, iface_num, REQ_GET_SPEEDS)?;
        let protocol_version = read_register(&interface, iface_num, REQ_GET_VERSION).ok();
        let capabilities = Capabilities {
            supported_speeds: decode_speeds(speeds_byte),
            can_capture: true,
            can_control_vbus: true,
            protocol_version,
        };

        Ok(Box::new(CynthionDevice {
            description,
            capabilities,
            interface,
            iface_num,
        }))
    }
}

/// An opened Cynthion analyzer.
struct CynthionDevice {
    description: DeviceDescription,
    capabilities: Capabilities,
    interface: Interface,
    iface_num: u8,
}

impl MagicDevice for CynthionDevice {
    fn description(&self) -> &DeviceDescription {
        &self.description
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn read_state(&mut self) -> Result<State> {
        let byte = read_register(&self.interface, self.iface_num, REQ_GET_STATE)?;
        Ok(decode_state(byte))
    }

    fn start_capture(&mut self, options: CaptureOptions) -> Result<CaptureStream> {
        if !self.capabilities.supported_speeds.contains(&options.speed) {
            return Err(Error::Unsupported("speed not supported by this device"));
        }

        let stop_state = encode_state(options.speed, false, false);
        let run_state = encode_state(options.speed, true, options.vbus_passthrough);

        // Make sure we start from a stopped state, then enable capture.
        write_state(&self.interface, self.iface_num, stop_state)?;
        write_state(&self.interface, self.iface_num, run_state)?;

        let reader = self
            .interface
            .endpoint::<Bulk, In>(ENDPOINT)?
            .reader(READ_LEN);

        Ok(CaptureStream::new(Box::new(CynthionCapture {
            reader: Box::new(reader),
            interface: self.interface.clone(),
            iface_num: self.iface_num,
            stop_state,
            parser: RecordParser::new(),
            scratch: vec![0u8; READ_LEN],
            done: false,
            stopped: false,
        })))
    }
}

/// Stateful decoder for the analyzer's bulk record stream.
///
/// Feed it raw bytes with [`RecordParser::extend`] and pull decoded items with
/// [`RecordParser::next_item`]. It owns no USB handle, so it is fully unit
/// testable over in-memory byte buffers.
struct RecordParser {
    /// Unparsed bytes; the valid range is `buf[pos..]`.
    buf: Vec<u8>,
    pos: usize,
    /// Running 60 MHz clock-cycle total.
    cycles: u64,
}

impl RecordParser {
    fn new() -> Self {
        RecordParser {
            buf: Vec::with_capacity(READ_LEN * 2),
            pos: 0,
            cycles: 0,
        }
    }

    /// Append freshly read bytes, compacting away already-consumed ones first.
    fn extend(&mut self, data: &[u8]) {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// Decode the next complete record, or `None` if more bytes are needed.
    fn next_item(&mut self) -> Option<CaptureItem> {
        if self.buf.len() - self.pos < 4 {
            return None;
        }
        let h = &self.buf[self.pos..self.pos + 4];

        if h[0] == 0xFF {
            // Event record: [0xFF, code, cycle_delta_be:2].
            let code = h[1];
            let delta = u16::from_be_bytes([h[2], h[3]]) as u64;
            self.pos += 4;
            self.cycles += delta;
            Some(CaptureItem {
                timestamp_ns: clk_to_ns(self.cycles),
                data: CaptureData::Event(code),
            })
        } else {
            // Packet record: [len_be:2, cycle_delta_be:2, payload, pad?].
            let len = u16::from_be_bytes([h[0], h[1]]) as usize;
            let delta = u16::from_be_bytes([h[2], h[3]]) as u64;
            let total = 4 + len + (len & 1); // 16-bit alignment padding
            if self.buf.len() - self.pos < total {
                return None;
            }
            let payload = self.buf[self.pos + 4..self.pos + 4 + len].to_vec();
            self.pos += total;
            self.cycles += delta;
            Some(CaptureItem {
                timestamp_ns: clk_to_ns(self.cycles),
                data: CaptureData::Packet(payload),
            })
        }
    }
}

/// Active capture: pulls bytes from the bulk reader and decodes records.
struct CynthionCapture {
    reader: Box<dyn Read + Send>,
    interface: Interface,
    iface_num: u8,
    /// State byte to write to disable capture.
    stop_state: u8,
    parser: RecordParser,
    /// Reusable read buffer.
    scratch: Vec<u8>,
    /// Stream has ended (EOF or error).
    done: bool,
    /// Capture has been disabled.
    stopped: bool,
}

impl Iterator for CynthionCapture {
    type Item = Result<CaptureItem>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            if let Some(item) = self.parser.next_item() {
                return Some(Ok(item));
            }
            match self.reader.read(&mut self.scratch) {
                Ok(0) => {
                    self.done = true;
                    return None;
                }
                Ok(n) => {
                    let chunk = self.scratch[..n].to_vec();
                    self.parser.extend(&chunk);
                }
                Err(e) => {
                    self.done = true;
                    return Some(Err(e.into()));
                }
            }
        }
    }
}

impl CaptureSource for CynthionCapture {
    fn stop(&mut self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        self.stopped = true;
        write_state(&self.interface, self.iface_num, self.stop_state)
    }

    fn stop_handle(&self) -> StopFn {
        let interface = self.interface.clone();
        let iface_num = self.iface_num;
        let stop_state = self.stop_state;
        Box::new(move || write_state(&interface, iface_num, stop_state))
    }
}

impl Drop for CynthionCapture {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Read a one-byte vendor register from the analyzer interface.
fn read_register(interface: &Interface, iface_num: u8, request: u8) -> Result<u8> {
    let data = interface
        .control_in(
            ControlIn {
                control_type: ControlType::Vendor,
                recipient: Recipient::Interface,
                request,
                value: 0,
                index: iface_num as u16,
                length: 64,
            },
            TIMEOUT,
        )
        .wait()?;
    data.first()
        .copied()
        .ok_or_else(|| Error::Protocol(format!("empty response to request {request}")))
}

/// Write the analyzer State register.
fn write_state(interface: &Interface, iface_num: u8, state: u8) -> Result<()> {
    interface
        .control_out(
            ControlOut {
                control_type: ControlType::Vendor,
                recipient: Recipient::Interface,
                request: REQ_SET_STATE,
                value: state as u16,
                index: iface_num as u16,
                data: &[],
            },
            TIMEOUT,
        )
        .wait()?;
    Ok(())
}

/// Decode the supported-speeds bitmask into a list of speeds.
fn decode_speeds(mask: u8) -> Vec<Speed> {
    Speed::ALL
        .into_iter()
        .filter(|s| mask & s.mask_bit() != 0)
        .collect()
}

/// Encode an analyzer State register byte.
fn encode_state(speed: Speed, enable: bool, vbus_passthrough: bool) -> u8 {
    let mut byte = 0u8;
    if enable {
        byte |= 1 << 0; // enable
    }
    byte |= (speed.encode() & 0b11) << 1; // speed
    if vbus_passthrough {
        byte |= 1 << 3; // target_c_vbus_en
    }
    byte
}

/// Decode an analyzer State register byte.
fn decode_state(byte: u8) -> State {
    State {
        enable: byte & (1 << 0) != 0,
        speed: Speed::from_encoded((byte >> 1) & 0b11),
        target_c_vbus_en: byte & (1 << 3) != 0,
        control_vbus_en: byte & (1 << 4) != 0,
        aux_vbus_en: byte & (1 << 5) != 0,
        target_a_discharge: byte & (1 << 6) != 0,
        power_control_enable: byte & (1 << 7) != 0,
    }
}

/// Convert a count of 60 MHz clock cycles to nanoseconds.
///
/// Three cycles span 50 ns exactly; the lookup table corrects the remainder so
/// the result tracks the device clock without drifting.
fn clk_to_ns(clk_cycles: u64) -> u64 {
    const TABLE: [u64; 3] = [0, 16, 33];
    (clk_cycles / 3) * 50 + TABLE[(clk_cycles % 3) as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clk_to_ns_table() {
        assert_eq!(clk_to_ns(0), 0);
        assert_eq!(clk_to_ns(1), 16);
        assert_eq!(clk_to_ns(2), 33);
        assert_eq!(clk_to_ns(3), 50);
        assert_eq!(clk_to_ns(6), 100);
        assert_eq!(clk_to_ns(60_000_000), 1_000_000_000); // 1 s at 60 MHz
    }

    #[test]
    fn speed_mask_and_encode_roundtrip() {
        for s in Speed::ALL {
            assert_eq!(Speed::from_encoded(s.encode()), s);
        }
        assert_eq!(decode_speeds(0b1111), Speed::ALL.to_vec());
        assert_eq!(decode_speeds(0b1000), vec![Speed::High]);
        assert_eq!(decode_speeds(0b0000), Vec::<Speed>::new());
    }

    #[test]
    fn state_encode_decode() {
        let b = encode_state(Speed::High, true, true);
        let s = decode_state(b);
        assert!(s.enable);
        assert_eq!(s.speed, Speed::High);
        assert!(s.target_c_vbus_en);
        assert!(!decode_state(encode_state(Speed::Full, false, false)).enable);
    }

    /// A packet record with the given payload and cycle delta, plus alignment pad.
    fn packet_record(delta: u16, payload: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        r.extend_from_slice(&delta.to_be_bytes());
        r.extend_from_slice(payload);
        if payload.len() % 2 == 1 {
            r.push(0x00); // 16-bit alignment padding
        }
        r
    }

    fn event_record(code: u8, delta: u16) -> Vec<u8> {
        let mut r = vec![0xFF, code];
        r.extend_from_slice(&delta.to_be_bytes());
        r
    }

    #[test]
    fn parses_packet_event_and_odd_padding() {
        let mut stream = Vec::new();
        stream.extend(packet_record(3, &[0xC3, 0x01, 0x02])); // odd length -> padded
        stream.extend(event_record(0x05, 3));
        stream.extend(packet_record(6, &[0x69, 0x00])); // even length -> no pad

        let mut p = RecordParser::new();
        p.extend(&stream);

        let a = p.next_item().expect("packet");
        assert_eq!(a.data, CaptureData::Packet(vec![0xC3, 0x01, 0x02]));
        assert_eq!(a.timestamp_ns, clk_to_ns(3));

        let b = p.next_item().expect("event");
        assert_eq!(b.data, CaptureData::Event(0x05));
        assert_eq!(b.timestamp_ns, clk_to_ns(6)); // cumulative: 3 + 3

        let c = p.next_item().expect("packet");
        assert_eq!(c.data, CaptureData::Packet(vec![0x69, 0x00]));
        assert_eq!(c.timestamp_ns, clk_to_ns(12)); // cumulative: 6 + 6

        assert!(p.next_item().is_none());
    }

    #[test]
    fn handles_records_split_across_reads() {
        let record = packet_record(10, &[0xAA, 0xBB, 0xCC, 0xDD]);
        let mut p = RecordParser::new();

        // Feed the record one byte at a time; only the last byte completes it.
        for (i, byte) in record.iter().enumerate() {
            p.extend(&[*byte]);
            if i + 1 < record.len() {
                assert!(p.next_item().is_none(), "incomplete at byte {i}");
            }
        }
        let item = p.next_item().expect("completed packet");
        assert_eq!(item.data, CaptureData::Packet(vec![0xAA, 0xBB, 0xCC, 0xDD]));
        assert!(p.next_item().is_none());
    }
}
