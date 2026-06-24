//! Minimal pcap writer producing files that open directly in Wireshark.
//!
//! Captured packets are written with link type `LINKTYPE_USB_2_0` (288), which
//! expects raw USB 2.0 packets beginning with the PID byte — exactly what the
//! Cynthion analyzer streams. Nanosecond timestamp resolution is used so the
//! device's 60 MHz timing is preserved.

use std::io::{self, Write};

/// pcap link type for raw USB 2.0 packets (PID-first).
pub const LINKTYPE_USB_2_0: u32 = 288;

/// Magic number selecting nanosecond-resolution timestamps.
const PCAP_MAGIC_NANOS: u32 = 0xa1b2_3c4d;
/// Snap length advertised in the header (larger than any USB 2.0 packet).
const SNAPLEN: u32 = 262_144;

/// Writes captured packets to a `.pcap` stream.
pub struct PcapWriter<W: Write> {
    out: W,
    /// Wall-clock anchor (Unix nanoseconds) that capture time 0 maps to.
    base_unix_ns: u128,
}

impl<W: Write> PcapWriter<W> {
    /// Create a writer and emit the global header.
    ///
    /// `base_unix_ns` is the absolute time (nanoseconds since the Unix epoch)
    /// corresponding to a capture timestamp of 0; per-packet timestamps are
    /// added to it.
    pub fn new(mut out: W, base_unix_ns: u128) -> io::Result<Self> {
        out.write_all(&PCAP_MAGIC_NANOS.to_le_bytes())?;
        out.write_all(&2u16.to_le_bytes())?; // version major
        out.write_all(&4u16.to_le_bytes())?; // version minor
        out.write_all(&0i32.to_le_bytes())?; // thiszone (GMT)
        out.write_all(&0u32.to_le_bytes())?; // sigfigs
        out.write_all(&SNAPLEN.to_le_bytes())?; // snaplen
        out.write_all(&LINKTYPE_USB_2_0.to_le_bytes())?; // network
        Ok(PcapWriter { out, base_unix_ns })
    }

    /// Append one packet, timestamped `ts_ns` nanoseconds into the capture.
    pub fn write_packet(&mut self, ts_ns: u64, data: &[u8]) -> io::Result<()> {
        let abs = self.base_unix_ns + ts_ns as u128;
        let sec = (abs / 1_000_000_000) as u32;
        let nsec = (abs % 1_000_000_000) as u32;
        let len = data.len() as u32;

        self.out.write_all(&sec.to_le_bytes())?; // ts_sec
        self.out.write_all(&nsec.to_le_bytes())?; // ts_nsec
        self.out.write_all(&len.to_le_bytes())?; // incl_len
        self.out.write_all(&len.to_le_bytes())?; // orig_len
        self.out.write_all(data)?;
        Ok(())
    }

    /// Flush buffered output.
    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_header_layout() {
        let buf = Vec::new();
        let w = PcapWriter::new(buf, 0).unwrap();
        let buf = w.out;
        assert_eq!(buf.len(), 24);
        assert_eq!(&buf[0..4], &PCAP_MAGIC_NANOS.to_le_bytes());
        assert_eq!(&buf[4..6], &2u16.to_le_bytes()); // major
        assert_eq!(&buf[6..8], &4u16.to_le_bytes()); // minor
        assert_eq!(&buf[20..24], &LINKTYPE_USB_2_0.to_le_bytes());
    }

    #[test]
    fn packet_record_layout() {
        let mut w = PcapWriter::new(Vec::new(), 1_000_000_000).unwrap();
        w.write_packet(500, &[0xAA, 0xBB, 0xCC]).unwrap();
        let rec = &w.out[24..]; // skip global header
        assert_eq!(&rec[0..4], &1u32.to_le_bytes()); // ts_sec = 1
        assert_eq!(&rec[4..8], &500u32.to_le_bytes()); // ts_nsec = 500
        assert_eq!(&rec[8..12], &3u32.to_le_bytes()); // incl_len
        assert_eq!(&rec[12..16], &3u32.to_le_bytes()); // orig_len
        assert_eq!(&rec[16..19], &[0xAA, 0xBB, 0xCC]);
    }
}
