//! Minimal **pcapng** writer for USB Type-C Power Delivery traces.
//!
//! PD messages don't fit any existing link-layer type, so we emit them under a
//! new, purpose-defined link type [`LINKTYPE_USB_TYPE_C_PD`]: each packet is an
//! 8-byte [pseudo-header](pd_pseudo_header) (version, SOP type, direction, flags,
//! CRC) followed by the Power Delivery message exactly as in section 6.2
//! "Messages" of the USB Power Delivery specification (the 16-bit header plus any
//! data objects; no preamble, no on-wire CRC bytes).
//!
//! The number 304 is **provisional** — the next currently-unallocated link type
//! when this was written — pending an official allocation. The format follows the
//! guidance in libpcap issue #1036; see `docs/linktypes/LINKTYPE_USB_TYPE_C_PD.html`.
//!
//! pcapng is used (not legacy pcap) so multiple capture ports map cleanly onto
//! separate Interface Description Blocks: by convention interface 0 = TARGET-C,
//! interface 1 = AUX, so the port is encoded by the packet's interface id and the
//! pseudo-header stays instrument-agnostic.
//!
//! SPDX-License-Identifier: BSD-3-Clause

use std::io::{self, Write};

/// Provisional pcapng/pcap link type for USB Type-C Power Delivery packets:
/// an 8-byte pseudo-header followed by a PD message (USB-PD spec §6.2).
pub const LINKTYPE_USB_TYPE_C_PD: u32 = 304;

/// SOP* sequence a PD message was framed with (pseudo-header `sop_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PdSop {
    /// SOP — port-to-port (the device under test).
    Sop = 0,
    /// SOP' — to the near-end cable plug.
    SopPrime = 1,
    /// SOP'' — to the far-end cable plug.
    SopDoublePrime = 2,
    /// SOP'_Debug.
    SopPrimeDebug = 3,
    /// SOP''_Debug.
    SopDoublePrimeDebug = 4,
    /// Hard Reset ordered set.
    HardReset = 5,
    /// Cable Reset ordered set.
    CableReset = 6,
    /// Framing not known / not recorded.
    Unknown = 0xFF,
}

/// Direction of a PD message relative to the device under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdDirection {
    /// Sent by the DUT toward our instrument (a received message).
    FromDut,
    /// Sent by our instrument toward the DUT (a transmitted message).
    ToDut,
}

impl PdDirection {
    fn wire(self) -> u8 {
        match self {
            PdDirection::FromDut => 0,
            PdDirection::ToDut => 1,
        }
    }
}

// Pseudo-header flag bits.
const FLAG_CRC_PRESENT: u8 = 1 << 0;
const FLAG_CRC_VALID: u8 = 1 << 1;
const FLAG_CC2: u8 = 1 << 2; // 0 = CC1, 1 = CC2

/// Build the 8-byte [`LINKTYPE_USB_TYPE_C_PD`] pseudo-header.
///
/// Layout (all multi-byte fields little-endian):
/// ```text
///   0  u8   version       = 1
///   1  u8   sop_type      (PdSop)
///   2  u8   direction     0 = from DUT (rx), 1 = to DUT (tx)
///   3  u8   flags         bit0 CRC_PRESENT, bit1 CRC_VALID, bit2 CC_POLARITY (0=CC1,1=CC2)
///   4  u32  crc32         on-wire CRC-32 if CRC_PRESENT, else 0
/// ```
/// `cc` is 1 or 2 (0 = unknown, recorded as CC1). `crc` is `Some` only when the
/// real on-wire CRC was captured — controllers with hardware AUTO_CRC (e.g. the
/// FUSB302B) check/append it themselves, so we pass `None` and clear CRC_PRESENT.
pub fn pd_pseudo_header(sop: PdSop, dir: PdDirection, cc: u8, crc: Option<u32>) -> [u8; 8] {
    let mut flags = 0u8;
    if cc == 2 {
        flags |= FLAG_CC2;
    }
    let crc_val = match crc {
        Some(c) => {
            flags |= FLAG_CRC_PRESENT | FLAG_CRC_VALID;
            c
        }
        None => 0,
    };
    let mut h = [0u8; 8];
    h[0] = 1; // version
    h[1] = sop as u8;
    h[2] = dir.wire();
    h[3] = flags;
    h[4..8].copy_from_slice(&crc_val.to_le_bytes());
    h
}

/// Description of one capture interface (one pcapng IDB).
pub struct IfaceDesc<'a> {
    /// Human-readable name (pcapng `if_name` option), e.g. "TARGET-C".
    pub name: &'a str,
    /// Link type for this interface.
    pub linktype: u32,
    /// Snap length advertised for this interface.
    pub snaplen: u32,
}

// Block types.
const BT_SHB: u32 = 0x0A0D_0D0A;
const BT_IDB: u32 = 0x0000_0001;
const BT_EPB: u32 = 0x0000_0006;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

/// Writes a USB-PD trace as a pcapng stream.
///
/// Timestamps are microseconds since the Unix epoch (`if_tsresol` = 6).
pub struct PcapNgWriter<W: Write> {
    out: W,
}

impl<W: Write> PcapNgWriter<W> {
    /// Create a writer, emitting the Section Header Block and one Interface
    /// Description Block per entry in `interfaces` (interface id = index).
    pub fn new(mut out: W, interfaces: &[IfaceDesc]) -> io::Result<Self> {
        // Section Header Block.
        let mut shb = Vec::new();
        shb.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
        shb.extend_from_slice(&1u16.to_le_bytes()); // major
        shb.extend_from_slice(&0u16.to_le_bytes()); // minor
        shb.extend_from_slice(&(-1i64).to_le_bytes()); // section length: unknown
        write_block(&mut out, BT_SHB, &shb)?;

        for iface in interfaces {
            let mut idb = Vec::new();
            idb.extend_from_slice(&(iface.linktype as u16).to_le_bytes());
            idb.extend_from_slice(&0u16.to_le_bytes()); // reserved
            idb.extend_from_slice(&iface.snaplen.to_le_bytes());
            // Options: if_name (code 2), if_tsresol (code 9, microseconds), endofopt.
            push_option(&mut idb, 2, iface.name.as_bytes());
            push_option(&mut idb, 9, &[6]); // 10^-6 s
            push_option(&mut idb, 0, &[]); // opt_endofopt
            write_block(&mut out, BT_IDB, &idb)?;
        }
        Ok(PcapNgWriter { out })
    }

    /// Append one packet on `iface_id`, timestamped `ts_unix_us` microseconds
    /// since the Unix epoch. `data` is the full link-layer payload (pseudo-header
    /// + PD message).
    pub fn write_packet(&mut self, iface_id: u32, ts_unix_us: u64, data: &[u8]) -> io::Result<()> {
        let mut epb = Vec::new();
        epb.extend_from_slice(&iface_id.to_le_bytes());
        epb.extend_from_slice(&((ts_unix_us >> 32) as u32).to_le_bytes()); // ts high
        epb.extend_from_slice(&((ts_unix_us & 0xFFFF_FFFF) as u32).to_le_bytes()); // ts low
        epb.extend_from_slice(&(data.len() as u32).to_le_bytes()); // captured len
        epb.extend_from_slice(&(data.len() as u32).to_le_bytes()); // original len
        epb.extend_from_slice(data);
        while epb.len() % 4 != 0 {
            epb.push(0); // pad packet data to 32 bits (within the block body)
        }
        write_block(&mut self.out, BT_EPB, &epb)
    }

    /// Flush buffered output.
    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Write a generic pcapng block: type, total length, body (padded to 32 bits),
/// trailing total length.
fn write_block<W: Write>(out: &mut W, block_type: u32, body: &[u8]) -> io::Result<()> {
    let pad = (4 - body.len() % 4) % 4;
    let total = (12 + body.len() + pad) as u32;
    out.write_all(&block_type.to_le_bytes())?;
    out.write_all(&total.to_le_bytes())?;
    out.write_all(body)?;
    out.write_all(&vec![0u8; pad])?;
    out.write_all(&total.to_le_bytes())?;
    Ok(())
}

/// Append a pcapng option (code, value padded to 32 bits) to a block body.
fn push_option(body: &mut Vec<u8>, code: u16, value: &[u8]) {
    body.extend_from_slice(&code.to_le_bytes());
    body.extend_from_slice(&(value.len() as u16).to_le_bytes());
    body.extend_from_slice(value);
    while body.len() % 4 != 0 {
        body.push(0);
    }
}

// ---------------------------------------------------------------------------
// Reader: parse a pcapng file back into interfaces + packets, and decode the
// USB-PD pseudo-header. Used by `usbmagic pd-dump`.
// ---------------------------------------------------------------------------

/// One interface (IDB) read from a pcapng file.
#[derive(Debug, Clone)]
pub struct PcapNgInterface {
    /// `if_name` option, if present (e.g. "TARGET-C").
    pub name: Option<String>,
    /// Link type for this interface.
    pub linktype: u32,
    /// `if_tsresol`: timestamp units are 10^-tsresol seconds (decimal form).
    pub tsresol: u8,
}

/// One captured packet (EPB) read from a pcapng file.
#[derive(Debug, Clone)]
pub struct PcapNgPacket {
    /// Index into the interface table.
    pub iface_id: u32,
    /// Raw timestamp in the interface's `tsresol` units since the Unix epoch.
    pub ts: u64,
    /// Captured link-layer bytes (pseudo-header + PD message for our link type).
    pub data: Vec<u8>,
}

/// Parsed contents of a pcapng file.
#[derive(Debug, Clone)]
pub struct PcapNg {
    /// Interfaces, in IDB order (index = interface id).
    pub interfaces: Vec<PcapNgInterface>,
    /// Captured packets, in file order.
    pub packets: Vec<PcapNgPacket>,
}

fn rd_u16(b: &[u8], le: bool) -> u16 {
    let a = [b[0], b[1]];
    if le {
        u16::from_le_bytes(a)
    } else {
        u16::from_be_bytes(a)
    }
}
fn rd_u32(b: &[u8], le: bool) -> u32 {
    let a = [b[0], b[1], b[2], b[3]];
    if le {
        u32::from_le_bytes(a)
    } else {
        u32::from_be_bytes(a)
    }
}

/// Parse a pcapng byte stream into interfaces and packets. Handles both byte
/// orders; ignores block and option types it doesn't need.
pub fn parse_pcapng(buf: &[u8]) -> std::result::Result<PcapNg, String> {
    let mut le = true;
    let mut interfaces: Vec<PcapNgInterface> = Vec::new();
    let mut packets: Vec<PcapNgPacket> = Vec::new();
    let mut off = 0usize;
    while off + 12 <= buf.len() {
        // The SHB block type (0x0A0D0D0A) is byte-order independent; use it to
        // (re)detect endianness from the byte-order magic before reading lengths.
        if buf[off..off + 4] == [0x0A, 0x0D, 0x0D, 0x0A] {
            if off + 12 > buf.len() {
                break;
            }
            le = buf[off + 8..off + 12] == [0x4D, 0x3C, 0x2B, 0x1A];
        }
        let total = rd_u32(&buf[off + 4..off + 8], le) as usize;
        if total < 12 || off + total > buf.len() {
            break;
        }
        let bt = rd_u32(&buf[off..off + 4], le);
        let body = &buf[off + 8..off + total - 4];
        match bt {
            // Interface Description Block.
            0x0000_0001 if body.len() >= 8 => {
                let linktype = rd_u16(&body[0..2], le) as u32;
                let mut name = None;
                let mut tsresol = 6u8;
                let mut o = 8usize;
                while o + 4 <= body.len() {
                    let code = rd_u16(&body[o..o + 2], le);
                    let len = rd_u16(&body[o + 2..o + 4], le) as usize;
                    o += 4;
                    if code == 0 || o + len > body.len() {
                        break;
                    }
                    match code {
                        2 => name = Some(String::from_utf8_lossy(&body[o..o + len]).into_owned()),
                        9 if len >= 1 => tsresol = body[o],
                        _ => {}
                    }
                    o += len + ((4 - len % 4) % 4);
                }
                interfaces.push(PcapNgInterface { name, linktype, tsresol });
            }
            // Enhanced Packet Block.
            0x0000_0006 if body.len() >= 20 => {
                let iface_id = rd_u32(&body[0..4], le);
                let ts = ((rd_u32(&body[4..8], le) as u64) << 32) | rd_u32(&body[8..12], le) as u64;
                let caplen = rd_u32(&body[12..16], le) as usize;
                let end = (20 + caplen).min(body.len());
                packets.push(PcapNgPacket {
                    iface_id,
                    ts,
                    data: body[20..end].to_vec(),
                });
            }
            _ => {} // SHB, short blocks, and anything else: skip
        }
        off += total;
    }
    if interfaces.is_empty() && packets.is_empty() {
        return Err("no pcapng blocks found".into());
    }
    Ok(PcapNg { interfaces, packets })
}

/// A decoded [`LINKTYPE_USB_TYPE_C_PD`] pseudo-header.
#[derive(Debug, Clone, Copy)]
pub struct PdPseudoHeader {
    /// Pseudo-header version.
    pub version: u8,
    /// Raw SOP type byte (see [`sop_name`]).
    pub sop: u8,
    /// Message direction.
    pub direction: PdDirection,
    /// CC line (1 or 2).
    pub cc: u8,
    /// On-wire CRC-32, if it was captured.
    pub crc: Option<u32>,
}

/// Decode the 8-byte USB-PD pseudo-header at the start of `d` (the PD message
/// follows at `d[8..]`). Returns `None` if `d` is too short.
pub fn parse_pd_pseudo_header(d: &[u8]) -> Option<PdPseudoHeader> {
    if d.len() < 8 {
        return None;
    }
    let flags = d[3];
    let crc = (flags & FLAG_CRC_PRESENT != 0)
        .then(|| u32::from_le_bytes([d[4], d[5], d[6], d[7]]));
    let direction = if d[2] == 1 {
        PdDirection::ToDut
    } else {
        PdDirection::FromDut
    };
    Some(PdPseudoHeader {
        version: d[0],
        sop: d[1],
        direction,
        cc: if flags & FLAG_CC2 != 0 { 2 } else { 1 },
        crc,
    })
}

/// Human-readable name for a pseudo-header `sop_type` byte.
pub fn sop_name(v: u8) -> &'static str {
    match v {
        0 => "SOP",
        1 => "SOP'",
        2 => "SOP''",
        3 => "SOP'_Debug",
        4 => "SOP''_Debug",
        5 => "Hard Reset",
        6 => "Cable Reset",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudo_header_layout() {
        // TX on CC2, no CRC captured.
        let h = pd_pseudo_header(PdSop::Sop, PdDirection::ToDut, 2, None);
        assert_eq!(h[0], 1); // version
        assert_eq!(h[1], 0); // SOP
        assert_eq!(h[2], 1); // to DUT
        assert_eq!(h[3], FLAG_CC2); // CC2, no CRC
        assert_eq!(&h[4..8], &0u32.to_le_bytes());

        // RX on CC1 with a captured CRC.
        let h = pd_pseudo_header(PdSop::SopPrime, PdDirection::FromDut, 1, Some(0xDEAD_BEEF));
        assert_eq!(h[1], 1); // SOP'
        assert_eq!(h[2], 0); // from DUT
        assert_eq!(h[3], FLAG_CRC_PRESENT | FLAG_CRC_VALID); // CC1, CRC present+valid
        assert_eq!(&h[4..8], &0xDEAD_BEEFu32.to_le_bytes());
    }

    #[test]
    fn shb_and_idb_layout() {
        let ifaces = [IfaceDesc {
            name: "TARGET-C",
            linktype: LINKTYPE_USB_TYPE_C_PD,
            snaplen: 1024,
        }];
        let w = PcapNgWriter::new(Vec::new(), &ifaces).unwrap();
        let buf = w.out;
        // SHB: type, total=28, byte-order magic.
        assert_eq!(&buf[0..4], &BT_SHB.to_le_bytes());
        assert_eq!(&buf[4..8], &28u32.to_le_bytes());
        assert_eq!(&buf[8..12], &BYTE_ORDER_MAGIC.to_le_bytes());
        assert_eq!(&buf[24..28], &28u32.to_le_bytes()); // trailing length
        // IDB starts at 28.
        let idb = &buf[28..];
        assert_eq!(&idb[0..4], &BT_IDB.to_le_bytes());
        assert_eq!(&idb[8..10], &(LINKTYPE_USB_TYPE_C_PD as u16).to_le_bytes());
        assert_eq!(&idb[12..16], &1024u32.to_le_bytes()); // snaplen
    }

    #[test]
    fn epb_layout_and_padding() {
        let ifaces = [IfaceDesc {
            name: "T",
            linktype: LINKTYPE_USB_TYPE_C_PD,
            snaplen: 64,
        }];
        let mut w = PcapNgWriter::new(Vec::new(), &ifaces).unwrap();
        let before = w.out.len();
        // 3-byte payload -> padded to 4 within the block.
        w.write_packet(0, 0x0000_0001_0000_0002, &[0xAA, 0xBB, 0xCC]).unwrap();
        let epb = &w.out[before..];
        assert_eq!(&epb[0..4], &BT_EPB.to_le_bytes());
        // body = iface(4)+tshi(4)+tslo(4)+cap(4)+orig(4)+data(3)+pad(1) = 24; total = 12+24 = 36
        assert_eq!(&epb[4..8], &36u32.to_le_bytes());
        assert_eq!(&epb[8..12], &0u32.to_le_bytes()); // interface id 0
        assert_eq!(&epb[12..16], &1u32.to_le_bytes()); // ts high
        assert_eq!(&epb[16..20], &2u32.to_le_bytes()); // ts low
        assert_eq!(&epb[20..24], &3u32.to_le_bytes()); // captured len
        assert_eq!(&epb[24..28], &3u32.to_le_bytes()); // original len
        assert_eq!(&epb[28..31], &[0xAA, 0xBB, 0xCC]);
        assert_eq!(epb.len() % 4, 0);
        assert_eq!(&epb[epb.len() - 4..], &36u32.to_le_bytes()); // trailing length
    }

    #[test]
    fn write_then_read_roundtrip() {
        let ifaces = [
            IfaceDesc { name: "TARGET-C", linktype: LINKTYPE_USB_TYPE_C_PD, snaplen: 4096 },
            IfaceDesc { name: "AUX", linktype: LINKTYPE_USB_TYPE_C_PD, snaplen: 4096 },
        ];
        let mut w = PcapNgWriter::new(Vec::new(), &ifaces).unwrap();
        let mut pkt = pd_pseudo_header(PdSop::Sop, PdDirection::ToDut, 1, None).to_vec();
        pkt.extend_from_slice(&[0x6f, 0x11, 0x01, 0x80, 0xac, 0x05]); // a VDM
        w.write_packet(0, 1_700_000_000_000_000, &pkt).unwrap();
        let buf = w.out;

        let parsed = parse_pcapng(&buf).unwrap();
        assert_eq!(parsed.interfaces.len(), 2);
        assert_eq!(parsed.interfaces[0].name.as_deref(), Some("TARGET-C"));
        assert_eq!(parsed.interfaces[1].name.as_deref(), Some("AUX"));
        assert_eq!(parsed.interfaces[0].linktype, LINKTYPE_USB_TYPE_C_PD);
        assert_eq!(parsed.packets.len(), 1);
        let p = &parsed.packets[0];
        assert_eq!(p.iface_id, 0);
        assert_eq!(p.ts, 1_700_000_000_000_000);
        assert_eq!(p.data, pkt);

        let ph = parse_pd_pseudo_header(&p.data).unwrap();
        assert_eq!(ph.version, 1);
        assert_eq!(ph.sop, 0);
        assert_eq!(ph.direction, PdDirection::ToDut);
        assert_eq!(ph.cc, 1);
        assert_eq!(ph.crc, None);
        assert_eq!(&p.data[8..], &[0x6f, 0x11, 0x01, 0x80, 0xac, 0x05]);
    }
}
