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
}
