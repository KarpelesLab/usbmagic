//! USB **Power Delivery** capability over the Type-C CC lines.
//!
//! On the Cynthion this is implemented by the FUSB302B controllers on the
//! TARGET-C and AUX ports (driven by the FPGA over I2C — see `docs/ARCHITECTURE.md`
//! §2.1). The BMC physical layer lives in the controller; this trait models the
//! policy/message layer plus raw register access for forensic work, including
//! custom Vendor-Defined Messages and VCONN control.

use std::time::Duration;

use crate::error::{Error, Result};

/// Which Type-C port's PD controller to address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdPort {
    /// TARGET-C — the device-under-test Type-C port.
    TargetC,
    /// AUX Type-C port.
    Aux,
}

/// CC line on which the connection was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcOrientation {
    None,
    Cc1,
    Cc2,
}

/// Snapshot of the CC / attach state reported by the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CcStatus {
    /// A partner is attached.
    pub attached: bool,
    /// Which CC line is active.
    pub orientation: CcOrientation,
    /// VCONN is currently sourced.
    pub vconn: bool,
    /// We are presenting as a source (Rp); else sink (Rd).
    pub is_source: bool,
}

/// USB-PD message kind, distinguishing control vs data vs extended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdMessageClass {
    Control,
    Data,
    Extended,
}

/// A USB Power Delivery message: the 16-bit header plus its data objects.
///
/// Carried as raw little-endian bytes (header first) so non-compliant or unknown
/// messages round-trip losslessly; accessors decode the standard header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdMessage {
    /// Header + payload, exactly as on the wire (BMC payload, no CRC/preamble).
    pub raw: Vec<u8>,
}

impl PdMessage {
    /// Build from a 16-bit header and a list of 32-bit data objects.
    pub fn from_objects(header: u16, objects: &[u32]) -> PdMessage {
        let mut raw = Vec::with_capacity(2 + objects.len() * 4);
        raw.extend_from_slice(&header.to_le_bytes());
        for o in objects {
            raw.extend_from_slice(&o.to_le_bytes());
        }
        PdMessage { raw }
    }

    /// The 16-bit message header, if present.
    pub fn header(&self) -> Option<u16> {
        (self.raw.len() >= 2).then(|| u16::from_le_bytes([self.raw[0], self.raw[1]]))
    }

    /// Message type field (header bits 0–4).
    pub fn message_type(&self) -> Option<u8> {
        self.header().map(|h| (h & 0x1F) as u8)
    }

    /// Number of 32-bit data objects (header bits 12–14).
    pub fn num_data_objects(&self) -> Option<u8> {
        self.header().map(|h| ((h >> 12) & 0x7) as u8)
    }

    /// Whether this is a control (no data objects), data, or extended message.
    pub fn class(&self) -> Option<PdMessageClass> {
        let h = self.header()?;
        let extended = (h >> 15) & 1 == 1;
        let ndo = (h >> 12) & 0x7;
        Some(if extended {
            PdMessageClass::Extended
        } else if ndo == 0 {
            PdMessageClass::Control
        } else {
            PdMessageClass::Data
        })
    }

    /// The data objects (each 32-bit, little-endian) following the header.
    pub fn objects(&self) -> Vec<u32> {
        self.raw[2.min(self.raw.len())..]
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    }
}

/// A Power Data Object as advertised in a Source_Capabilities message.
///
/// Kept as the raw 32-bit value plus convenience decoders for the common
/// Fixed-supply PDO; exotic PDOs are still accessible via [`Pdo::raw`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pdo {
    pub raw: u32,
}

impl Pdo {
    /// True if this is a Fixed Supply PDO (type bits 30–31 == 0).
    pub fn is_fixed(self) -> bool {
        (self.raw >> 30) & 0x3 == 0
    }
    /// Fixed-supply voltage in millivolts (50 mV units, bits 10–19).
    pub fn fixed_voltage_mv(self) -> Option<u32> {
        self.is_fixed().then(|| ((self.raw >> 10) & 0x3FF) * 50)
    }
    /// Fixed-supply maximum current in milliamps (10 mA units, bits 0–9).
    pub fn fixed_max_current_ma(self) -> Option<u32> {
        self.is_fixed().then(|| (self.raw & 0x3FF) * 10)
    }

    /// True if this is an Augmented PDO (APDO), e.g. a PPS supply (bits 30–31 == 0b11).
    pub fn is_augmented(self) -> bool {
        (self.raw >> 30) & 0x3 == 0b11
    }

    /// If this is a PPS (SPR Programmable Power Supply) APDO, returns
    /// `(min_mv, max_mv, max_ma)`. PPS is APDO subtype 0 (bits 28–29 == 0).
    pub fn pps(self) -> Option<(u32, u32, u32)> {
        if !self.is_augmented() || (self.raw >> 28) & 0x3 != 0 {
            return None;
        }
        let max_mv = ((self.raw >> 17) & 0xFF) * 100; // 100 mV units
        let min_mv = ((self.raw >> 8) & 0xFF) * 100; // 100 mV units
        let max_ma = (self.raw & 0x7F) * 50; // 50 mA units
        Some((min_mv, max_mv, max_ma))
    }
}

/// A Vendor-Defined Message (structured VDM), the primary vehicle for custom PD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vdm {
    /// Standard or Vendor ID (header bits 16–31).
    pub svid: u16,
    /// Command (header bits 0–4).
    pub command: u8,
    /// Command type (header bits 6–7): 0=REQ, 1=ACK, 2=NAK, 3=BUSY.
    pub command_type: u8,
    /// Object position (header bits 8–10), 0 if unused.
    pub object_position: u8,
    /// Following VDOs (vendor data objects).
    pub objects: Vec<u32>,
}

impl Vdm {
    /// Encode as a structured-VDM header word (the first data object).
    pub fn vdm_header(&self) -> u32 {
        (u32::from(self.svid) << 16)
            | (1 << 15) // structured VDM
            | (u32::from(self.object_position & 0x7) << 8)
            | (u32::from(self.command_type & 0x3) << 6)
            | u32::from(self.command & 0x1F)
    }
}

/// Driving USB Power Delivery on a Type-C port.
pub trait PowerDelivery {
    /// Read the CC/attach status of a port.
    fn cc_status(&mut self, port: PdPort) -> Result<CcStatus>;

    /// Enable or disable VCONN output (e.g. to power an e-marked cable).
    fn set_vconn(&mut self, port: PdPort, on: bool) -> Result<()>;

    /// Transmit a raw PD message on a port.
    fn pd_send(&mut self, port: PdPort, message: &PdMessage) -> Result<()>;

    /// Receive the next PD message within `timeout`, if any.
    fn pd_recv(&mut self, port: PdPort, timeout: Duration) -> Result<Option<PdMessage>>;

    /// Read a raw controller (FUSB302B) register — forensic/low-level access.
    fn controller_read(&mut self, port: PdPort, reg: u8) -> Result<u8>;

    /// Write a raw controller (FUSB302B) register.
    fn controller_write(&mut self, port: PdPort, reg: u8, value: u8) -> Result<()>;

    /// Send a structured Vendor-Defined Message. Default builds the message from
    /// the VDM header + objects and calls [`pd_send`](PowerDelivery::pd_send).
    ///
    /// `header` is the 16-bit PD message header the caller wants to use (so the
    /// message type / spec-rev / role bits stay under the caller's control — a
    /// forensic tool must be able to set them freely, including illegal combos).
    fn send_vdm(&mut self, port: PdPort, header: u16, vdm: &Vdm) -> Result<()> {
        let mut objects = Vec::with_capacity(1 + vdm.objects.len());
        objects.push(vdm.vdm_header());
        objects.extend_from_slice(&vdm.objects);
        // Sanity: the header's data-object count should match what we send.
        let ndo = ((header >> 12) & 0x7) as usize;
        if ndo != objects.len() {
            return Err(Error::Protocol(format!(
                "VDM header declares {ndo} data objects but {} were provided",
                objects.len()
            )));
        }
        self.pd_send(port, &PdMessage::from_objects(header, &objects))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pd_header_decode() {
        // GoodCRC (control msg type 1), 0 data objects.
        let m = PdMessage::from_objects(0x0001, &[]);
        assert_eq!(m.message_type(), Some(1));
        assert_eq!(m.num_data_objects(), Some(0));
        assert_eq!(m.class(), Some(PdMessageClass::Control));

        // Source_Capabilities (data msg type 1) with 1 data object.
        let header = 0x0001 | (1 << 12);
        let m = PdMessage::from_objects(header, &[0x0001_2c91]);
        assert_eq!(m.num_data_objects(), Some(1));
        assert_eq!(m.class(), Some(PdMessageClass::Data));
        assert_eq!(m.objects(), vec![0x0001_2c91]);
    }

    #[test]
    fn fixed_pdo_decode() {
        // 5V @ 3A fixed PDO: voltage=100 (×50mV), current=300 (×10mA).
        let raw = (100u32 << 10) | 300;
        let pdo = Pdo { raw };
        assert!(pdo.is_fixed());
        assert_eq!(pdo.fixed_voltage_mv(), Some(5000));
        assert_eq!(pdo.fixed_max_current_ma(), Some(3000));
    }

    #[test]
    fn vdm_header_encode() {
        let vdm = Vdm {
            svid: 0xFF00, // PD SID
            command: 1,   // Discover Identity
            command_type: 0,
            object_position: 0,
            objects: vec![],
        };
        let h = vdm.vdm_header();
        assert_eq!(h >> 16, 0xFF00);
        assert_eq!(h & 0x1F, 1);
        assert_eq!((h >> 15) & 1, 1); // structured
    }
}
