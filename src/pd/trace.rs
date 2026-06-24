//! Bidirectional PD message trace: pretty-print every transmitted and received
//! message to the console, and optionally record it to a pcapng file under
//! [`LINKTYPE_USB_TYPE_C_PD`](crate::pcapng::LINKTYPE_USB_TYPE_C_PD).
//!
//! SPDX-License-Identifier: BSD-3-Clause

use std::io::Write;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::error::Result;
use crate::pcapng::{pd_pseudo_header, PcapNgWriter};
pub use crate::pcapng::{PdDirection, PdSop};
use crate::pd::{Pdo, PdMessage};

/// Human-readable PD message-type name (control / data / extended).
pub fn pd_message_name(msg: &PdMessage) -> &'static str {
    use crate::pd::PdMessageClass;
    let mt = msg.message_type().unwrap_or(0);
    match msg.class() {
        Some(PdMessageClass::Control) => match mt {
            1 => "GoodCRC",
            2 => "GotoMin",
            3 => "Accept",
            4 => "Reject",
            5 => "Ping",
            6 => "PS_RDY",
            7 => "Get_Source_Cap",
            8 => "Get_Sink_Cap",
            9 => "DR_Swap",
            10 => "PR_Swap",
            11 => "VCONN_Swap",
            12 => "Wait",
            13 => "Soft_Reset",
            _ => "Control(?)",
        },
        Some(PdMessageClass::Data) => match mt {
            1 => "Source_Capabilities",
            2 => "Request",
            3 => "BIST",
            4 => "Sink_Capabilities",
            5 => "Battery_Status",
            6 => "Alert",
            15 => "Vendor_Defined",
            _ => "Data(?)",
        },
        Some(PdMessageClass::Extended) => "Extended",
        None => "(empty)",
    }
}

/// Format one PD message as a console line (plus PDO breakdown for
/// Source_Capabilities), tagged with direction and a running index/timestamp.
pub fn format_pd_message(index: u32, ts: f64, dir: PdDirection, msg: &PdMessage) -> String {
    let arrow = match dir {
        PdDirection::FromDut => "RX <-",
        PdDirection::ToDut => "TX ->",
    };
    let hex: String = msg.raw.iter().map(|b| format!("{b:02x}")).collect();
    let name = pd_message_name(msg);
    let mut s = format!(
        "#{index:<3} [{ts:7.3}s] {arrow} {name:<20} hdr={:#06x} obj={} raw={hex}",
        msg.header().unwrap_or(0),
        msg.num_data_objects().unwrap_or(0),
    );
    if name == "Source_Capabilities" {
        for (i, o) in msg.objects().iter().enumerate() {
            let pdo = Pdo { raw: *o };
            if let (Some(mv), Some(ma)) = (pdo.fixed_voltage_mv(), pdo.fixed_max_current_ma()) {
                s.push_str(&format!(
                    "\n       PDO{}: {:.2} V @ {:.2} A (fixed)",
                    i + 1,
                    mv as f64 / 1000.0,
                    ma as f64 / 1000.0
                ));
            } else if let Some((min_mv, max_mv, max_ma)) = pdo.pps() {
                s.push_str(&format!(
                    "\n       PDO{}: {:.2}–{:.2} V @ {:.2} A (PPS)",
                    i + 1,
                    min_mv as f64 / 1000.0,
                    max_mv as f64 / 1000.0,
                    max_ma as f64 / 1000.0
                ));
            } else {
                s.push_str(&format!("\n       PDO{}: {o:#010x}", i + 1));
            }
        }
    }
    s
}

/// Records PD messages to the console and (optionally) a pcapng file.
///
/// Interface ids map to ports by convention (interface 0 = TARGET-C, 1 = AUX);
/// the caller passes the id matching the IDB order it created the writer with.
pub struct PdTrace {
    writer: Option<PcapNgWriter<Box<dyn Write>>>,
    start: Instant,
    base_unix_us: u64,
    count: u32,
}

impl PdTrace {
    /// Create a trace. `writer` is the pcapng sink (already initialized with the
    /// interface table), or `None` for console-only.
    pub fn new(writer: Option<PcapNgWriter<Box<dyn Write>>>) -> Self {
        let base_unix_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(0);
        PdTrace {
            writer,
            start: Instant::now(),
            base_unix_us,
            count: 0,
        }
    }

    /// Number of messages recorded so far.
    pub fn count(&self) -> u32 {
        self.count
    }

    /// Record one message: print it and, if a pcapng writer is attached, append a
    /// packet (pseudo-header + message bytes) on `iface_id`.
    pub fn record(
        &mut self,
        iface_id: u32,
        dir: PdDirection,
        sop: PdSop,
        cc: u8,
        crc: Option<u32>,
        msg: &PdMessage,
    ) -> Result<()> {
        self.count += 1;
        let elapsed = self.start.elapsed();
        println!(
            "{}",
            format_pd_message(self.count, elapsed.as_secs_f64(), dir, msg)
        );
        if let Some(w) = &mut self.writer {
            let unix_us = self.base_unix_us + elapsed.as_micros() as u64;
            let mut data = pd_pseudo_header(sop, dir, cc, crc).to_vec();
            data.extend_from_slice(&msg.raw);
            w.write_packet(iface_id, unix_us, &data)?;
        }
        Ok(())
    }

    /// Flush the pcapng writer, if any.
    pub fn flush(&mut self) -> Result<()> {
        if let Some(w) = &mut self.writer {
            w.flush()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_format() {
        // Source_Capabilities with one 5V/3A fixed PDO.
        let header = 0x0001 | (1 << 12);
        let pdo = (100u32 << 10) | 300;
        let msg = PdMessage::from_objects(header, &[pdo]);
        assert_eq!(pd_message_name(&msg), "Source_Capabilities");
        let line = format_pd_message(1, 0.5, PdDirection::FromDut, &msg);
        assert!(line.contains("RX <-"));
        assert!(line.contains("Source_Capabilities"));
        assert!(line.contains("5.00 V @ 3.00 A (fixed)"));

        let good = PdMessage::from_objects(0x0001, &[]);
        assert_eq!(pd_message_name(&good), "GoodCRC");
        assert!(format_pd_message(2, 0.0, PdDirection::ToDut, &good).contains("TX ->"));
    }
}
