//! Flash Cynthion gateware to the ECP5 ourselves, over the **Apollo** USB
//! interface — no dependency on the Python `apollo`/`cynthion` tools.
//!
//! The Cynthion's Apollo stub enumerates as USB `1d50:615c`; while user gateware
//! is running the board instead appears as `1d50:615b`. Programming the ECP5 is
//! done by driving its JTAG/configuration engine through Apollo vendor requests
//! (SRAM = volatile, fast; SPI flash = persistent).
//!
//! Status: device/mode **detection is implemented**; the JTAG configuration
//! playback (a port of `apollo_fpga`'s protocol) is the next focused step — see
//! [`flash`]. This module is the stable entry point the CLI (`usbmagic flash`)
//! and library use.

use nusb::MaybeFuture;

use crate::error::{Error, Result};

/// USB vendor ID shared by Cynthion/Apollo.
pub const VID: u16 = 0x1d50;
/// Apollo debug stub (board ready to be programmed).
pub const PID_APOLLO: u16 = 0x615c;
/// Running analyzer/host gateware (must be switched to Apollo to reprogram).
pub const PID_GATEWARE: u16 = 0x615b;

/// What the board is currently presenting on USB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoardMode {
    /// Apollo debug stub — ready to accept a bitstream.
    Apollo,
    /// User gateware is running — must be switched to Apollo before reprogramming.
    Gateware,
    /// No Cynthion found.
    NotFound,
}

/// Where to program the bitstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashTarget {
    /// Volatile FPGA SRAM configuration — lost on power cycle. Fast dev loop.
    Sram,
    /// Persistent SPI configuration flash — survives power cycles.
    Flash,
}

/// A discovered board and the address that identifies it.
#[derive(Debug, Clone)]
pub struct ApolloDevice {
    pub mode: BoardMode,
    pub serial: Option<String>,
    pub bus_id: String,
    pub address: u8,
}

/// Detect whether a Cynthion is attached and in which mode.
pub fn detect() -> Result<BoardMode> {
    Ok(find()?.map(|d| d.mode).unwrap_or(BoardMode::NotFound))
}

/// Find the first attached Cynthion (Apollo mode preferred over running gateware).
pub fn find() -> Result<Option<ApolloDevice>> {
    let mut gateware: Option<ApolloDevice> = None;
    for info in nusb::list_devices().wait()? {
        if info.vendor_id() != VID {
            continue;
        }
        let mode = match info.product_id() {
            PID_APOLLO => BoardMode::Apollo,
            PID_GATEWARE => BoardMode::Gateware,
            _ => continue,
        };
        let dev = ApolloDevice {
            mode,
            serial: info.serial_number().map(str::to_string),
            bus_id: info.bus_id().to_string(),
            address: info.device_address(),
        };
        match mode {
            // An Apollo-mode board is immediately usable — return it.
            BoardMode::Apollo => return Ok(Some(dev)),
            // Remember a running-gateware board but keep looking for Apollo.
            BoardMode::Gateware => gateware = gateware.or(Some(dev)),
            BoardMode::NotFound => {}
        }
    }
    Ok(gateware)
}

/// Program `bitstream` to the board's ECP5 at `target`.
///
/// Requires the board to be in Apollo mode. The bitstream-playback protocol is
/// not yet implemented; this validates inputs and board state so the surrounding
/// tooling (CLI, vendoring) is wired and testable today.
pub fn flash(bitstream: &[u8], target: FlashTarget) -> Result<()> {
    if bitstream.is_empty() {
        return Err(Error::Protocol("empty bitstream".into()));
    }
    match detect()? {
        BoardMode::NotFound => Err(Error::NoDevice),
        BoardMode::Gateware => Err(Error::Unsupported(
            "board is running gateware; switch it to Apollo mode before flashing \
             (request-via-gateware / press PROGRAM) — auto-switch not yet implemented",
        )),
        BoardMode::Apollo => {
            let _ = target;
            Err(Error::Unsupported(
                "Apollo bitstream programming not yet implemented (porting the \
                 apollo_fpga JTAG/configuration protocol is the next step)",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bitstream_rejected() {
        assert!(matches!(flash(&[], FlashTarget::Sram), Err(Error::Protocol(_))));
    }

    #[test]
    fn detect_runs() {
        // Just exercises enumeration; result depends on what's attached.
        let _ = detect();
    }
}
