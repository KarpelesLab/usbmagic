//! Flash Cynthion gateware to the ECP5 ourselves, over the **Apollo** USB
//! interface — no dependency on the Python `apollo`/`cynthion` tools.
//!
//! The Cynthion's Apollo stub enumerates as USB `1d50:615c`; while user gateware
//! is running the board instead appears as `1d50:615b` and carries an *Apollo
//! stub interface* (vendor class `0xff`, subclass `0x00`). Sending vendor request
//! `0xF0` to that interface hands the shared USB port to Apollo, which then
//! re-enumerates as `1d50:615c`, ready to be programmed.
//!
//! # Attribution
//!
//! The Apollo control protocol and ECP5 configuration sequence implemented here
//! are derived from Great Scott Gadgets' Apollo
//! (<https://github.com/greatscottgadgets/apollo>), BSD-3-Clause, Copyright (c)
//! 2020-2024 Great Scott Gadgets. See the project `LICENSE`.
//!
//! Status: the Apollo USB layer (detection, port handoff, identity/firmware,
//! reconfigure) is implemented and hardware-tested; the JTAG/ECP5 bitstream
//! playback ([`flash`]) is the next step.

use std::time::Duration;

use nusb::transfer::{ControlIn, ControlOut, ControlType, Recipient};
use nusb::MaybeFuture;

use crate::error::{Error, Result};

/// USB vendor ID shared by Cynthion/Apollo.
pub const VID: u16 = 0x1d50;
/// Apollo debug stub (board ready to be programmed).
pub const PID_APOLLO: u16 = 0x615c;
/// Running analyzer/host gateware (carries an Apollo stub interface).
pub const PID_GATEWARE: u16 = 0x615b;

/// Alternate Apollo VID/PID used by some builds (pid.codes).
const APOLLO_IDS: &[(u16, u16)] = &[(0x1d50, 0x615c), (0x1209, 0x0010)];

// Apollo vendor requests (recipient = device unless noted).
const REQUEST_GET_ID: u8 = 0xa0;
const REQUEST_GET_FIRMWARE_VERSION: u8 = 0xa2;
const REQUEST_GET_USB_API_VERSION: u8 = 0xa3;
const REQUEST_RECONFIGURE: u8 = 0xc0;
/// Sent to the *stub interface* (recipient = interface) to hand off the USB port.
const REQUEST_APOLLO_ADV_STOP: u8 = 0xF0;

const TIMEOUT: Duration = Duration::from_secs(1);
/// Apollo stub interface descriptor: vendor class, subclass 0.
const STUB_CLASS: u8 = 0xff;
const STUB_SUBCLASS: u8 = 0x00;

/// What the board is currently presenting on USB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoardMode {
    /// Apollo debug stub — ready to accept a bitstream.
    Apollo,
    /// User gateware is running — can be switched to Apollo before reprogramming.
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

fn is_apollo(vid: u16, pid: u16) -> bool {
    APOLLO_IDS.contains(&(vid, pid))
}

/// Detect whether a Cynthion is attached and in which mode.
pub fn detect() -> Result<BoardMode> {
    Ok(find()?.map(|d| d.mode).unwrap_or(BoardMode::NotFound))
}

/// Find the first attached Cynthion (Apollo mode preferred over running gateware).
pub fn find() -> Result<Option<ApolloDevice>> {
    let mut gateware: Option<ApolloDevice> = None;
    for info in nusb::list_devices().wait()? {
        let (vid, pid) = (info.vendor_id(), info.product_id());
        let mode = if is_apollo(vid, pid) {
            BoardMode::Apollo
        } else if vid == VID && pid == PID_GATEWARE {
            BoardMode::Gateware
        } else {
            continue;
        };
        let dev = ApolloDevice {
            mode,
            serial: info.serial_number().map(str::to_string),
            bus_id: info.bus_id().to_string(),
            address: info.device_address(),
        };
        match mode {
            BoardMode::Apollo => return Ok(Some(dev)),
            BoardMode::Gateware => gateware = gateware.or(Some(dev)),
            BoardMode::NotFound => {}
        }
    }
    Ok(gateware)
}

/// A live connection to an Apollo debugger.
pub struct Apollo {
    _device: nusb::Device,
    interface: nusb::Interface,
}

impl Apollo {
    /// Open Apollo, performing a USB-port handoff from running gateware if needed.
    ///
    /// If the board is already in Apollo mode it connects directly; if it is
    /// running gateware with an Apollo stub interface, it requests the handoff
    /// and waits for Apollo to re-enumerate.
    pub fn open() -> Result<Apollo> {
        if let Some(info) = find_apollo_info()? {
            return Apollo::from_info(&info);
        }

        // No Apollo yet — look for running gateware with a stub interface.
        let stub = find_stub_info()?.ok_or(Error::NoDevice)?;
        request_handoff(&stub)?;

        // Wait for Apollo to re-enumerate (up to ~5 s).
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(100));
            if let Some(info) = find_apollo_info()? {
                return Apollo::from_info(&info);
            }
        }
        Err(Error::Protocol(
            "requested Apollo handoff but Apollo did not re-enumerate".into(),
        ))
    }

    fn from_info(info: &nusb::DeviceInfo) -> Result<Apollo> {
        let device = info.open().wait()?;
        // Control transfers are issued through a claimed interface; Apollo's
        // debug interface is interface 0.
        let interface = device.claim_interface(0).wait()?;
        Ok(Apollo {
            _device: device,
            interface,
        })
    }

    fn read_string(&self, request: u8) -> Result<String> {
        let data = self
            .interface
            .control_in(
                ControlIn {
                    control_type: ControlType::Vendor,
                    recipient: Recipient::Device,
                    request,
                    value: 0,
                    index: 0,
                    length: 256,
                },
                TIMEOUT,
            )
            .wait()?;
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        Ok(String::from_utf8_lossy(&data[..end]).into_owned())
    }

    /// The Apollo identity string (contains "Apollo").
    pub fn id(&self) -> Result<String> {
        self.read_string(REQUEST_GET_ID)
    }

    /// The Apollo firmware version string.
    pub fn firmware_version(&self) -> Result<String> {
        self.read_string(REQUEST_GET_FIRMWARE_VERSION)
    }

    /// The Apollo USB API version as `(major, minor)`.
    pub fn usb_api_version(&self) -> Result<(u8, u8)> {
        let data = self
            .interface
            .control_in(
                ControlIn {
                    control_type: ControlType::Vendor,
                    recipient: Recipient::Device,
                    request: REQUEST_GET_USB_API_VERSION,
                    value: 0,
                    index: 0,
                    length: 2,
                },
                TIMEOUT,
            )
            .wait()?;
        if data.len() < 2 {
            return Err(Error::Protocol("short USB API version response".into()));
        }
        Ok((data[0], data[1]))
    }

    /// Trigger Apollo to reconfigure the FPGA from its SPI flash (restores the
    /// previously-flashed gateware, e.g. the analyzer).
    pub fn reconfigure(&self) -> Result<()> {
        self.interface
            .control_out(
                ControlOut {
                    control_type: ControlType::Vendor,
                    recipient: Recipient::Device,
                    request: REQUEST_RECONFIGURE,
                    value: 0,
                    index: 0,
                    data: &[],
                },
                TIMEOUT,
            )
            .wait()?;
        Ok(())
    }
}

fn find_apollo_info() -> Result<Option<nusb::DeviceInfo>> {
    Ok(nusb::list_devices()
        .wait()?
        .find(|i| is_apollo(i.vendor_id(), i.product_id())))
}

fn find_stub_info() -> Result<Option<nusb::DeviceInfo>> {
    Ok(nusb::list_devices().wait()?.find(|i| {
        i.vendor_id() == VID
            && i.product_id() == PID_GATEWARE
            && i.interfaces()
                .any(|f| f.class() == STUB_CLASS && f.subclass() == STUB_SUBCLASS)
    }))
}

/// Ask running gateware to release the shared USB port to Apollo.
fn request_handoff(info: &nusb::DeviceInfo) -> Result<()> {
    let stub_iface = info
        .interfaces()
        .find(|f| f.class() == STUB_CLASS && f.subclass() == STUB_SUBCLASS)
        .map(|f| f.interface_number())
        .ok_or(Error::Unsupported("no Apollo stub interface on device"))?;

    let device = info.open().wait()?;
    let interface = device.claim_interface(stub_iface).wait()?;
    // Recipient = interface; index carries the interface number. The device
    // disconnects and re-enumerates as Apollo, so a transfer error here is
    // expected and ignored.
    let _ = interface
        .control_out(
            ControlOut {
                control_type: ControlType::Vendor,
                recipient: Recipient::Interface,
                request: REQUEST_APOLLO_ADV_STOP,
                value: 0,
                index: u16::from(stub_iface),
                data: &[],
            },
            TIMEOUT,
        )
        .wait();
    Ok(())
}

/// Program `bitstream` to the board's ECP5 at `target`.
///
/// Switches the board to Apollo mode if needed. The JTAG/ECP5 bitstream playback
/// is not yet implemented; this validates inputs and the Apollo link so the
/// surrounding tooling is wired and testable today.
pub fn flash(bitstream: &[u8], target: FlashTarget) -> Result<()> {
    if bitstream.is_empty() {
        return Err(Error::Protocol("empty bitstream".into()));
    }
    let apollo = Apollo::open()?;
    let _ = (target, &apollo);
    Err(Error::Unsupported(
        "Apollo link is up, but ECP5 bitstream playback (JTAG) is not yet \
         implemented — that is the next step",
    ))
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
        let _ = detect();
    }
}
