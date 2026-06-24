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

/// JTAG IDCODE of the Cynthion's ECP5 (LFE5U-12F).
pub const ECP5_12F_IDCODE: u32 = 0x2111_1043;

/// Apollo's JTAG-over-USB vendor requests and TAP state numbers.
/// (Ported from Great Scott Gadgets' Apollo `jtag.py`.)
#[allow(dead_code)] // some requests are used by the upcoming configure() path
mod jtag {
    pub const REQUEST_JTAG_START: u8 = 0xbf;
    pub const REQUEST_JTAG_STOP: u8 = 0xbe;
    pub const REQUEST_JTAG_CLEAR_OUT_BUFFER: u8 = 0xb0;
    pub const REQUEST_JTAG_SET_OUT_BUFFER: u8 = 0xb1;
    pub const REQUEST_JTAG_GET_IN_BUFFER: u8 = 0xb2;
    pub const REQUEST_JTAG_SCAN: u8 = 0xb3;
    pub const REQUEST_JTAG_RUN_CLOCK: u8 = 0xb4;
    pub const REQUEST_JTAG_GO_TO_STATE: u8 = 0xb5;
    pub const REQUEST_JTAG_GET_INFO: u8 = 0xb8;

    // TAP FSM state numbers (subset).
    pub const STATE_RESET: u16 = 0;
    pub const STATE_IDLE: u16 = 1;
    pub const STATE_DRSHIFT: u16 = 4;
    pub const STATE_DRPAUSE: u16 = 6;
    pub const STATE_IRSHIFT: u16 = 11;
    pub const STATE_IRPAUSE: u16 = 13;
}

/// ECP5 configuration opcodes and status flags (from Lattice TN1260 / GSG Apollo).
#[allow(dead_code)]
mod ecp5 {
    pub const READ_ID: u8 = 0xE0;
    pub const LSC_READ_STATUS: u8 = 0x3C;
    pub const LSC_REFRESH: u8 = 0x79;
    pub const ISC_ENABLE: u8 = 0xC6;
    pub const ISC_ERASE: u8 = 0x0E;
    pub const ISC_DISABLE: u8 = 0x26;
    pub const LSC_INIT_ADDRESS: u8 = 0x46; // "set working address"
    pub const LSC_BITSTREAM_BURST: u8 = 0x7A;
    pub const NO_OP: u8 = 0xFF;
    pub const MAGIC_1C: u8 = 0x1C; // pre-configuration command used by Apollo

    pub const STATUS_DONE: u32 = 1 << 8;
    pub const STATUS_BUSY: u32 = 1 << 12;
    pub const STATUS_FAIL: u32 = 1 << 13;
}

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
        // If no Apollo is present, ask running gateware to hand off the USB port.
        if find_apollo_info()?.is_none() {
            let stub = find_stub_info()?.ok_or(Error::NoDevice)?;
            request_handoff(&stub)?;
        }

        // Wait for Apollo, retrying the open: right after (re-)enumeration the
        // device node can briefly be inaccessible until udev applies group
        // permissions, which surfaces as a transient permission error.
        let mut last_err = None;
        for _ in 0..60 {
            if let Some(info) = find_apollo_info()? {
                match Apollo::from_info(&info) {
                    Ok(apollo) => return Ok(apollo),
                    Err(e) => last_err = Some(e),
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(last_err.unwrap_or_else(|| {
            Error::Protocol("Apollo did not become available after handoff".into())
        }))
    }

    fn from_info(info: &nusb::DeviceInfo) -> Result<Apollo> {
        let device = info.open().wait()?;
        // EP0 device-recipient control transfers work through any claimed
        // interface, but Apollo's interfaces 0/1 are CDC-ACM and held by the
        // kernel `cdc_acm` driver. Claim a non-CDC interface (the DFU/vendor one)
        // to avoid an "interface busy" error.
        let iface_num = info
            .interfaces()
            .map(|f| (f.interface_number(), f.class()))
            .filter(|(_, class)| !matches!(class, 0x02 | 0x0a))
            .map(|(n, _)| n)
            .min()
            .unwrap_or(0);
        let interface = device.claim_interface(iface_num).wait()?;
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

    /// Low-level Apollo vendor OUT request (recipient = device).
    fn out_req(&self, request: u8, value: u16, index: u16, data: &[u8]) -> Result<()> {
        self.interface
            .control_out(
                ControlOut {
                    control_type: ControlType::Vendor,
                    recipient: Recipient::Device,
                    request,
                    value,
                    index,
                    data,
                },
                TIMEOUT,
            )
            .wait()?;
        Ok(())
    }

    /// Low-level Apollo vendor IN request (recipient = device).
    fn in_req(&self, request: u8, value: u16, index: u16, length: u16) -> Result<Vec<u8>> {
        Ok(self
            .interface
            .control_in(
                ControlIn {
                    control_type: ControlType::Vendor,
                    recipient: Recipient::Device,
                    request,
                    value,
                    index,
                    length,
                },
                TIMEOUT,
            )
            .wait()?)
    }

    /// Read the JTAG IDCODE of the attached FPGA.
    ///
    /// Resets the TAP (which loads the IDCODE instruction), scans 32 DR bits, and
    /// returns them. For the Cynthion's ECP5 LFE5U-12F this is [`ECP5_12F_IDCODE`].
    /// Drives JTAG over Apollo's vendor-request protocol (ported from GSG Apollo).
    pub fn read_idcode(&self) -> Result<u32> {
        self.out_req(jtag::REQUEST_JTAG_START, 0, 0, &[])?;
        // Force the TAP to RESET (loads IDCODE), then into DRSHIFT.
        self.out_req(jtag::REQUEST_JTAG_GO_TO_STATE, jtag::STATE_RESET, 0, &[])?;
        self.out_req(jtag::REQUEST_JTAG_GO_TO_STATE, jtag::STATE_DRSHIFT, 0, &[])?;
        self.out_req(jtag::REQUEST_JTAG_CLEAR_OUT_BUFFER, 0, 0, &[])?;
        // Scan 32 bits (no state advance), then read the 4 captured bytes.
        self.out_req(jtag::REQUEST_JTAG_SCAN, 32, 0, &[])?;
        let buf = self.in_req(jtag::REQUEST_JTAG_GET_IN_BUFFER, 0, 0, 4)?;
        self.out_req(jtag::REQUEST_JTAG_STOP, 0, 0, &[])?;
        if buf.len() < 4 {
            return Err(Error::Protocol("short JTAG IDCODE response".into()));
        }
        // Bits are captured LSB-first into the buffer -> little-endian value.
        Ok(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
    }

    // --- JTAG primitives (over Apollo vendor requests) ---

    fn jtag_go(&self, state: u16) -> Result<()> {
        self.out_req(jtag::REQUEST_JTAG_GO_TO_STATE, state, 0, &[])
    }

    /// RUNTEST: idle for `cycles` TCK cycles.
    fn jtag_run_test(&self, cycles: u16) -> Result<()> {
        self.jtag_go(jtag::STATE_IDLE)?;
        self.out_req(jtag::REQUEST_JTAG_RUN_CLOCK, cycles, 0, &[])
    }

    /// Max bytes per scan the firmware accepts (default 256 if it doesn't report).
    fn jtag_max_bytes(&self) -> usize {
        match self.in_req(jtag::REQUEST_JTAG_GET_INFO, 0, 0, 8) {
            Ok(d) if d.len() >= 4 => match u32::from_le_bytes([d[0], d[1], d[2], d[3]]) as usize {
                0 => 256,
                m => m,
            },
            _ => 256,
        }
    }

    /// Shift an 8-bit instruction into IR, ending in IRPAUSE.
    fn jtag_shift_ir(&self, opcode: u8) -> Result<()> {
        self.jtag_go(jtag::STATE_IRSHIFT)?;
        self.out_req(jtag::REQUEST_JTAG_SET_OUT_BUFFER, 0, 0, &[opcode])?;
        self.out_req(jtag::REQUEST_JTAG_SCAN, 8, 1, &[])?; // advance on last bit
        self.jtag_go(jtag::STATE_IRPAUSE)
    }

    /// Read `nbits` from DR (ending in DRPAUSE).
    fn jtag_shift_dr_read(&self, nbits: u16) -> Result<Vec<u8>> {
        self.jtag_go(jtag::STATE_DRSHIFT)?;
        self.out_req(jtag::REQUEST_JTAG_CLEAR_OUT_BUFFER, 0, 0, &[])?;
        self.out_req(jtag::REQUEST_JTAG_SCAN, nbits, 0, &[])?;
        let buf = self.in_req(jtag::REQUEST_JTAG_GET_IN_BUFFER, 0, 0, nbits.div_ceil(8))?;
        self.jtag_go(jtag::STATE_DRPAUSE)?;
        Ok(buf)
    }

    /// Write `nbits` of `data` into DR (ending in DRPAUSE).
    ///
    /// Matches Apollo's wire format: the byte array is reversed, then each byte is
    /// shifted LSB-first by the firmware. Chunked to the firmware's buffer size;
    /// write responses are discarded.
    fn jtag_shift_dr_write(&self, data: &[u8], nbits: u32, max_bytes: usize) -> Result<()> {
        self.jtag_go(jtag::STATE_DRSHIFT)?;
        let wire: Vec<u8> = data.iter().rev().copied().collect();
        let mut sent_bits: u32 = 0;
        let mut off = 0usize;
        while off < wire.len() {
            let end = (off + max_bytes).min(wire.len());
            let chunk = &wire[off..end];
            off = end;
            let last = off >= wire.len();
            let chunk_bits = ((chunk.len() as u32) * 8).min(nbits - sent_bits);
            sent_bits += chunk_bits;
            self.out_req(jtag::REQUEST_JTAG_SET_OUT_BUFFER, 0, 0, chunk)?;
            self.out_req(
                jtag::REQUEST_JTAG_SCAN,
                chunk_bits as u16,
                if last { 1 } else { 0 },
                &[],
            )?;
        }
        self.jtag_go(jtag::STATE_DRPAUSE)
    }

    /// Issue an ECP5 command with an optional DR data payload.
    fn ecp5_cmd_write(&self, opcode: u8, data: &[u8], nbits: u32, max_bytes: usize) -> Result<()> {
        self.jtag_shift_ir(opcode)?;
        if nbits > 0 {
            self.jtag_shift_dr_write(data, nbits, max_bytes)?;
        }
        Ok(())
    }

    /// Issue an ECP5 command and read a 32-bit DR response.
    fn ecp5_cmd_read32(&self, opcode: u8) -> Result<u32> {
        self.jtag_shift_ir(opcode)?;
        let buf = self.jtag_shift_dr_read(32)?;
        if buf.len() < 4 {
            return Err(Error::Protocol("short ECP5 response".into()));
        }
        Ok(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
    }

    fn ecp5_status(&self) -> Result<u32> {
        self.ecp5_cmd_read32(ecp5::LSC_READ_STATUS)
    }

    fn ecp5_wait_not_busy(&self) -> Result<u32> {
        for _ in 0..200 {
            let status = self.ecp5_status()?;
            if status & ecp5::STATUS_BUSY == 0 {
                return Ok(status);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Err(Error::Protocol("ECP5 stayed busy".into()))
    }

    /// Configure the ECP5's SRAM with `bitstream` over JTAG (volatile; lost on
    /// power cycle). Returns the final status register. Ported from GSG Apollo's
    /// `ECP5_JTAGProgrammer.configure`.
    pub fn configure_sram(&self, bitstream: &[u8]) -> Result<u32> {
        // Apollo: reverse the bits in each byte, then reverse the byte order; the
        // DR-write reverses the byte order again, netting original-order bytes
        // shifted MSB-first.
        let mut payload: Vec<u8> = bitstream.iter().map(|b| b.reverse_bits()).collect();
        payload.reverse();

        let max_bytes = self.jtag_max_bytes().max(8);

        self.out_req(jtag::REQUEST_JTAG_START, 0, 0, &[])?;
        self.jtag_go(jtag::STATE_RESET)?;

        // Restart configuration (clear SRAM).
        self.ecp5_cmd_write(ecp5::LSC_REFRESH, &[], 0, max_bytes)?;
        self.ecp5_wait_not_busy().ok();
        std::thread::sleep(Duration::from_millis(50));

        // Verify a plausible part is present.
        let id = self.ecp5_cmd_read32(ecp5::READ_ID)?;
        if id == 0 || id == 0xFFFF_FFFF {
            self.out_req(jtag::REQUEST_JTAG_STOP, 0, 0, &[])?;
            return Err(Error::Protocol(format!("no FPGA detected (id {id:#010x})")));
        }

        // Apollo's pre-configuration command (0x1C with 510 bits of 0x3f,0xff…).
        let mut magic = vec![0x3fu8];
        magic.extend(std::iter::repeat(0xffu8).take(63));
        self.ecp5_cmd_write(ecp5::MAGIC_1C, &magic, 510, max_bytes)?;

        // Enable configuration.
        self.ecp5_cmd_write(ecp5::ISC_ENABLE, &[0x00], 8, max_bytes)?;
        self.jtag_run_test(2)?;

        // Erase SRAM.
        self.ecp5_cmd_write(ecp5::ISC_ERASE, &[0x01], 8, max_bytes)?;
        self.ecp5_wait_not_busy().ok();
        self.jtag_run_test(2)?;

        // Set working address, then burst the bitstream.
        self.ecp5_cmd_write(ecp5::LSC_INIT_ADDRESS, &[0x01], 8, max_bytes)?;
        let nbits = (payload.len() as u32) * 8;
        self.ecp5_cmd_write(ecp5::LSC_BITSTREAM_BURST, &payload, nbits, max_bytes)?;

        // Allow configuration to take.
        self.jtag_shift_ir(ecp5::NO_OP)?;
        self.jtag_run_test(100)?;

        let status_after_burst = self.ecp5_status()?;

        // Disable configuration; the FPGA starts running.
        self.ecp5_cmd_write(ecp5::ISC_DISABLE, &[], 0, max_bytes)?;
        self.jtag_run_test(2)?;

        let final_status = self.ecp5_status().unwrap_or(status_after_burst);
        self.out_req(jtag::REQUEST_JTAG_STOP, 0, 0, &[])?;

        if final_status & ecp5::STATUS_FAIL != 0 {
            return Err(Error::Protocol(format!(
                "configuration failed (status {final_status:#010x})"
            )));
        }
        Ok(final_status)
    }

    // --- Meta-JTAG register access (LUNA JTAGRegisterInterface) ---
    //
    // Gateware built with LUNA's JTAGRegisterInterface exposes a CSR bank over
    // two ECP5 user-JTAG registers: IR 0x32 selects the address/instruction
    // register, IR 0x38 the data register. Ported from GSG Apollo
    // (ECP5_JTAGRegisters).

    /// Shift `nbits` of big-endian `data` through DR and return the read-back
    /// bytes (little-endian value order), ending in DRPAUSE.
    fn jtag_dr_xfer(&self, be_data: &[u8], nbits: u16) -> Result<Vec<u8>> {
        self.jtag_go(jtag::STATE_DRSHIFT)?;
        let wire: Vec<u8> = be_data.iter().rev().copied().collect();
        self.out_req(jtag::REQUEST_JTAG_SET_OUT_BUFFER, 0, 0, &wire)?;
        self.out_req(jtag::REQUEST_JTAG_SCAN, nbits, 1, &[])?; // advance on last bit
        let buf = self.in_req(jtag::REQUEST_JTAG_GET_IN_BUFFER, 0, 0, nbits.div_ceil(8))?;
        self.jtag_go(jtag::STATE_DRPAUSE)?;
        Ok(buf)
    }

    /// Auto-detect a meta-register width by shifting 128 bits and counting the
    /// leading 1s the gateware pre-loads.
    fn jtag_meta_width(&self, opcode: u8) -> Result<usize> {
        self.jtag_shift_ir(opcode)?;
        self.jtag_go(jtag::STATE_DRSHIFT)?;
        self.out_req(jtag::REQUEST_JTAG_CLEAR_OUT_BUFFER, 0, 0, &[])?;
        self.out_req(jtag::REQUEST_JTAG_SCAN, 128, 0, &[])?; // read-only, no advance
        let buf = self.in_req(jtag::REQUEST_JTAG_GET_IN_BUFFER, 0, 0, 16)?;
        self.jtag_go(jtag::STATE_DRPAUSE)?;
        let mut count = 0usize;
        'outer: for &byte in &buf {
            for bit in (0..8).rev() {
                if (byte >> bit) & 1 == 1 {
                    count += 1;
                } else {
                    break 'outer;
                }
            }
        }
        Ok(count)
    }

    fn meta_txn(
        &self,
        addr: u8,
        is_write: bool,
        value: u32,
        iw: usize,
        dw: usize,
    ) -> Result<u32> {
        let iw_bytes = iw.div_ceil(8);
        let dw_bytes = dw.div_ceil(8);
        if iw == 0 || dw == 0 || iw > 32 || dw > 32 {
            return Err(Error::Protocol(format!(
                "implausible register widths (instr {iw}, data {dw})"
            )));
        }
        let write_flag = if is_write { 1u32 << (iw - 1) } else { 0 };
        let cmd = write_flag | u32::from(addr);

        // Select + write the address/instruction register.
        self.jtag_shift_ir(0x32)?;
        self.jtag_dr_xfer(&cmd.to_be_bytes()[4 - iw_bytes..], iw as u16)?;
        self.jtag_run_test(32)?;

        // Select the data register; write value / read result.
        self.jtag_shift_ir(0x38)?;
        let buf = self.jtag_dr_xfer(&value.to_be_bytes()[4 - dw_bytes..], dw as u16)?;
        self.jtag_run_test(32)?;

        let mut v = 0u32;
        for (i, b) in buf.iter().take(dw_bytes).enumerate() {
            v |= u32::from(*b) << (8 * i);
        }
        Ok(v)
    }

    /// Open a JTAG meta-register session (auto-detecting widths) and run `f`.
    fn with_registers<T>(&self, f: impl FnOnce(&Self, usize, usize) -> Result<T>) -> Result<T> {
        self.out_req(jtag::REQUEST_JTAG_START, 0, 0, &[])?;
        self.jtag_go(jtag::STATE_RESET)?;
        // Read data width before instruction width (scanning the instruction
        // register latches the data register).
        let dw = self.jtag_meta_width(0x38)?;
        let iw = self.jtag_meta_width(0x32)?;
        let r = f(self, iw, dw);
        let _ = self.out_req(jtag::REQUEST_JTAG_STOP, 0, 0, &[]);
        r
    }

    /// Read a gateware CSR register (auto-detects widths each call).
    pub fn register_read(&self, addr: u8) -> Result<u32> {
        self.with_registers(|a, iw, dw| a.meta_txn(addr, false, 0, iw, dw))
    }

    /// Write a gateware CSR register.
    pub fn register_write(&self, addr: u8, value: u32) -> Result<()> {
        self.with_registers(|a, iw, dw| a.meta_txn(addr, true, value, iw, dw).map(|_| ()))
    }

    /// Auto-detected (instruction_width, data_width) of the gateware register bank.
    pub fn register_widths(&self) -> Result<(usize, usize)> {
        self.with_registers(|_, iw, dw| Ok((iw, dw)))
    }

    /// Read a register from an I2C device behind the pd_bridge gateware
    /// (bit-banged over the GPIO registers, whole transaction in one JTAG session).
    pub fn fusb302_read_register(&self, dev_addr: u8, reg: u8) -> Result<u8> {
        self.with_registers(|a, iw, dw| {
            let mut bus = I2cBus::new(a, iw, dw);
            bus.read_reg(dev_addr, reg)
        })
    }

    /// Write a register to an I2C device behind the pd_bridge gateware.
    pub fn fusb302_write_register(&self, dev_addr: u8, reg: u8, value: u8) -> Result<()> {
        self.with_registers(|a, iw, dw| {
            let mut bus = I2cBus::new(a, iw, dw);
            bus.write_reg(dev_addr, reg, value)
        })
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

// pd_bridge gateware register map.
const REG_GPIO_OUT: u8 = 2; // bit0 = SCL level, bit1 = SDA drive-low
const REG_GPIO_IN: u8 = 3; // bit0 = SDA line, bit1 = FUSB302B INT#

/// Bit-banged I2C master over the pd_bridge GPIO registers. Lives inside a single
/// [`Apollo::with_registers`] session so every SCL/SDA edge reuses one JTAG
/// connection. USB latency between edges is the (very slow, but valid) I2C clock.
struct I2cBus<'a> {
    a: &'a Apollo,
    iw: usize,
    dw: usize,
    out: u32,
}

impl<'a> I2cBus<'a> {
    const SCL: u32 = 0b01;
    const SDA_LOW: u32 = 0b10;

    fn new(a: &'a Apollo, iw: usize, dw: usize) -> Self {
        // Idle: SCL high, SDA released.
        I2cBus {
            a,
            iw,
            dw,
            out: Self::SCL,
        }
    }

    fn apply(&self) -> Result<()> {
        self.a
            .meta_txn(REG_GPIO_OUT, true, self.out, self.iw, self.dw)
            .map(|_| ())
    }

    fn scl(&mut self, high: bool) -> Result<()> {
        if high {
            self.out |= Self::SCL;
        } else {
            self.out &= !Self::SCL;
        }
        self.apply()
    }

    /// `release` true = let SDA float high (external pull-up); false = drive it low.
    fn sda(&mut self, release: bool) -> Result<()> {
        if release {
            self.out &= !Self::SDA_LOW;
        } else {
            self.out |= Self::SDA_LOW;
        }
        self.apply()
    }

    fn read_sda(&self) -> Result<bool> {
        Ok(self.a.meta_txn(REG_GPIO_IN, false, 0, self.iw, self.dw)? & 1 == 1)
    }

    fn start(&mut self) -> Result<()> {
        self.sda(true)?;
        self.scl(true)?;
        self.sda(false)?; // SDA falls while SCL high
        self.scl(false)?;
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.sda(false)?;
        self.scl(true)?;
        self.sda(true)?; // SDA rises while SCL high
        Ok(())
    }

    /// Clock out one bit (SDA = `bit`, where releasing high represents a 1).
    fn write_bit(&mut self, bit: bool) -> Result<()> {
        self.sda(bit)?;
        self.scl(true)?;
        self.scl(false)?;
        Ok(())
    }

    fn read_bit(&mut self) -> Result<bool> {
        self.sda(true)?; // release so the slave can drive
        self.scl(true)?;
        let bit = self.read_sda()?;
        self.scl(false)?;
        Ok(bit)
    }

    /// Write a byte MSB-first; returns true if the slave ACKed.
    fn write_byte(&mut self, byte: u8) -> Result<bool> {
        for i in (0..8).rev() {
            self.write_bit((byte >> i) & 1 == 1)?;
        }
        let nack = self.read_bit()?; // ACK = slave pulls SDA low
        Ok(!nack)
    }

    /// Read a byte MSB-first, then ACK (continue) or NACK (last byte).
    fn read_byte(&mut self, ack: bool) -> Result<u8> {
        let mut v = 0u8;
        for _ in 0..8 {
            v = (v << 1) | u8::from(self.read_bit()?);
        }
        self.write_bit(!ack)?; // ACK = drive low (bit 0); NACK = release (bit 1)
        Ok(v)
    }

    fn read_reg(&mut self, dev_addr: u8, reg: u8) -> Result<u8> {
        self.start()?;
        if !self.write_byte(dev_addr << 1)? {
            // (address << 1) | 0 — R/W bit 0 = write
            self.stop()?;
            return Err(Error::Protocol(format!(
                "I2C: no ACK from device {dev_addr:#04x} (write)"
            )));
        }
        if !self.write_byte(reg)? {
            self.stop()?;
            return Err(Error::Protocol(format!("I2C: no ACK for register {reg:#04x}")));
        }
        self.start()?; // repeated start
        if !self.write_byte((dev_addr << 1) | 1)? {
            self.stop()?;
            return Err(Error::Protocol(format!(
                "I2C: no ACK from device {dev_addr:#04x} (read)"
            )));
        }
        let value = self.read_byte(false)?; // single byte -> NACK
        self.stop()?;
        Ok(value)
    }

    fn write_reg(&mut self, dev_addr: u8, reg: u8, value: u8) -> Result<()> {
        self.start()?;
        let ok =
            self.write_byte(dev_addr << 1)? && self.write_byte(reg)? && self.write_byte(value)?;
        self.stop()?;
        if ok {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "I2C write to {dev_addr:#04x} reg {reg:#04x} was not ACKed"
            )))
        }
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
    match target {
        FlashTarget::Sram => {
            let status = apollo.configure_sram(bitstream)?;
            if status & ecp5::STATUS_DONE == 0 {
                return Err(Error::Protocol(format!(
                    "bitstream loaded but DONE not set (status {status:#010x})"
                )));
            }
            Ok(())
        }
        FlashTarget::Flash => Err(Error::Unsupported(
            "persistent SPI-flash programming not yet implemented (SRAM works)",
        )),
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
        let _ = detect();
    }
}
