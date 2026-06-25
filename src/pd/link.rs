//! High-level USB **Power Delivery link** — the consumer-facing way to talk PD
//! through one Cynthion Type-C port (a FUSB302B behind the `pd_bridge` gateware).
//!
//! [`PdLink`] wraps an [`Apollo`] and a port and exposes the whole conversation:
//! present as source/sink, bring up VBUS, run a spec-timed source negotiation,
//! send raw messages or structured VDMs, and receive replies — optionally
//! recording everything to a [`PdTrace`].
//!
//! ```no_run
//! use usbmagic::flash::Apollo;
//! use usbmagic::{PdLink, PdPort, Vdm, VbusSource};
//!
//! let apollo = Apollo::open()?;                  // gateware must be pd_bridge
//! let mut pd = PdLink::new(apollo, PdPort::TargetC);
//! pd.bring_up_vbus(VbusSource::Auto)?;           // 5 V for the device
//! pd.setup_source()?;                            // present Rp, detect the sink
//! if let Some(req) = pd.negotiate_source(&[(100 << 10) | 150])? {
//!     println!("sink requested: {:#06x}", req.header().unwrap_or(0));
//!     let vdm = Vdm { svid: 0x05ac, command: 1, command_type: 0,
//!                     object_position: 0, objects: vec![] };
//!     pd.send_vdm(&vdm, None)?;                   // any VDM you like
//!     while let Some(msg) = pd.recv(std::time::Duration::from_secs(2))? {
//!         println!("reply: {:#06x}", msg.header().unwrap_or(0));
//!     }
//! }
//! # Ok::<(), usbmagic::Error>(())
//! ```
//!
//! SPDX-License-Identifier: BSD-3-Clause

use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::flash::{vbus, Apollo, PdLine};
use crate::pcapng::{PdDirection, PdSop};
use crate::pd::trace::PdTrace;
use crate::pd::{PdMessage, PdMessageClass, PdPort, Vdm};

impl From<PdPort> for PdLine {
    fn from(p: PdPort) -> PdLine {
        match p {
            PdPort::TargetC => PdLine::TargetC,
            PdPort::Aux => PdLine::Aux,
        }
    }
}
impl From<PdLine> for PdPort {
    fn from(l: PdLine) -> PdPort {
        match l {
            PdLine::TargetC => PdPort::TargetC,
            PdLine::Aux => PdPort::Aux,
        }
    }
}

/// Where to source VBUS for a device on TARGET-C.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VbusSource {
    /// AUX supply if one is present, else CONTROL/host 5 V.
    Auto,
    /// Only route the AUX supply.
    Aux,
    /// Only route CONTROL / host 5 V.
    Control,
    /// Don't touch VBUS.
    None,
}

/// pcapng interface id for a port (interface 0 = TARGET-C, 1 = AUX).
fn iface_id(port: PdLine) -> u32 {
    match port {
        PdLine::TargetC => 0,
        PdLine::Aux => 1,
    }
}

/// 16-bit PD message header for a message we originate as a source/DFP, Spec
/// Rev 3.0 (power-role=source bit8, data-role=DFP bit5, SpecRev=10 bits6-7).
fn source_header(msg_type: u16, ndo: u16, msg_id: u16) -> u16 {
    0x01A0 | (msg_type & 0x1F) | ((msg_id & 0x7) << 9) | ((ndo & 0x7) << 12)
}

/// A USB Power Delivery link on one Cynthion Type-C port.
pub struct PdLink {
    apollo: Apollo,
    port: PdLine,
    cc: u8,
    msg_id: u16,
    vbus_route: u8,
    trace: Option<PdTrace>,
}

impl PdLink {
    /// Wrap an already-open [`Apollo`] (which must be running the `pd_bridge`
    /// gateware) as a PD link on `port`.
    pub fn new(apollo: Apollo, port: PdPort) -> Self {
        PdLink {
            apollo,
            port: port.into(),
            cc: 0,
            msg_id: 0,
            vbus_route: 0,
            trace: None,
        }
    }

    /// Attach a trace recorder; every message sent or received is recorded to it
    /// (console, and pcapng if the trace has a writer).
    pub fn set_trace(&mut self, trace: PdTrace) {
        self.trace = Some(trace);
    }

    /// The underlying Apollo handle (for low-level register / VBUS access).
    pub fn apollo(&self) -> &Apollo {
        &self.apollo
    }
    /// The port this link drives.
    pub fn port(&self) -> PdPort {
        self.port.into()
    }
    /// The active CC line (1 or 2), or 0 before `setup_source`/`setup_sink`.
    pub fn cc(&self) -> u8 {
        self.cc
    }
    /// Mutable access to the attached trace, if any.
    pub fn trace_mut(&mut self) -> Option<&mut PdTrace> {
        self.trace.as_mut()
    }
    /// Recover the Apollo handle (and the trace), consuming the link.
    pub fn into_parts(self) -> (Apollo, Option<PdTrace>) {
        (self.apollo, self.trace)
    }

    // --- VBUS ---

    /// Bring up 5 V VBUS on TARGET-C: prefer an AUX supply, fall back to
    /// CONTROL/host 5 V. Returns a label for the source used. Only valid on
    /// TARGET-C. The route is remembered for [`cycle_vbus`](Self::cycle_vbus).
    pub fn bring_up_vbus(&mut self, mode: VbusSource) -> Result<&'static str> {
        if self.port != PdLine::TargetC {
            return Err(Error::Unsupported("VBUS bring-up is only for TARGET-C"));
        }
        let (label, bits) = bring_up_vbus_target_c(&self.apollo, mode)?;
        self.vbus_route = bits;
        Ok(label)
    }

    /// Set the raw VBUS switch bits (see [`crate::flash::vbus`]). Returns the
    /// read-back switch state.
    pub fn set_vbus(&self, bits: u8) -> Result<u8> {
        self.apollo.set_vbus_switches(bits)
    }

    /// Drop + discharge TARGET-C VBUS, then re-apply the last brought-up route,
    /// forcing a fresh Type-C attach (so a sink re-opens its Source_Capabilities
    /// window).
    pub fn cycle_vbus(&self) -> Result<()> {
        cycle_vbus_target_c(&self.apollo, self.vbus_route)
    }

    // --- PHY role ---

    /// Present as a PD source (Rp), detect the sink's CC, enable BMC TX/RX with
    /// hardware AUTO_CRC and GoodCRC auto-retry. Stores and returns the CC (1/2),
    /// or 0 if no sink is detected.
    pub fn setup_source(&mut self) -> Result<u8> {
        self.cc = self.apollo.fusb302_setup_source(self.port)?;
        Ok(self.cc)
    }

    /// Present as a PD sink (Rd), detect the source's CC, enable BMC receive.
    /// Stores and returns the CC (1/2), or 0 if nothing is attached.
    pub fn setup_sink(&mut self) -> Result<u8> {
        self.cc = self.apollo.fusb302_setup_sink(self.port)?;
        Ok(self.cc)
    }

    // --- messaging ---

    /// Build a source/DFP Rev 3.0 header for the next message, advancing the
    /// MessageID. Useful when assembling custom messages with [`PdMessage`].
    pub fn next_source_header(&mut self, msg_type: u16, ndo: u16) -> u16 {
        let h = source_header(msg_type, ndo, self.msg_id);
        self.msg_id = self.msg_id.wrapping_add(1);
        h
    }

    /// Transmit a PD message (header + data objects) and record it.
    pub fn send(&mut self, msg: &PdMessage) -> Result<()> {
        self.apollo.fusb302_tx(self.port, &msg.raw)?;
        self.record(PdDirection::ToDut, msg)
    }

    /// Send a structured Vendor-Defined Message. `header` overrides the 16-bit PD
    /// message header (for forensic / non-compliant cases); when `None`, a
    /// source/DFP Rev 3.0 Vendor_Defined header is built and the MessageID
    /// advanced.
    pub fn send_vdm(&mut self, vdm: &Vdm, header: Option<u16>) -> Result<()> {
        let mut objects = vec![vdm.vdm_header()];
        objects.extend_from_slice(&vdm.objects);
        let h = match header {
            Some(h) => h,
            None => self.next_source_header(15, objects.len() as u16),
        };
        self.send(&PdMessage::from_objects(h, &objects))
    }

    /// Pre-stage a message in the TX FIFO without transmitting (slow part), to be
    /// sent later with [`fire`](Self::fire). Used to hit tight PD timing windows
    /// over the slow JTAG-I2C link.
    pub fn stage(&self, msg: &PdMessage) -> Result<()> {
        self.apollo.fusb302_tx_stage(self.port, &msg.raw)
    }

    /// Transmit the previously [`stage`](Self::stage)d message (one fast write).
    /// Note: not recorded to the trace (the caller knows what it staged) — record
    /// it explicitly if needed.
    pub fn fire(&self) -> Result<()> {
        self.apollo.fusb302_tx_fire(self.port)
    }

    /// Whether the partner GoodCRC'd our last transmit: `Some(true)` ACKed,
    /// `Some(false)` retries failed, `None` no result yet. (The GoodCRC is
    /// consumed by hardware, not delivered to the FIFO.)
    pub fn tx_acked(&self) -> Result<Option<bool>> {
        self.apollo.fusb302_tx_result(self.port)
    }

    /// Read one received PD message from the RX FIFO, if any, recording it.
    pub fn poll(&mut self) -> Result<Option<PdMessage>> {
        match self.apollo.fusb302_poll_message(self.port)? {
            Some(raw) => {
                let msg = PdMessage { raw };
                self.record(PdDirection::FromDut, &msg)?;
                Ok(Some(msg))
            }
            None => Ok(None),
        }
    }

    /// Receive the next PD message within `timeout` (polling the RX FIFO).
    pub fn recv(&mut self, timeout: Duration) -> Result<Option<PdMessage>> {
        let start = Instant::now();
        loop {
            if let Some(m) = self.poll()? {
                return Ok(Some(m));
            }
            if start.elapsed() >= timeout {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(15));
        }
    }

    /// Raw FUSB302B controller register read (forensic / low-level access).
    pub fn controller_read(&self, reg: u8) -> Result<u8> {
        self.apollo.fusb302_read_register(self.port, 0x22, reg)
    }
    /// Raw FUSB302B controller register write.
    pub fn controller_write(&self, reg: u8, value: u8) -> Result<()> {
        self.apollo.fusb302_write_register(self.port, 0x22, reg, value)
    }

    // --- negotiation ---

    /// Run a source-initiated PD negotiation with the timing the spec demands,
    /// worked around the slow JTAG-I2C link: pre-stage `Source_Capabilities`,
    /// cycle VBUS for a fresh attach, fire the caps inside the sink's
    /// `tSinkWaitCap` window, then listen for the `Request`. On receiving it,
    /// reply `Accept` + `PS_RDY` (best effort) and return the Request message.
    ///
    /// `pdos` are the advertised Power Data Objects (e.g. `(100 << 10) | 150`
    /// for a 5 V @ 1.5 A fixed PDO). Requires [`setup_source`](Self::setup_source)
    /// (and usually VBUS) first. Returns `None` if no Request arrived.
    pub fn negotiate_source(&mut self, pdos: &[u32]) -> Result<Option<PdMessage>> {
        for _ in 0..4 {
            let caps = PdMessage::from_objects(source_header(1, pdos.len() as u16, self.msg_id), pdos);
            // Slow part, done before the window: load the FIFO (no TXON).
            self.apollo.fusb302_tx_stage(self.port, &caps.raw)?;
            // Force a fresh attach so the sink re-opens its tSinkWaitCap window.
            if self.vbus_route != 0 {
                cycle_vbus_target_c(&self.apollo, self.vbus_route)?;
            }
            // Wait out the sink's attach debounce, then fire inside the window.
            std::thread::sleep(Duration::from_millis(180));
            self.apollo.fusb302_tx_fire(self.port)?;
            self.record(PdDirection::ToDut, &caps)?;
            self.msg_id = self.msg_id.wrapping_add(1);
            let _ = self.apollo.fusb302_tx_result(self.port); // clear/observe TX result

            // Stay quiet (half-duplex) and listen for the Request.
            let window = Instant::now();
            while window.elapsed() < Duration::from_millis(1200) {
                if let Some(msg) = self.poll()? {
                    if msg.class() == Some(PdMessageClass::Data) && msg.message_type() == Some(2) {
                        let accept = self.next_source_header(3, 0);
                        self.send(&PdMessage::from_objects(accept, &[]))?;
                        let rdy = self.next_source_header(6, 0);
                        self.send(&PdMessage::from_objects(rdy, &[]))?;
                        return Ok(Some(msg));
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(15));
                }
            }
        }
        Ok(None)
    }

    fn record(&mut self, dir: PdDirection, msg: &PdMessage) -> Result<()> {
        let id = iface_id(self.port);
        let cc = self.cc;
        if let Some(t) = &mut self.trace {
            t.record(id, dir, PdSop::Sop, cc, None, msg)?;
        }
        Ok(())
    }
}

/// Bring up 5 V VBUS on TARGET-C: prefer an AUX supply, fall back to CONTROL/host
/// 5 V. Returns `(label, switch_bits)`. Only ever 5 V; AUX and CONTROL are never
/// on the rail together (no back-feed into the host).
fn bring_up_vbus_target_c(apollo: &Apollo, mode: VbusSource) -> Result<(&'static str, u8)> {
    apollo.set_vbus_switches(0)?;
    let try_aux = matches!(mode, VbusSource::Auto | VbusSource::Aux);
    let try_control = matches!(mode, VbusSource::Auto | VbusSource::Control);
    if try_aux {
        let cc = apollo.fusb302_setup_sink(PdLine::Aux)?;
        if cc != 0 {
            for _ in 0..20 {
                let s = apollo.fusb302_read_register(PdLine::Aux, 0x22, 0x40)?;
                if (s >> 7) & 1 == 1 {
                    let bits = vbus::AUX_IN | vbus::AUX | vbus::TARGET_C;
                    apollo.set_vbus_switches(bits)?;
                    return Ok(("AUX 5 V", bits));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        if matches!(mode, VbusSource::Aux) {
            return Err(Error::Protocol("no powered supply detected on AUX".into()));
        }
    }
    if try_control {
        let bits = vbus::CONTROL_IN | vbus::CONTROL | vbus::TARGET_C;
        apollo.set_vbus_switches(bits)?;
        std::thread::sleep(Duration::from_millis(150));
        let s = apollo.fusb302_read_register(PdLine::TargetC, 0x22, 0x40).unwrap_or(0);
        if (s >> 7) & 1 == 1 {
            return Ok(("CONTROL / host 5 V", bits));
        }
        return Ok(("CONTROL / host 5 V (VBUS not yet confirmed)", bits));
    }
    Err(Error::Protocol(format!("no VBUS source available (mode {mode:?})")))
}

/// Drop + discharge TARGET-C VBUS, then re-apply `route` to force a fresh attach.
fn cycle_vbus_target_c(apollo: &Apollo, route: u8) -> Result<()> {
    apollo.set_vbus_switches(vbus::TARGET_C | vbus::TARGET_A_DISCHARGE)?;
    std::thread::sleep(Duration::from_millis(600));
    apollo.set_vbus_switches(route)?;
    Ok(())
}
