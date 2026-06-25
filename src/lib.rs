//! `usbmagic` — a library for working with "magic USB ports": programmable USB
//! test instruments that can passively observe or actively shape USB traffic.
//!
//! The first supported device is the [Cynthion] from Great Scott Gadgets running
//! the *USB Analyzer* gateware (USB ID `1d50:615b`), which passively captures
//! Low/Full/High-speed USB 2.0 traffic flowing through its TARGET ports.
//!
//! [Cynthion]: https://greatscottgadgets.com/cynthion/
//!
//! # Architecture
//!
//! Devices are abstracted behind the [`MagicDevice`] trait, and each concrete
//! device is implemented as a [`backend::Backend`]. [`discover`] enumerates the
//! USB bus and returns one [`Discovered`] handle per matching device.
//!
//! ```no_run
//! use usbmagic::{discover, CaptureOptions, CaptureData, Speed};
//!
//! let mut dev = discover()?.into_iter().next().ok_or("no device")?.open()?;
//! let opts = CaptureOptions { speed: Speed::Auto, ..Default::default() };
//! for item in dev.start_capture(opts)?.take(10) {
//!     match item?.data {
//!         CaptureData::Packet(bytes) => println!("packet: {} bytes", bytes.len()),
//!         CaptureData::Event(code) => println!("event: {code:#04x}"),
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod backend;
pub mod capture;
pub mod device;
pub mod error;
pub mod flash;
pub mod host;
pub mod mock;
pub mod pcap;
pub mod pcapng;
pub mod pd;
pub mod power;

pub use capture::{CaptureData, CaptureItem, CaptureOptions, CaptureStream, Speed, StopFn};
pub use device::{discover, Capabilities, DeviceDescription, Discovered, MagicDevice, State};
pub use error::{Error, Result};
pub use host::{
    DeviceDescriptor, Direction, EnumeratedDevice, Handshake, Pid, RawTransaction, Setup, UsbHost,
};
pub use pcapng::{
    parse_pcapng, parse_pd_pseudo_header, pd_pseudo_header, sop_name, PcapNg, PcapNgInterface,
    PcapNgPacket, PcapNgWriter, PdDirection, PdPseudoHeader, PdSop, LINKTYPE_USB_TYPE_C_PD,
};
pub use pd::{
    format_pd_message, pd_message_name, PdLink, PdMessage, PdPort, PdTrace, PowerDelivery,
    VbusSource, Vdm,
};
pub use power::{MonitoredPort, PortPower, PowerMonitor};
