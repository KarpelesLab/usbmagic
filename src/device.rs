//! The [`MagicDevice`] trait, device metadata types, and [`discover`].

use crate::backend::{self, Backend};
use crate::capture::{CaptureOptions, CaptureStream, Speed};
use crate::error::Result;

use nusb::MaybeFuture;

/// Stable identity of a device, available without opening it.
#[derive(Debug, Clone)]
pub struct DeviceDescription {
    /// Name of the backend that handles this device (e.g. `"cynthion"`).
    pub backend: &'static str,
    /// USB vendor ID.
    pub vendor_id: u16,
    /// USB product ID.
    pub product_id: u16,
    /// Product string, if the OS has it cached.
    pub product: Option<String>,
    /// Serial number, if present.
    pub serial: Option<String>,
    /// Host-controller-relative bus identifier.
    pub bus_id: String,
    /// Device address on the bus.
    pub address: u8,
}

/// What a device can do, discovered after opening it.
#[derive(Debug, Clone)]
pub struct Capabilities {
    /// Speeds the device reports it can capture at.
    pub supported_speeds: Vec<Speed>,
    /// Whether the device can capture traffic.
    pub can_capture: bool,
    /// Whether the device can drive VBUS to the target.
    pub can_control_vbus: bool,
    /// Gateware minor protocol version, if the device reports one.
    pub protocol_version: Option<u8>,
}

/// A decoded snapshot of the device's control State register.
#[derive(Debug, Clone, Copy)]
pub struct State {
    /// Capture is currently enabled.
    pub enable: bool,
    /// Configured capture speed.
    pub speed: Speed,
    /// VBUS enabled on the TARGET-C port.
    pub target_c_vbus_en: bool,
    /// VBUS enabled on the CONTROL port.
    pub control_vbus_en: bool,
    /// VBUS enabled on the AUX port.
    pub aux_vbus_en: bool,
    /// TARGET-A VBUS discharge active.
    pub target_a_discharge: bool,
    /// Power control enabled.
    pub power_control_enable: bool,
}

/// A magic USB device that can be controlled and captured from.
pub trait MagicDevice {
    /// Stable identity of this device.
    fn description(&self) -> &DeviceDescription;

    /// Capabilities reported by this device.
    fn capabilities(&self) -> &Capabilities;

    /// Read the device's current control state.
    fn read_state(&mut self) -> Result<State>;

    /// Start a capture session with the given options.
    fn start_capture(&mut self, options: CaptureOptions) -> Result<CaptureStream>;

    /// Access this device as a USB **host** (drive a downstream device), if it
    /// supports host mode. Defaults to `None`; backends that gain host gateware
    /// override it.
    fn as_host(&mut self) -> Option<&mut dyn crate::host::UsbHost> {
        None
    }

    /// Access this device's USB **Power Delivery** capability, if any.
    fn power_delivery(&mut self) -> Option<&mut dyn crate::pd::PowerDelivery> {
        None
    }

    /// Access this device's per-port **power monitor**, if any.
    fn power_monitor(&mut self) -> Option<&mut dyn crate::power::PowerMonitor> {
        None
    }
}

/// A device found on the bus that a backend can open.
pub struct Discovered {
    description: DeviceDescription,
    info: nusb::DeviceInfo,
    backend: &'static dyn Backend,
}

impl Discovered {
    /// The device's identity (no I/O).
    pub fn description(&self) -> &DeviceDescription {
        &self.description
    }

    /// Open the device, returning a controllable handle.
    pub fn open(self) -> Result<Box<dyn MagicDevice>> {
        self.backend.open(self.info)
    }
}

/// Build a [`DeviceDescription`] from raw USB info and a backend name.
pub(crate) fn describe(backend: &'static str, info: &nusb::DeviceInfo) -> DeviceDescription {
    DeviceDescription {
        backend,
        vendor_id: info.vendor_id(),
        product_id: info.product_id(),
        product: info.product_string().map(str::to_string),
        serial: info.serial_number().map(str::to_string),
        bus_id: info.bus_id().to_string(),
        address: info.device_address(),
    }
}

/// Enumerate all connected magic USB devices across all backends.
pub fn discover() -> Result<Vec<Discovered>> {
    let mut found = Vec::new();
    for info in nusb::list_devices().wait()? {
        for backend in backend::BACKENDS {
            if backend.matches(&info) {
                found.push(Discovered {
                    description: describe(backend.name(), &info),
                    info,
                    backend: *backend,
                });
                break;
            }
        }
    }
    Ok(found)
}
