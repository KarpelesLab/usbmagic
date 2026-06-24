//! Device backends. Each backend knows how to recognize and open one family of
//! magic USB devices.

pub mod cynthion;

use crate::device::MagicDevice;
use crate::error::Result;

/// A driver for one family of magic USB devices.
pub trait Backend: Sync {
    /// Short, stable backend name (e.g. `"cynthion"`).
    fn name(&self) -> &'static str;

    /// Whether this backend can handle the given USB device.
    fn matches(&self, info: &nusb::DeviceInfo) -> bool;

    /// Open the device and return a controllable handle.
    fn open(&self, info: nusb::DeviceInfo) -> Result<Box<dyn MagicDevice>>;
}

/// All backends, tried in order during discovery.
pub static BACKENDS: &[&dyn Backend] = &[&cynthion::CYNTHION];
