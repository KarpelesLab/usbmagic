//! Thin helpers over [`rawusb`] shared by the backends and the flasher.

use std::sync::OnceLock;
use std::time::Duration;

use rawusb::{
    request_type, ControlType, Device, DeviceHandle, Direction, InterfaceDescriptor, Recipient,
};

use crate::error::Result;

/// Timeout for the best-effort string-descriptor reads done during discovery.
const STRING_TIMEOUT: Duration = Duration::from_millis(500);

/// The process-wide rawusb context (one event thread, created on first use).
pub(crate) fn context() -> Result<&'static rawusb::Context> {
    static CTX: OnceLock<rawusb::Context> = OnceLock::new();
    if let Some(ctx) = CTX.get() {
        return Ok(ctx);
    }
    let ctx = rawusb::Context::new()?;
    Ok(CTX.get_or_init(|| ctx))
}

/// All USB devices currently attached.
pub(crate) fn devices() -> Result<Vec<Device>> {
    Ok(context()?.devices()?)
}

/// Every interface alternate setting of the device's active configuration.
pub(crate) fn interfaces(dev: &Device) -> Vec<InterfaceDescriptor> {
    dev.active_config_descriptor()
        .map(|c| c.all_alt_settings().cloned().collect())
        .unwrap_or_default()
}

/// Number of the first interface with the given class and subclass.
pub(crate) fn find_interface(dev: &Device, class: u8, sub_class: u8) -> Option<u8> {
    interfaces(dev)
        .into_iter()
        .find(|i| i.class == class && i.sub_class == sub_class)
        .map(|i| i.number)
}

/// Open the device and claim one interface.
pub(crate) fn open_claim(dev: &Device, interface: u8) -> Result<DeviceHandle> {
    let handle = dev.open()?;
    handle.claim_interface(interface)?;
    Ok(handle)
}

/// Product and serial strings, read best-effort: `None` for each one the
/// device lacks or that could not be read (e.g. no permission to open it).
pub(crate) fn strings(dev: &Device) -> (Option<String>, Option<String>) {
    let desc = dev.device_descriptor();
    let Ok(handle) = dev.open() else {
        return (None, None);
    };
    let Some(lang) = handle
        .read_languages(STRING_TIMEOUT)
        .ok()
        .and_then(|l| l.first().copied())
    else {
        return (None, None);
    };
    let read = |index: u8| {
        (index != 0)
            .then(|| {
                handle
                    .read_string_descriptor(lang, index, STRING_TIMEOUT)
                    .ok()
            })
            .flatten()
    };
    (
        read(desc.product_string_index),
        read(desc.serial_number_string_index),
    )
}

/// Vendor control IN request; returns the bytes the device sent.
pub(crate) fn vendor_in(
    handle: &DeviceHandle,
    recipient: Recipient,
    request: u8,
    value: u16,
    index: u16,
    length: u16,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; length as usize];
    let rt = request_type(Direction::In, ControlType::Vendor, recipient);
    let n = handle.control_read(rt, request, value, index, &mut buf, timeout)?;
    buf.truncate(n);
    Ok(buf)
}

/// Vendor control OUT request.
pub(crate) fn vendor_out(
    handle: &DeviceHandle,
    recipient: Recipient,
    request: u8,
    value: u16,
    index: u16,
    data: &[u8],
    timeout: Duration,
) -> Result<()> {
    let rt = request_type(Direction::Out, ControlType::Vendor, recipient);
    handle.control_write(rt, request, value, index, data, timeout)?;
    Ok(())
}
