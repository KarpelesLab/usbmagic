//! Error and result types for the library.

use thiserror::Error;

/// Convenience alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced while discovering, controlling, or capturing from a device.
#[derive(Debug, Error)]
pub enum Error {
    /// A USB operation (open, claim, configure) failed.
    #[error("USB error: {0}")]
    Usb(#[from] nusb::Error),

    /// A USB control or bulk transfer failed.
    #[error("USB transfer error: {0}")]
    Transfer(#[from] nusb::transfer::TransferError),

    /// An I/O error, e.g. while reading the capture stream or writing output.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// No device matched the requested criteria.
    #[error("no matching magic USB device found")]
    NoDevice,

    /// More than one device matched and no selector was given.
    #[error("multiple devices match; select one (e.g. by serial number)")]
    AmbiguousDevice,

    /// The device or backend does not support the requested operation.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),

    /// The device returned data that did not match the expected protocol.
    #[error("protocol error: {0}")]
    Protocol(String),
}
