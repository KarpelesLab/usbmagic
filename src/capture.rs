//! Backend-agnostic capture types: the link speed, capture options, and the
//! decoded items ([`CaptureItem`]) yielded by a [`CaptureStream`].

use crate::error::Result;

/// USB bus speed to capture at.
///
/// [`Speed::Auto`] lets the device detect the speed of the link on its TARGET
/// ports; the others force a specific speed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Speed {
    /// Detect the link speed automatically.
    Auto,
    /// Low speed (1.5 Mbit/s).
    Low,
    /// Full speed (12 Mbit/s).
    Full,
    /// High speed (480 Mbit/s).
    High,
}

impl Speed {
    /// All speeds, in protocol order.
    pub const ALL: [Speed; 4] = [Speed::Auto, Speed::Low, Speed::Full, Speed::High];

    /// The 2-bit value written into the device State register (bits 1–2).
    pub fn encode(self) -> u8 {
        match self {
            Speed::Auto => 0,
            Speed::Low => 1,
            Speed::Full => 2,
            Speed::High => 3,
        }
    }

    /// Decode the 2-bit value from the device State register.
    pub fn from_encoded(value: u8) -> Speed {
        match value & 0b11 {
            0 => Speed::Auto,
            1 => Speed::Low,
            2 => Speed::Full,
            _ => Speed::High,
        }
    }

    /// The bit representing this speed in the device's supported-speeds mask.
    pub fn mask_bit(self) -> u8 {
        match self {
            Speed::Auto => 0b0001,
            Speed::Low => 0b0010,
            Speed::Full => 0b0100,
            Speed::High => 0b1000,
        }
    }

    /// Lowercase human-readable name.
    pub fn as_str(self) -> &'static str {
        match self {
            Speed::Auto => "auto",
            Speed::Low => "low",
            Speed::Full => "full",
            Speed::High => "high",
        }
    }
}

impl std::fmt::Display for Speed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Options controlling a capture session.
#[derive(Debug, Clone, Copy)]
pub struct CaptureOptions {
    /// Speed to capture at.
    pub speed: Speed,
    /// Drive VBUS through to the TARGET so a bus-powered target device powers on
    /// during capture. Experimental — leave `false` for purely passive capture.
    pub vbus_passthrough: bool,
}

impl Default for CaptureOptions {
    fn default() -> Self {
        CaptureOptions {
            speed: Speed::Auto,
            vbus_passthrough: false,
        }
    }
}

/// A single decoded item from the capture stream.
#[derive(Debug, Clone)]
pub struct CaptureItem {
    /// Timestamp in nanoseconds since the start of the capture, derived from the
    /// device's 60 MHz clock.
    pub timestamp_ns: u64,
    /// The payload of this item.
    pub data: CaptureData,
}

/// The payload of a [`CaptureItem`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureData {
    /// A captured USB packet: the raw on-the-wire bytes starting with the PID.
    Packet(Vec<u8>),
    /// An out-of-band event reported by the device, identified by its code.
    Event(u8),
}

/// A callable that stops the underlying capture.
///
/// It is [`Send`] so it can be invoked from a timer thread or signal handler to
/// unblock a capture that is otherwise blocked waiting for USB traffic.
pub type StopFn = Box<dyn FnMut() -> Result<()> + Send>;

/// The backend-specific source of capture items behind a [`CaptureStream`].
pub trait CaptureSource: Iterator<Item = Result<CaptureItem>> {
    /// Stop the capture now. Idempotent.
    fn stop(&mut self) -> Result<()>;

    /// Produce a detached handle that can stop this capture from another thread.
    fn stop_handle(&self) -> StopFn;
}

/// A stream of [`CaptureItem`]s from a device.
///
/// Iterate it to pull decoded packets and events. The capture is stopped
/// automatically when the stream is dropped; call [`CaptureStream::stop`] to do
/// so explicitly, or [`CaptureStream::stop_handle`] to get a [`StopFn`] you can
/// trigger from elsewhere.
pub struct CaptureStream {
    inner: Box<dyn CaptureSource>,
}

impl CaptureStream {
    /// Wrap a backend capture source.
    pub fn new(inner: Box<dyn CaptureSource>) -> Self {
        CaptureStream { inner }
    }

    /// Stop the capture explicitly.
    pub fn stop(mut self) -> Result<()> {
        self.inner.stop()
    }

    /// Get a [`StopFn`] that stops this capture when called.
    pub fn stop_handle(&self) -> StopFn {
        self.inner.stop_handle()
    }
}

impl Iterator for CaptureStream {
    type Item = Result<CaptureItem>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}
