//! A software mock of a Cynthion in host mode, plus a simulated attached device.
//!
//! It lets the host-side stack ([`crate::host`], [`crate::pd`], [`crate::power`])
//! be developed and tested before any gateware exists. The simulated device
//! answers the standard enumeration sequence, so [`UsbHost::enumerate`] works
//! end-to-end against it.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::capture::Speed;
use crate::error::Result;
use crate::host::{
    descriptor_type, request, BusError, ControlForensics, ControlResult, Direction, Handshake, Pid,
    PortStatus, RawTransaction, Setup, TransactionResult, UsbHost, WireEvent, WireEventKind,
};
use crate::pd::{CcOrientation, CcStatus, PdMessage, PdPort, PowerDelivery};
use crate::power::{MonitoredPort, PortPower, PowerMonitor};

/// A simulated USB device the [`MockHost`] enumerates and talks to.
#[derive(Debug, Clone)]
pub struct VirtualDevice {
    pub device_descriptor: [u8; 18],
    pub config_descriptor: Vec<u8>,
    /// String descriptors keyed by `(index, langid)`.
    pub strings: BTreeMap<(u8, u16), String>,
    pub speed: Speed,
    /// Current device address (0 until SET_ADDRESS).
    pub address: u8,
}

impl VirtualDevice {
    /// A full-speed device (VID `0x1209` / PID `0x0001`) with one vendor-class
    /// interface (two bulk endpoints) and a few string descriptors.
    pub fn example() -> VirtualDevice {
        let mut dd = [0u8; 18];
        dd[0] = 18; // bLength
        dd[1] = descriptor_type::DEVICE;
        dd[2] = 0x00;
        dd[3] = 0x02; // bcdUSB 2.00
        dd[7] = 64; // bMaxPacketSize0
        dd[8] = 0x09;
        dd[9] = 0x12; // idVendor 0x1209
        dd[10] = 0x01;
        dd[11] = 0x00; // idProduct 0x0001
        dd[12] = 0x00;
        dd[13] = 0x01; // bcdDevice 1.00
        dd[14] = 1; // iManufacturer
        dd[15] = 2; // iProduct
        dd[16] = 3; // iSerialNumber
        dd[17] = 1; // bNumConfigurations

        // Config (str 5) + one vendor interface (str 4) + two bulk endpoints.
        let mut config = vec![
            9, descriptor_type::CONFIGURATION, 0, 0, 1, 1, 5, 0xC0, 50, //
            9, descriptor_type::INTERFACE, 0, 0, 2, 0xFF, 0x00, 0x00, 4, //
            7, descriptor_type::ENDPOINT, 0x81, 0x02, 0x40, 0x00, 0x00, //
            7, descriptor_type::ENDPOINT, 0x01, 0x02, 0x40, 0x00, 0x00, //
        ];
        let total = config.len() as u16;
        config[2..4].copy_from_slice(&total.to_le_bytes());

        let mut strings = BTreeMap::new();
        for (idx, s) in [
            (1u8, "usbmagic"),
            (2, "Mock Device"),
            (3, "SN-0001"),
            (4, "Default Interface"),
            (5, "Config 1"),
        ] {
            strings.insert((idx, 0x0409u16), s.to_string());
        }

        VirtualDevice {
            device_descriptor: dd,
            config_descriptor: config,
            strings,
            speed: Speed::Full,
            address: 0,
        }
    }

    /// Build the on-wire bytes of string descriptor `index` in `langid`, or
    /// `None` if the device has no such string (→ the device STALLs).
    fn string_descriptor(&self, index: u8, langid: u16) -> Option<Vec<u8>> {
        let mut d = vec![0u8, descriptor_type::STRING];
        if index == 0 {
            // LANGID list (string index 0).
            let mut langs: Vec<u16> = self.strings.keys().map(|k| k.1).collect();
            langs.sort_unstable();
            langs.dedup();
            if langs.is_empty() {
                langs.push(0x0409);
            }
            for l in langs {
                d.extend_from_slice(&l.to_le_bytes());
            }
        } else {
            for u in self.strings.get(&(index, langid))?.encode_utf16() {
                d.extend_from_slice(&u.to_le_bytes());
            }
        }
        d[0] = d.len() as u8;
        Some(d)
    }
}

/// A mock host: an in-memory stand-in for the future Cynthion host backend.
pub struct MockHost {
    vbus: bool,
    clock_ns: u64,
    events: Vec<WireEvent>,
    device: VirtualDevice,
    pd_registers: [u8; 256],
    pd_inbox: Vec<PdMessage>,
    vconn: bool,
}

impl MockHost {
    /// Create a mock host with the given simulated device attached.
    pub fn with_device(device: VirtualDevice) -> MockHost {
        MockHost {
            vbus: false,
            clock_ns: 0,
            events: Vec::new(),
            device,
            pd_registers: [0u8; 256],
            pd_inbox: Vec::new(),
            vconn: false,
        }
    }

    /// Create a mock host with the example full-speed device.
    pub fn new() -> MockHost {
        MockHost::with_device(VirtualDevice::example())
    }

    fn tick(&mut self, ns: u64) -> u64 {
        let now = self.clock_ns;
        self.clock_ns += ns;
        now
    }

    fn log(&mut self, kind: WireEventKind) {
        let timestamp_ns = self.clock_ns;
        self.events.push(WireEvent { timestamp_ns, kind });
    }
}

impl Default for MockHost {
    fn default() -> Self {
        MockHost::new()
    }
}

impl UsbHost for MockHost {
    fn set_vbus(&mut self, on: bool) -> Result<()> {
        self.vbus = on;
        self.tick(1_000);
        if on {
            let speed = self.device.speed;
            self.log(WireEventKind::Connect(Some(speed)));
        } else {
            self.log(WireEventKind::Disconnect);
        }
        Ok(())
    }

    fn port_status(&mut self) -> Result<PortStatus> {
        Ok(PortStatus {
            connected: self.vbus,
            speed: self.vbus.then_some(self.device.speed),
            vbus_mv: Some(if self.vbus { 5000 } else { 0 }),
            reset_in_progress: false,
        })
    }

    fn bus_reset(&mut self) -> Result<Option<Speed>> {
        self.tick(10_000_000); // ~10 ms reset
        self.device.address = 0; // reset returns the device to the default address
        self.log(WireEventKind::BusReset);
        Ok(self.vbus.then_some(self.device.speed))
    }

    fn control_raw(
        &mut self,
        address: u8,
        setup_bytes: [u8; 8],
        _data_out: &[u8],
        opts: ControlForensics,
    ) -> Result<ControlResult> {
        let start = self.tick(50_000);
        let setup = Setup {
            request_type: setup_bytes[0],
            request: setup_bytes[1],
            value: u16::from_le_bytes([setup_bytes[2], setup_bytes[3]]),
            index: u16::from_le_bytes([setup_bytes[4], setup_bytes[5]]),
            length: u16::from_le_bytes([setup_bytes[6], setup_bytes[7]]),
        };
        self.log(WireEventKind::Packet {
            pid: Pid::Setup,
            data: setup_bytes.to_vec(),
        });

        // No device answers at an address other than its current one.
        if address != self.device.address {
            self.log(WireEventKind::Error(BusError::Timeout));
            return Ok(ControlResult {
                data: Vec::new(),
                stalled: false,
                errors: vec![BusError::Timeout],
                duration_ns: self.clock_ns - start,
            });
        }

        let mut errors = Vec::new();
        // How many data bytes the host actually clocks (forensic override).
        let stage_len = opts.data_len_override.unwrap_or(setup.length as usize);

        let (mut data, stalled): (Vec<u8>, bool) = match setup.request {
            request::GET_DESCRIPTOR => {
                let desc_type = (setup.value >> 8) as u8;
                let index = (setup.value & 0xFF) as u8;
                let full: Option<Vec<u8>> = match desc_type {
                    descriptor_type::DEVICE => Some(self.device.device_descriptor.to_vec()),
                    descriptor_type::CONFIGURATION => Some(self.device.config_descriptor.clone()),
                    descriptor_type::STRING => self.device.string_descriptor(index, setup.index),
                    _ => None,
                };
                match full {
                    Some(bytes) => {
                        // The device returns at most what it has; asking for more
                        // (oversized) yields a short packet, not extra data.
                        if stage_len > bytes.len() {
                            errors.push(BusError::ShortPacket);
                        }
                        (bytes[..stage_len.min(bytes.len())].to_vec(), false)
                    }
                    None => (Vec::new(), true), // unknown/missing descriptor → STALL
                }
            }
            request::SET_ADDRESS => {
                self.device.address = setup.value as u8;
                (Vec::new(), false)
            }
            request::SET_CONFIGURATION => (Vec::new(), false),
            _ => (Vec::new(), true), // unsupported request → STALL
        };

        // Reflect data-stage wire violations.
        if opts.flags.truncate && !data.is_empty() {
            data.pop();
            errors.push(BusError::ShortPacket);
        }
        if opts.flags.extra_bytes > 0 {
            data.extend(std::iter::repeat(0xCD).take(opts.flags.extra_bytes));
            errors.push(BusError::Babble);
        }
        if opts.flags.corrupt_crc {
            errors.push(BusError::Crc16);
        }
        if opts.skip_status {
            errors.push(BusError::Other("control transfer had no status stage".into()));
        }
        if opts.status_wrong_dir {
            errors.push(BusError::Other("status stage driven in the wrong direction".into()));
        }

        Ok(ControlResult {
            data,
            stalled,
            errors,
            duration_ns: self.clock_ns - start,
        })
    }

    fn transfer(
        &mut self,
        address: u8,
        _endpoint: u8,
        dir: Direction,
        data: &[u8],
        max_len: usize,
    ) -> Result<TransactionResult> {
        let start = self.tick(20_000);
        if address != self.device.address {
            return Ok(TransactionResult {
                handshake: Handshake::None,
                data: Vec::new(),
                start_ns: start,
                duration_ns: self.clock_ns - start,
                errors: vec![BusError::Timeout],
            });
        }
        // The mock has no real endpoints: ACK with empty IN data / accept OUT.
        let _ = (max_len, data);
        let out: Vec<u8> = match dir {
            Direction::In => Vec::new(),
            Direction::Out => Vec::new(),
        };
        Ok(TransactionResult {
            handshake: Handshake::Ack,
            data: out,
            start_ns: start,
            duration_ns: self.clock_ns - start,
            errors: Vec::new(),
        })
    }

    fn raw_transaction(&mut self, tx: RawTransaction) -> Result<TransactionResult> {
        let start = self.tick(10_000);
        // Faithfully reflect forensic intent in the wire log.
        let mut errors = Vec::new();
        if tx.flags.corrupt_crc {
            errors.push(BusError::Crc16);
        }
        if tx.flags.bad_pid_check {
            errors.push(BusError::PidCheck);
        }
        if tx.flags.crc5_error {
            errors.push(BusError::Crc5);
        }
        if tx.flags.extra_bytes > 0 {
            errors.push(BusError::Babble);
        }
        if tx.flags.truncate {
            errors.push(BusError::ShortPacket);
        }
        let handshake = if tx.address == self.device.address {
            Handshake::Ack
        } else {
            errors.push(BusError::Timeout);
            Handshake::None
        };
        self.log(WireEventKind::Packet {
            pid: tx.pid,
            data: tx.data.clone(),
        });
        Ok(TransactionResult {
            handshake,
            data: Vec::new(),
            start_ns: start,
            duration_ns: self.clock_ns - start,
            errors,
        })
    }

    fn poll_events(&mut self) -> Result<Vec<WireEvent>> {
        Ok(std::mem::take(&mut self.events))
    }
}

impl PowerDelivery for MockHost {
    fn cc_status(&mut self, _port: PdPort) -> Result<CcStatus> {
        Ok(CcStatus {
            attached: self.vbus,
            orientation: if self.vbus {
                CcOrientation::Cc1
            } else {
                CcOrientation::None
            },
            vconn: self.vconn,
            is_source: true,
        })
    }

    fn set_vconn(&mut self, _port: PdPort, on: bool) -> Result<()> {
        self.vconn = on;
        Ok(())
    }

    fn pd_send(&mut self, _port: PdPort, message: &PdMessage) -> Result<()> {
        // Loopback: a sent message becomes receivable, useful for tests.
        self.pd_inbox.push(message.clone());
        Ok(())
    }

    fn pd_recv(&mut self, _port: PdPort, _timeout: Duration) -> Result<Option<PdMessage>> {
        Ok((!self.pd_inbox.is_empty()).then(|| self.pd_inbox.remove(0)))
    }

    fn controller_read(&mut self, _port: PdPort, reg: u8) -> Result<u8> {
        Ok(self.pd_registers[reg as usize])
    }

    fn controller_write(&mut self, _port: PdPort, reg: u8, value: u8) -> Result<()> {
        self.pd_registers[reg as usize] = value;
        Ok(())
    }
}

impl PowerMonitor for MockHost {
    fn read(&mut self, port: MonitoredPort) -> Result<PortPower> {
        let sourcing = matches!(port, MonitoredPort::TargetA | MonitoredPort::TargetC) && self.vbus;
        Ok(PortPower {
            voltage_mv: if self.vbus { 5000 } else { 0 },
            current_ma: if sourcing { 100 } else { 0 },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerate_against_mock_device() {
        let mut host = MockHost::new();
        host.set_vbus(true).unwrap();

        let dev = host.enumerate().unwrap();
        assert_eq!(dev.address, 1);
        assert_eq!(dev.speed, Some(Speed::Full));
        assert_eq!(dev.device_descriptor.vendor_id, 0x1209);
        assert_eq!(dev.device_descriptor.product_id, 0x0001);
        assert_eq!(dev.device_descriptor.max_packet_size0, 64);

        // The wire log recorded the reset that enumerate() issued.
        let events = host.poll_events().unwrap();
        assert!(events
            .iter()
            .any(|e| matches!(e.kind, WireEventKind::BusReset)));
    }

    #[test]
    fn forensic_corrupt_crc_is_reported_not_hidden() {
        let mut host = MockHost::new();
        host.set_vbus(true).unwrap();
        let mut tx = RawTransaction {
            pid: crate::host::Pid::Setup,
            address: 0,
            endpoint: 0,
            data: vec![0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00],
            flags: Default::default(),
        };
        tx.flags.corrupt_crc = true;
        let r = host.raw_transaction(tx).unwrap();
        assert!(r.errors.contains(&BusError::Crc16));
    }

    #[test]
    fn pd_loopback_and_vconn() {
        let mut host = MockHost::new();
        host.set_vconn(PdPort::TargetC, true).unwrap();
        assert!(host.cc_status(PdPort::TargetC).unwrap().vconn);

        let msg = PdMessage::from_objects(0x0001, &[]);
        host.pd_send(PdPort::TargetC, &msg).unwrap();
        let got = host.pd_recv(PdPort::TargetC, Duration::from_millis(1)).unwrap();
        assert_eq!(got, Some(msg));
    }

    #[test]
    fn power_monitor_reads() {
        let mut host = MockHost::new();
        host.set_vbus(true).unwrap();
        let p = host.read(MonitoredPort::TargetC).unwrap();
        assert_eq!(p.voltage_mv, 5000);
        assert_eq!(p.current_ma, 100);
    }

    #[test]
    fn examine_builds_full_model() {
        let mut host = MockHost::new();
        host.set_vbus(true).unwrap();
        let dev = host.enumerate().unwrap();
        let model = host.examine(dev.address).unwrap();
        assert_eq!(model.device_descriptor.vendor_id, 0x1209);
        assert_eq!(model.configurations.len(), 1);
        let iface = &model.configurations[0].interfaces[0];
        assert_eq!(iface.descriptor.class, 0xFF);
        assert_eq!(iface.endpoints.len(), 2);
        assert_eq!(model.strings.get(&(1, 0x0409)).map(String::as_str), Some("usbmagic"));
        assert_eq!(model.strings.get(&(2, 0x0409)).map(String::as_str), Some("Mock Device"));
        assert!(model.anomalies.is_empty());
    }

    #[test]
    fn forensic_oversized_descriptor_reports_short_packet() {
        use crate::host::UsbForensics;
        let mut host = MockHost::new();
        host.set_vbus(true).unwrap();
        host.enumerate().unwrap();
        // Ask for 4096 bytes of an 18-byte descriptor.
        let r = host
            .get_descriptor_oversized(1, descriptor_type::DEVICE, 0, 4096)
            .unwrap();
        assert_eq!(r.data.len(), 18); // device only has 18
        assert!(r.errors.contains(&BusError::ShortPacket));
    }

    #[test]
    fn forensic_babble_and_unassigned_and_bad_pid() {
        use crate::host::UsbForensics;
        let mut host = MockHost::new();
        host.set_vbus(true).unwrap();
        host.enumerate().unwrap();

        let r = host.babble(1, 1, &[0xAA], 16).unwrap();
        assert!(r.errors.contains(&BusError::Babble));

        // Nobody answers at address 9.
        let r = host.talk_to_unassigned(9, 1).unwrap();
        assert!(r.errors.contains(&BusError::Timeout));
        assert_eq!(r.handshake, Handshake::None);

        let r = host.bad_pid(1, 0, Pid::Out).unwrap();
        assert!(r.errors.contains(&BusError::PidCheck));
    }

    #[test]
    fn forensic_setup_length_mismatch_and_skip_status() {
        use crate::host::UsbForensics;
        let mut host = MockHost::new();
        host.set_vbus(true).unwrap();
        host.enumerate().unwrap();
        // GET_DESCRIPTOR(device) claiming wLength=18 but only clocking 4 bytes.
        let setup = Setup {
            request_type: 0x80,
            request: request::GET_DESCRIPTOR,
            value: (u16::from(descriptor_type::DEVICE)) << 8,
            index: 0,
            length: 18,
        };
        let r = host.setup_length_mismatch(1, setup.to_bytes(), &[], 4).unwrap();
        assert_eq!(r.data.len(), 4); // honored the override, not wLength

        let r = host.control_without_status(1, setup.to_bytes(), &[]).unwrap();
        assert!(r
            .errors
            .iter()
            .any(|e| matches!(e, BusError::Other(s) if s.contains("status"))));
    }
}
