//! Per-port VBUS power telemetry.
//!
//! On the Cynthion this is the PAC1954 4-channel monitor on the FPGA's I2C bus
//! (see `docs/ARCHITECTURE.md` §2.1). Useful forensically to log exactly when and
//! how much power each port draws/sources around reset, attach, and PD events.

use crate::error::Result;

/// A Cynthion port the power monitor can measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitoredPort {
    Control,
    Aux,
    TargetA,
    TargetC,
}

impl MonitoredPort {
    /// All monitored ports, in channel order.
    pub const ALL: [MonitoredPort; 4] = [
        MonitoredPort::Control,
        MonitoredPort::Aux,
        MonitoredPort::TargetA,
        MonitoredPort::TargetC,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            MonitoredPort::Control => "control",
            MonitoredPort::Aux => "aux",
            MonitoredPort::TargetA => "target-a",
            MonitoredPort::TargetC => "target-c",
        }
    }
}

/// A single VBUS measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortPower {
    /// Bus voltage in millivolts.
    pub voltage_mv: u32,
    /// Current in milliamps; positive = sourced out of the port, negative = sunk.
    pub current_ma: i32,
}

impl PortPower {
    /// Instantaneous power in milliwatts (magnitude).
    pub fn power_mw(self) -> u32 {
        (u64::from(self.voltage_mv) * u64::from(self.current_ma.unsigned_abs()) / 1000) as u32
    }
}

/// Reading per-port VBUS voltage and current.
pub trait PowerMonitor {
    /// Measure a single port.
    fn read(&mut self, port: MonitoredPort) -> Result<PortPower>;

    /// Measure all ports. Default reads each in turn.
    fn read_all(&mut self) -> Result<[(MonitoredPort, PortPower); 4]> {
        Ok([
            (MonitoredPort::Control, self.read(MonitoredPort::Control)?),
            (MonitoredPort::Aux, self.read(MonitoredPort::Aux)?),
            (MonitoredPort::TargetA, self.read(MonitoredPort::TargetA)?),
            (MonitoredPort::TargetC, self.read(MonitoredPort::TargetC)?),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power_mw_calc() {
        let p = PortPower {
            voltage_mv: 5000,
            current_ma: 500,
        };
        assert_eq!(p.power_mw(), 2500);
        let sink = PortPower {
            voltage_mv: 5000,
            current_ma: -200,
        };
        assert_eq!(sink.power_mw(), 1000);
    }
}
