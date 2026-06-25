<!-- SPDX-License-Identifier: BSD-3-Clause -->
# USB host forensics API

`usbmagic` is a forensics tool, not a compliant USB stack. As a host it can talk to
and analyze a device **and deliberately break the rules** — issue malformed SETUP
packets, mismatched lengths, illegal PIDs, babble, toggle desync — and faithfully
record what the device does in response (including errors a normal host hides).

This is the **library API** (`usbmagic::host`). It is backed today by a software
[`MockHost`](../src/mock.rs); the real USB-2.0 host gateware (Plane A) and a
`usbmagic host` CLI come later. The data path needs a real data USB-C cable on the
Cynthion TARGET port.

## Communicate & analyze

```rust
use usbmagic::{UsbHost, UsbForensics};
use usbmagic::mock::MockHost;

let mut host = MockHost::new();
host.set_vbus(true)?;
let dev = host.enumerate()?;                 // reset + address + device descriptor
let model = host.examine(dev.address)?;      // full analysis -> UsbDeviceModel
println!("{:04x}:{:04x}", model.device_descriptor.vendor_id, model.device_descriptor.product_id);
for cfg in &model.configurations {
    for iface in &cfg.interfaces {
        println!("interface class {:#04x}, {} endpoints", iface.descriptor.class, iface.endpoints.len());
    }
}
# Ok::<(), usbmagic::Error>(())
```

- `examine(addr) -> UsbDeviceModel` reads the device descriptor, every configuration
  (interfaces, endpoints, class-specific descriptors preserved as raw), and the
  referenced string descriptors. **Lenient**: truncated/odd descriptors are recorded in
  `UsbDeviceModel::anomalies` rather than aborting.
- Lower-level: `get_descriptor`, `get_string`, `read_configuration`, and
  `control_transfer` / `transfer` / `raw_transaction`.
- `poll_events()` drains the timestamped `WireEvent` log — what actually crossed the bus.

## Breaking the rules

Three escalating layers, all on `UsbHost` + the `UsbForensics` extension trait
(available on any `UsbHost` via a blanket impl). `Setup` already lets you craft any 8
SETUP bytes (illegal `bmRequestType`, reserved `bRequest`, absurd `wLength`); the layers
below add **stage-level** and **wire-level** violations.

### Layer 1 — `control_raw(addr, setup: [u8;8], data_out, ControlForensics)`

| `ControlForensics` field | Effect | A compliant host… |
|---|---|---|
| `data_len_override: Some(n)` | clock `n` data bytes regardless of `wLength` | moves exactly `wLength` |
| `skip_status` | omit the status stage | always closes with a status stage |
| `status_wrong_dir` | drive status IN where OUT is required (or vice-versa) | uses the spec direction |
| `flags: TxFlags` | apply wire violations (below) to the data stage | sends clean packets |

### Layer 2 — `TxFlags` on `RawTransaction` / `control_raw`

| Flag | Effect |
|---|---|
| `no_retry` | report the first result, never retry NAK/timeout |
| `corrupt_crc` / `no_crc` | bad / absent data CRC16 |
| `crc5_error` | bad token CRC5 |
| `bad_pid_check` | wrong PID check nibble (illegal packet) |
| `force_toggle` / `force_data_pid` | force DATA0/DATA1 (or any data PID) regardless of toggle |
| `extra_bytes: n` | append `n` junk bytes (babble / over-max packet) |
| `truncate` | drop the last data byte (runt/short packet) |

### Layer 3 — named recipes (`UsbForensics`)

Thin, discoverable wrappers over the above so intent is explicit at the call site:

| Method | Violation |
|---|---|
| `get_descriptor_oversized(addr, type, idx, claim_len)` | request far more than exists |
| `setup_length_mismatch(addr, setup, data, actual_len)` | data stage disagrees with `wLength` |
| `setup_wrong_direction(addr, setup, data)` | status stage in the wrong direction |
| `control_without_status(addr, setup, data)` | control transfer with no status stage |
| `raw_setup(addr, [u8;8])` | any SETUP verbatim (illegal type/request/recipient) |
| `talk_to_unassigned(addr, ep)` | address/endpoint that shouldn't answer |
| `toggle_desync(addr, ep, data, pid)` | force a wrong data toggle |
| `babble(addr, ep, data, extra)` | packet longer than the endpoint max |
| `bad_pid(addr, ep, pid)` | token with a corrupted PID check nibble |

```rust
use usbmagic::{UsbHost, UsbForensics, host::descriptor_type};
use usbmagic::mock::MockHost;

let mut host = MockHost::new();
host.set_vbus(true)?;
host.enumerate()?;

// Ask for 4 KiB of an 18-byte descriptor; record what really came back.
let r = host.get_descriptor_oversized(1, descriptor_type::DEVICE, 0, 4096)?;
assert_eq!(r.data.len(), 18);
assert!(r.errors.iter().any(|e| matches!(e, usbmagic::BusError::ShortPacket)));
# Ok::<(), usbmagic::Error>(())
```

> With `MockHost` these violations produce a modeled result + `BusError` so the API and
> tests are exercised now. The *interesting* answers — how a real device reacts to
> illegal traffic — require the host gateware and a data cable; the API is identical.
