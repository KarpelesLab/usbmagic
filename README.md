# usbmagic

A Rust library and CLI for working with **magic USB ports** — programmable USB
test instruments that can observe or shape USB traffic. The first supported
device is the [Cynthion](https://greatscottgadgets.com/cynthion/) from Great
Scott Gadgets running the *USB Analyzer* gateware (USB ID `1d50:615b`), which
passively captures Low/Full/High-speed USB 2.0 traffic flowing through its
TARGET ports.

Built on [`nusb`](https://docs.rs/nusb) (pure-Rust USB, no libusb).

## Install / build

```sh
cargo build --release
# binary at target/release/usbmagic
```

### USB permissions (Linux)

Capture needs read/write access to the device node. The simplest fix is to be in
the group that owns `/dev/bus/usb/*` (often `usb` or `plugdev`), or install a
udev rule:

```
# /etc/udev/rules.d/55-cynthion.rules
SUBSYSTEM=="usb", ATTRS{idVendor}=="1d50", ATTRS{idProduct}=="615b", MODE="0660", TAG+="uaccess"
```

Then `sudo udevadm control --reload && sudo udevadm trigger`.

## CLI usage

```sh
# List connected magic USB devices
usbmagic list

# Show device details, supported speeds, gateware version, and live state
usbmagic info

# Capture to a Wireshark-readable pcap for 5 seconds
usbmagic capture --speed auto --duration 5 --output capture.pcap

# Capture 100 packets, printing a summary to the terminal (no file)
usbmagic capture --speed high --count 100

# Stream pcap to stdout into Wireshark
usbmagic capture -o - | wireshark -k -i -
```

When more than one device is present, select one with `--device <serial>` (matches
any device whose serial number contains the string).

The pcap output uses link type `LINKTYPE_USB_2_0` (288) with nanosecond
timestamps, so files open directly in Wireshark, `tshark`, and Packetry.

> **Note:** the analyzer is *passive*. Meaningful packets appear only when there
> is USB traffic between a host and a device connected across the Cynthion's
> TARGET-A and TARGET-C ports. With nothing attached, a capture will simply wait.

## Library usage

```rust
use usbmagic::{discover, CaptureData, CaptureOptions, Speed};

let mut dev = discover()?.into_iter().next().expect("a device").open()?;
println!("speeds: {:?}", dev.capabilities().supported_speeds);

let opts = CaptureOptions { speed: Speed::Auto, ..Default::default() };
for item in dev.start_capture(opts)?.take(10) {
    let item = item?;
    match item.data {
        CaptureData::Packet(bytes) => println!("{} ns: packet {} B", item.timestamp_ns, bytes.len()),
        CaptureData::Event(code) => println!("{} ns: event {code:#04x}", item.timestamp_ns),
    }
}
# Ok::<(), usbmagic::Error>(())
```

### Host / PD / power capability traits (in progress)

Toward the forensics-host goal (see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)), the
crate defines capability traits independent of the analyzer:

- `host::UsbHost` — drive a downstream device: `set_vbus`, `bus_reset`, `control_transfer`,
  `transfer`, `enumerate`, and the forensic `raw_transaction` (emit non-compliant traffic)
  + a `poll_events` wire log.
- `pd::PowerDelivery` — CC status, VCONN, raw PD message/VDM send/recv, controller registers.
- `power::PowerMonitor` — per-port VBUS voltage/current.

These have **no gateware yet**, but a `mock::MockHost` implements all three against a
simulated device so host-side code can be built and tested today:

```rust
use usbmagic::{mock::MockHost, UsbHost};

let mut host = MockHost::new();
host.set_vbus(true)?;
let dev = host.enumerate()?; // reset → addr 0 desc head → SET_ADDRESS → full descriptor
println!("{:04x}:{:04x}", dev.device_descriptor.vendor_id, dev.device_descriptor.product_id);
# Ok::<(), usbmagic::Error>(())
```

The CONTROL-port wire protocol that real gateware will speak is drafted in
[docs/PROTOCOL.md](docs/PROTOCOL.md).

### Flashing gateware

The FPGA gateware is built in a separate repo,
[`KarpelesLab/usbmagic-gateware`](https://github.com/KarpelesLab/usbmagic-gateware)
(Amaranth + Docker + CI). Its released `.bit` is vendored here under `firmware/` via
Git LFS (`scripts/pull-gateware.sh`), and `usbmagic` flashes it to the board itself over
the Apollo interface — no Python tooling:

```sh
usbmagic flash                 # flash the vendored bitstream to FPGA SRAM
usbmagic flash --bit x.bit --persistent   # program SPI flash from a specific file
```

Board-mode detection (Apollo `1d50:615c` vs running gateware `1d50:615b`) works today;
the bitstream-programming protocol port is in progress.

### Adding a backend

Devices are abstracted by the `MagicDevice` trait and registered as a `Backend`
in `src/backend`. To support another device, implement `Backend` (recognize it
by USB descriptors, open it, return a `MagicDevice`) and add it to `BACKENDS`.

## Attribution & license

Licensed under the **BSD 3-Clause License** (see [`LICENSE`](LICENSE)).

The Cynthion control protocol (vendor requests and the State register layout),
the captured-record stream format, and the clock-to-nanoseconds conversion are
derived from Great Scott Gadgets' [Packetry](https://github.com/greatscottgadgets/packetry)
(BSD-3-Clause, Copyright © 2022–2024 Great Scott Gadgets). Their copyright is
retained in `LICENSE` as required.

## Roadmap

The larger goal is a **professional USB forensics instrument** that uses the Cynthion as
a **USB 2.0 host** — driving a device under test directly so it never appears to the
operator's OS — with custom Power Delivery (PD) messaging and first-class handling of
non-compliant / broken USB exchanges. This requires custom LUNA/Amaranth FPGA gateware.

See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** for the full architecture and phased
roadmap. In short:

- **Now:** USB 2.0 analyzer capture (this crate).
- **Next:** custom gateware host controller (FS/LS → HS), Rust host stack, fault
  injection, PD plane (TARGET-C / AUX, incl. VCONN), power telemetry (PAC1954).
- **Deferred:** USB 3.0 / SuperSpeed — **not possible on Cynthion hardware** (no
  SuperSpeed routing); revisit on SS-capable hardware.
