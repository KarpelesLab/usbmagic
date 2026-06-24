# usbmagic — Host & Forensics Architecture

> Status: **design / roadmap** (no gateware or host-mode code written yet).
> This document is the plan we agreed to produce before bootstrapping any toolchain.

## 1. Vision

`usbmagic` is to become a **professional-grade USB forensics instrument** built on the
Great Scott Gadgets **Cynthion**, where:

- The **Cynthion acts as the USB host** — it sources VBUS, resets the bus, generates
  SOF, and drives the device under test (DUT) directly.
- The DUT connects to a Cynthion **TARGET** port and is therefore **invisible to the
  operator's operating system** — only the Cynthion itself appears on the operator's
  USB bus (over the CONTROL port). No kernel driver on the operator machine ever
  touches the DUT.
- A **Rust core** (this crate) is the host stack and policy engine: enumeration,
  control/bulk/interrupt transfers, **custom USB Power Delivery (PD)** messaging, and
  power telemetry.
- **Non-compliant / broken protocol exchanges are first-class.** The instrument can
  *deliberately emit* malformed traffic and *faithfully record* malformed responses,
  timeouts, and bus errors — never silently "fixing" or dropping anomalies.

### Scope of speeds

- **In scope now:** USB 2.0 — Low (1.5 Mbit/s), Full (12), High (480) — host mode on
  the Cynthion.
- **Out of scope on the Cynthion:** USB 3.0 / SuperSpeed. The board's USB-C SuperSpeed
  pairs are **not routed to the FPGA SERDES** and its PHYs are 480 Mbit/s max. SuperSpeed
  is deferred to SS-capable hardware later (see §10). The architecture keeps a
  **speed/PHY abstraction** so a SuperSpeed backend can be added without rework.

## 2. Verified hardware capabilities (ground truth)

| Component | Detail | Implication for this project |
|---|---|---|
| FPGA | Lattice **LFE5U-12F** (ECP5), yosys+nextpnr flow | Custom gateware via the open ECP5 toolchain |
| USB 2.0 PHYs | 3× **USB3343** ULPI, **480 Mbit/s** max, host-capable | USB 2.0 LS/FS/HS **host** is electrically possible; **no** USB 3.0 |
| USB-C SuperSpeed | SS pairs **not** routed to ECP5 SERDES | USB 3.0 **impossible** on this board |
| Type-C / PD | Type-C controller on **TARGET-C** + **AUX**, **bidirectional PD** on CC pins, **VCONN output** (per GSG; FUSB302B-class, I2C) | **Custom PD / CC messaging is feasible** (BMC in silicon); can power+interrogate **e-marked cables** via VCONN |
| Power monitor | **PAC1954** 4-channel V/I monitor (I2C) | Per-port VBUS voltage/current telemetry for forensics |
| Debug controller | **Apollo** MCU (USB `1d50:6018`) configures the FPGA | Gateware load/flash path |
| Analyzer gateware | USB Analyzer (`1d50:615b`), already supported by this crate | Reuse its ULPI/UTMI + timestamping primitives |

> **To confirm from the KiCad schematics** (`type_c`, `usb_phy`, `power_distribution`,
> `power_supplies`) before Phase 1: exact TARGET-A/TARGET-C/AUX/CONTROL port roles and
> pass-through wiring; whether the **FPGA or the Apollo MCU owns the I2C buses** to the
> FUSB302B and PAC1954; VBUS load-switch control nets; D±​ pulldown handling in host mode.

## 3. System architecture

Three functional **planes**, all surfaced to the Rust core over the CONTROL port:

```
        operator host (Linux)
              │  CONTROL (USB 2.0)  ── command protocol + event/wire-log stream
              ▼
   ┌─────────────────────────────────────────────┐
   │  Cynthion ECP5 (custom usbmagic gateware)     │
   │                                               │
   │  command mux / endpoints                      │
   │    ├── (A) USB 2.0 HOST controller core ──ULPI┼──► USB3343 ──► [ DUT D+/D- ]   TARGET
   │    ├── (B) I2C master ──► Type-C ctrl (PD) ───┼──► [ DUT CC1/CC2 ] + VCONN  (TARGET-C, AUX)
   │    ├── (C) I2C master ───────────────────────┼──► PAC1954  (per-port VBUS V/I)
   │    └── VBUS load-switch control ─────────────┼──► [ DUT VBUS ]
   │                                               │
   │  global 60 MHz timestamp (shared by all)      │
   └─────────────────────────────────────────────┘
```

- **(A) USB 2.0 host plane** — the hard core (see §4).
- **(B) PD / CC plane** — drive the Type-C controller over I2C for **bidirectional PD**
  on the CC pins (TARGET-C and AUX); PD policy engine in Rust/firmware. Includes
  **VCONN output** control, enabling power + interrogation of electronically-marked cables.
- **(C) Telemetry plane** — PAC1954 power readings + a unified timestamped event log.

The DUT is **only** ever connected to a TARGET port; the operator OS sees just the
Cynthion on CONTROL, so the DUT is structurally invisible to it.

## 4. The USB 2.0 host controller (the hard core)

**Design principle — forensics first, compliance optional.** Off-the-shelf host IP
assumes spec-compliant behavior and will mask the very anomalies a forensics tool exists
to find. So we build our own transaction engine that can both behave correctly *and*, on
demand, violate the spec and record violations.

Layered design:

- **L0 — PHY / link.** ULPI link to the USB3343 (reuse LUNA's ULPI PHY + UTMI translator;
  these are byte-level and role-agnostic). Host-side responsibilities: enable VBUS,
  drive bus **reset** (SE0), **speed detection** (LS/FS via line state; HS via the host
  side of chirp K/J), suspend/resume.
- **L1 — packet.** SYNC/EOP framing (in PHY), PID generation/checking, **CRC5** (tokens)
  and **CRC16** (data). Every check has a **raw/bypass path** so we can emit bad CRCs,
  illegal PIDs, wrong lengths, etc.
- **L2 — transaction.** Token issuance (SETUP/IN/OUT/SOF), **DATA0/DATA1 toggle** per
  endpoint, handshake handling (ACK/NAK/NYET/STALL/none), bus-turnaround timeout, and
  **configurable retries** (including a forensic "no retry / report exactly what
  happened" mode).
- **L3 — scheduler.** **SOF generation** (1 ms FS frame / 125 µs HS microframe) with a
  frame counter. Start with single-transaction-at-a-time; grow to a frame scheduler with
  periodic (interrupt/iso) budgeting later.
- **Capture-everything.** Every bus event (token, data, handshake, timeout, error,
  line-state change) is **timestamped on the 60 MHz clock** (reuse the analyzer's
  `clk_to_ns`) and streamed to the Rust core. The host is therefore also its own
  analyzer — we always see exactly what hit the wire, compliant or not.

**Reuse vs build.** Reuse LUNA's ULPI/UTMI, CRC, and SYNC primitives. Study (do not
directly port) existing FS/LS host FSMs such as Ultra-Embedded's `core_usb_host` as a
reference for the transaction state machine; our engine must add deliberate
non-compliance and full observability, which compliance cores lack.

**Speed phasing.** FS/LS host first (12/1.5 Mbit/s, no chirp) → HS host (adds chirp
negotiation, microframes, higher clocking, and the known **FIFO-overrun pressure** at
HS bulk rates — a real risk to budget for).

## 5. Control / command protocol (CONTROL port)

Two designs, chosen pragmatically:

- **(a) Fixed-function gateware + vendor control/bulk** — exactly the style this crate
  already speaks to the analyzer (vendor requests + bulk endpoints). Lean, fast to bring
  up, ideal for Phases 1–4.
- **(b) RISC-V SoC** (`luna-soc`) running firmware exposing a richer RPC, like Moondancer
  / libgreat. More flexible for complex sequencing and the PD policy engine; heavier.

**Plan:** start with (a) and a thin command set; migrate hot/complex logic into a SoC (b)
if/when needed. The **Rust-facing API stays stable** regardless of which side logic lives.

Indicative command surface:

- *Host plane:* `set_speed`, `set_vbus`, `bus_reset`, `port_status`,
  `submit_transaction{ addr, ep, pid, data, flags(raw|no_crc|no_retry|expect…) }`
  → `{ handshake, data, timing, errors }`; plus a **timestamped wire-event stream**.
- *PD plane:* raw Type-C-controller register/FIFO passthrough **and** higher-level
  `pd_send_message` / `pd_recv` (incl. VDM / vendor-defined messages), `vconn_enable`,
  `cc_status`, and e-marked-cable interrogation (TARGET-C and AUX).
- *Telemetry:* `power_read{ port }` (PAC1954 V/I).

## 6. Rust core evolution (this crate)

Keep the existing `Backend` / `MagicDevice` abstraction; add capability traits the
Cynthion backend implements once the gateware exists:

- `UsbHost` — `enumerate`, `control_transfer`, `bulk`/`interrupt`, `raw_transaction`,
  `bus_reset`, `set_vbus`, wire-event stream.
- `PowerDelivery` — `send`/`recv` PD messages (bidirectional), VDMs, request power,
  CC/orientation status, **VCONN control**, and e-marked-cable interrogation
  (TARGET-C and AUX ports).
- `PowerMonitor` — per-port voltage/current.

Forensics features layered on top:

- **Full wire log** (extend pcap or a custom container) — every event, timestamped.
- **Fault injection API** — malformed transfers, bad CRCs, illegal sequences.
- **Tolerant enumeration** — continue through errors, record everything, handle
  deliberately-broken / non-compliant devices.
- **Deterministic, replayable** command/event logs; scriptable transaction sequences.
- **Audited power/reset control** — VBUS and reset are explicit, logged (with PAC1954
  V/I), and mode-gated (read-only vs active).
- *(Optional, later)* a **libusb-compatible shim** so existing tools can drive a DUT
  through the Cynthion host.

Until gateware exists, the Rust host stack is developed against (i) an **Amaranth/cocotb
simulation** of the gateware and (ii) a **software mock** of the command protocol.

## 7. Forensic design tenets

1. Never silently fix or drop anomalies — record and surface them.
2. One monotonic, high-resolution FPGA timebase across all planes.
3. Deterministic, replayable logs.
4. Explicit, audited, logged power/reset actions.
5. Strict isolation: the DUT is never enumerated by the operator OS.

## 8. Roadmap (phased, with go/no-go gates)

> **Phase 0 — Toolchain & bring-up pipeline** *(deferred per your call; do when greenlit)*
> oss-cad-suite (yosys + nextpnr-ecp5 + prjtrellis) + a Python venv with
> amaranth/luna/luna-soc/apollo/cynthion. Build & flash a trivial heartbeat bitstream.
> **Gate:** we can flash our own bitstream to this board via Apollo.

- **Phase 1 — Host PHY bring-up.** Drive a TARGET USB3343 in host mode over ULPI;
  enable VBUS; detect device attach (line state), issue bus reset, detect LS/FS.
  **Gate:** a DUT powers up; attach + reset visible in the wire log.
- **Phase 2 — FS/LS transaction engine.** SOF gen, SETUP/IN/OUT, toggle, handshakes,
  CRC. Enumerate a real FS device from Rust (Get Device Descriptor → Set Address →
  Get Config → Set Config). **Gate:** full enumeration, DUT invisible to operator OS.
- **Phase 3 — Forensic fault injection + tolerant mode.** Raw/malformed transactions,
  no-CRC / no-retry, anomaly capture; survive non-compliant devices. **Gate:** inject a
  bad-CRC SETUP and record the device's behavior; enumerate a deliberately-broken device.
- **Phase 4 — HS host.** Host-side chirp negotiation, microframe SOF, HS data, FIFO /
  throughput management. **Gate:** enumerate + bulk-read a HS device.
- **Phase 5 — PD plane.** Type-C-controller I2C driver; bidirectional PD message TX/RX;
  custom VDM / vendor messages; CC/orientation status; power request; **VCONN** control.
  **Gate:** send a custom PD/VDM to a PD-capable DUT and capture the response; power an
  e-marked cable over VCONN and read its identity.
- **Phase 6 — Telemetry + forensics UX.** PAC1954 power logging; unified timestamped
  event log; replay; scripting API; (optional) libusb shim.
- **Phase 7 — USB 3.0 (future, different hardware).** SuperSpeed host on SS-capable
  hardware (ECPIX-5-class), reusing the speed/PHY abstraction. Note: a SuperSpeed *host*
  in open gateware is essentially frontier R&D.

Each phase ships in both repos (gateware + Rust) with tests: Amaranth simulation /
cocotb for gateware, Rust unit + hardware-in-the-loop.

## 9. Repositories & layout

- **`usbmagic`** (this repo, Rust) — host-side forensics core, backends, protocol
  clients, CLI/TUI.
- **`usbmagic-gateware`** (new, Amaranth/Python) — host controller core, I2C masters,
  command interface, optional SoC. Depends on LUNA. Sibling repo or submodule.
- **`docs/`** — this document, protocol specs, hardware notes.

## 10. Major risks & unknowns

- HS host timing on the ECP5 + the known **FIFO-overrun** at HS bulk rates.
- USB3343 **host-mode** register configuration quirks; VBUS sourced via external load
  switch (not the PHY); D±​ pulldown handling.
- **I2C bus ownership** (FPGA vs Apollo MCU) for FUSB302B / PAC1954 — confirm from schematic.
- **Single board:** limited independent verification of the host's wire output (mitigate
  with the built-in wire log, simulation, or a second Cynthion in analyzer mode).
- A SuperSpeed **host** in gateware (Phase 7) has little/no public prior art.
- Effort: multi-month, multi-discipline (FPGA + embedded + Rust).

## 11. Immediate next steps (when greenlit)

1. Pull the Cynthion KiCad schematics and confirm port roles + I2C ownership + VBUS nets.
2. Phase 0: bootstrap oss-cad-suite + Python venv.
3. Flash a heartbeat bitstream to validate build → Apollo → FPGA on this board.
