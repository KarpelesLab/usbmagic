# usbmagic host command protocol (v0, provisional)

> Status: **design draft.** This defines the wire protocol between the Rust host
> (`usbmagic` crate) and the **host-mode gateware** over the Cynthion CONTROL
> port. It mirrors the Rust capability traits in `src/host`, `src/pd`, `src/power`
> and will be refined as the gateware is built. The existing **analyzer** gateware
> (`1d50:615b`) keeps its own simpler protocol (vendor requests 0–4); this is a
> separate, richer interface used only by the host gateware.

All multi-byte integers are **little-endian** unless stated otherwise.

## 1. Transport & endpoints

The host gateware presents a vendor-specific interface on the CONTROL port with:

| Endpoint | Dir | Purpose |
|---|---|---|
| EP0 control | — | Enumeration + a few management vendor requests (§2) |
| Bulk `0x02` | OUT | Command frames (host → gateware) |
| Bulk `0x81` | IN | Response frames (gateware → host) |
| Bulk `0x83` | IN | Asynchronous **wire-event / log stream** (§6) |

Commands are request/response and **sequenced** so multiple may be in flight.
The event stream is independent and free-running once capture/host is enabled.

## 2. Management vendor requests (EP0)

Vendor-type, recipient Interface (same shape this crate already uses for the
analyzer). Used for bring-up before the bulk channel is active:

| `bRequest` | Dir | Meaning |
|---|---|---|
| `0x00` GET_PROTOCOL_VERSION | IN | returns `u16` major, `u16` minor |
| `0x01` GET_CAPABILITIES | IN | bitfield: host, pd(target-c), pd(aux), power-monitor, … |
| `0x02` RESET_CORE | OUT | reset the host core to a known idle state |

Everything else goes through the bulk command channel.

## 3. Command frame (Bulk OUT `0x02`)

```
offset  size  field
0       1     opcode        (see §5)
1       1     flags         (bit0 = expects response; bit1 = forensic/raw)
2       2     seq           (echoed in the response)
4       2     length        (payload byte count)
6       N     payload       (opcode-specific, §5)
```

## 4. Response frame (Bulk IN `0x81`)

```
offset  size  field
0       2     seq           (matches the command)
2       1     status        (0 = OK; see §4.1)
3       1     reserved
4       8     start_ns/dur  (u32 start_ns_lo, u32 duration_ns — bus timing, where relevant)
12      2     length        (payload byte count)
14      M     payload       (opcode-specific)
```

### 4.1 Status codes

`0` OK · `1` STALL (device STALLed) · `2` TIMEOUT · `3` NAK · `4` BAD_CRC ·
`5` BABBLE · `6` OVERFLOW · `7` UNSUPPORTED · `8` BAD_ARG · `0xFF` INTERNAL.

Bus anomalies that are not fatal (e.g. a CRC error captured in forensic mode)
are reported both here and, in full detail, on the event stream (§6) — the host
**never silently drops** them.

## 5. Opcodes

Grouped by plane. Payloads map 1:1 onto the Rust trait methods.

### 5.1 Host plane (`0x10`–`0x1F`) → [`crate::host::UsbHost`]

| Opcode | Name | Payload (OUT) | Response payload (IN) |
|---|---|---|---|
| `0x10` SET_VBUS | `u8 on` | — |
| `0x11` PORT_STATUS | — | `u8 flags, u8 speed, u32 vbus_mv` |
| `0x12` BUS_RESET | — | `u8 speed` (0xFF = none) |
| `0x13` CONTROL_TRANSFER | `u8 address, u8[8] setup, data_out…` | IN data… |
| `0x14` TRANSFER | `u8 address, u8 ep, u8 dir, u16 max_len, data…` | `u8 handshake, data…` |
| `0x15` RAW_TRANSACTION | `u8 pid, u8 address, u8 ep, u8 tx_flags, u8 toggle, data…` | `u8 handshake, data…` |

`speed`: `0`=auto/unknown, `1`=low, `2`=full, `3`=high.
`tx_flags` bits: `0` no_retry, `1` corrupt_crc, `2` no_crc, `3` force_toggle_valid,
`4` force_toggle_value. `pid` is the 4-bit PID value. The forensic fields let the
host emit deliberately non-compliant traffic — this is the point of the tool.

### 5.2 PD plane (`0x20`–`0x2F`) → [`crate::pd::PowerDelivery`]

`port`: `0`=TARGET-C, `1`=AUX.

| Opcode | Name | Payload (OUT) | Response payload (IN) |
|---|---|---|---|
| `0x20` CC_STATUS | `u8 port` | `u8 flags (attached/orientation/vconn/source)` |
| `0x21` SET_VCONN | `u8 port, u8 on` | — |
| `0x22` PD_SEND | `u8 port, msg_bytes…` | — |
| `0x23` PD_RECV | `u8 port, u16 timeout_ms` | `msg_bytes…` (empty = none) |
| `0x24` CTRL_READ | `u8 port, u8 reg` | `u8 value` |
| `0x25` CTRL_WRITE | `u8 port, u8 reg, u8 value` | — |

`msg_bytes` are the raw PD message (16-bit header first, then 32-bit data
objects, little-endian) — exactly [`crate::pd::PdMessage::raw`]. VDMs are sent via
`PD_SEND` with a VDM-shaped payload (see [`crate::pd::Vdm`]).

### 5.3 Power plane (`0x30`–`0x3F`) → [`crate::power::PowerMonitor`]

| Opcode | Name | Payload (OUT) | Response payload (IN) |
|---|---|---|---|
| `0x30` READ_PORT | `u8 port` | `u32 voltage_mv, i32 current_ma` |
| `0x31` READ_ALL | — | `4 × (u32 voltage_mv, i32 current_ma)` |

`port`: `0`=control, `1`=aux, `2`=target-a, `3`=target-c.

## 6. Wire-event / log stream (Bulk IN `0x83`)

Reuses the analyzer's record framing (16-bit-aligned, 60 MHz timestamp deltas)
extended with host-side event records, so existing timestamp handling
([`clk_to_ns`]) and pcap export still apply. Each record:

```
offset  size  field
0       1     record_type   (0xF0–0xFF = host event; otherwise a captured packet length hi byte, as in the analyzer)
1       1     subtype/code
2       2     cycle_delta   (big-endian, 60 MHz, as analyzer)
4       …     record-specific
```

Host event subtypes (`record_type = 0xF0`):

| code | event |
|---|---|
| `0x01` | bus reset |
| `0x02` | connect (next byte = speed) |
| `0x03` | disconnect |
| `0x04` | suspend |
| `0x05` | resume |
| `0x06` | SOF (next 2 bytes = frame number) |
| `0x10` | handshake (next byte = handshake code) |
| `0x20` | bus error (next byte = [`crate::host::BusError`] code) |

Captured packets that traversed the bus are emitted using the **same packet
record format as the analyzer** (length + payload), so a host session produces a
wire log indistinguishable in format from an analyzer capture — the host is its
own analyzer. These map to [`crate::host::WireEvent`] on the Rust side.

## 7. Versioning

The host negotiates with GET_PROTOCOL_VERSION (§2) at open. Minor versions add
opcodes/fields; major versions may change frame layout. The Rust side refuses a
major version it does not implement and degrades features by GET_CAPABILITIES.
