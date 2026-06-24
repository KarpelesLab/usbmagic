<!-- SPDX-License-Identifier: BSD-3-Clause -->
# PD wire tracing

`usbmagic` records every Power Delivery message it sends or receives. The trace
is always pretty-printed to the console (with a direction arrow, running index,
timestamp, decoded name, header and raw hex); pass `--dump <file.pcapng>` to also
write a **pcapng** capture for offline analysis.

## Commands that trace

- `usbmagic pd-listen --port <target-c|aux> [--dump f.pcapng]` — present a sink and
  record what a source sends.
- `usbmagic pd-source --port <target-c|aux> [--dump f.pcapng]` — present a source,
  advertise `Source_Capabilities`, record replies.
- `usbmagic pd-send …` — send arbitrary message(s) and record the whole exchange.

## Sending custom PD

`pd-send` is device-agnostic: it sends whatever you specify. Two ways to specify a
message (you can combine; raw messages are sent first, then the VDM):

```sh
# Raw PD message: full bytes, 16-bit header first (little-endian), then data objects.
usbmagic pd-send --port target-c --raw 6111c0901 --dump /tmp/pd.pcapng

# Structured Vendor-Defined Message (header/role/SpecRev filled in for you):
usbmagic pd-send --port target-c \
    --vdm --svid 0x05ac --command 1 --vdm-type req \
    --vdo 0x12345678 -t 3 --dump /tmp/pd.pcapng
```

Useful flags:

- `--role source|sink|raw` — PHY role to present first (default `source`).
- `--vbus auto|aux|control|none` — for a source on TARGET-C the device needs VBUS;
  `auto` routes an **AUX** supply if one is present, otherwise falls back to
  **CONTROL/host 5 V** (lower power). Always 5 V, never both rails at once.
- `--negotiate` — run an explicit source contract (`Source_Capabilities` → wait for
  `Request` → `Accept` → `PS_RDY`) before sending; some partners only accept VDMs
  inside an explicit contract.
- `--header 0xNNNN` — override the 16-bit PD message header for the VDM verbatim
  (forensics: lets you craft non-compliant/illegal combinations).
- `-t <secs>` — how long to keep tracing replies after the last send.

The header override and `--raw` exist so the tool can emit deliberately malformed
or unusual traffic — a requirement for forensic work — without baking any
device-specific knowledge into the tool.

## The pcapng format

Files use a purpose-defined link type, **`LINKTYPE_USB_TYPE_C_PD`** (provisional
number **304**), proposed per
[libpcap issue #1036](https://github.com/the-tcpdump-group/libpcap/issues/1036).
Each packet is an 8-byte pseudo-header (version, SOP type, direction, flags with
CC polarity + CRC presence, crc32) followed by the PD message exactly as in §6.2
"Messages" of the USB-PD spec. The pseudo-header is specified in
[`docs/linktypes/LINKTYPE_USB_TYPE_C_PD.html`](linktypes/LINKTYPE_USB_TYPE_C_PD.html).

The two Cynthion ports map to pcapng interfaces: **interface 0 = TARGET-C,
interface 1 = AUX**, so the port is encoded by the packet's interface id and the
pseudo-header stays instrument-agnostic. Timestamps are microseconds since the
Unix epoch.

> The Cynthion's FUSB302B controllers check/append the CRC in hardware, so the
> on-wire CRC octets aren't exposed; captured frames clear `CRC_PRESENT`.

### Reading a trace back

Since no Wireshark dissector exists for this link type yet, `usbmagic pd-dump`
decodes our pcapng files directly:

```sh
usbmagic pd-dump /tmp/pd.pcapng          # decoded, human-readable
usbmagic pd-dump /tmp/pd.pcapng --hex    # also show the raw link-layer bytes
```

It lists the interfaces (ports) and prints each message with its direction,
relative timestamp, decoded name/header, the port, SOP type, CC line, and CRC
status — e.g.:

```
#1   [  0.000s] TX -> Vendor_Defined       hdr=0x116f obj=1 raw=6f110180ac05
       port=TARGET-C sop=SOP cc1 crc=n/a (hw AUTO_CRC)
```

### Opening in Wireshark

There is no USB-PD dissector keyed on this (still-unallocated) link type yet, so
Wireshark will parse the pcapng container and show the per-packet bytes but won't
dissect the PD fields automatically. Until the link type is allocated and a
dissector exists, either read the bytes directly (the pseudo-header layout is
above) or map the capture to a `DLT_USERn` with a custom Lua/`user_dlts` dissector.

### Upstreaming (future)

To make this a real, portable link type, the next steps (out of scope here) are a
pull request to [tcpdump-htdocs](https://github.com/the-tcpdump-group/tcpdump-htdocs)
adding the `LINKTYPE_USB_TYPE_C_PD` entry to `linktypes.html` (linking to the
pseudo-header description we ship in `docs/linktypes/`), and the corresponding
`DLT_`/`LINKTYPE_` definitions in libpcap.
