//! `usbmagic` command-line tool: list, inspect, and capture from magic USB ports.

use std::io::{BufWriter, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};

use usbmagic::pcap::PcapWriter;
use usbmagic::pcapng::{IfaceDesc, PcapNgWriter};
use usbmagic::{discover, CaptureData, CaptureOptions, MagicDevice, PdMessage, PdTrace, Speed, Vdm};

#[derive(Parser)]
#[command(
    name = "usbmagic",
    version,
    about = "Work with magic USB ports (Great Scott Gadgets Cynthion USB analyzer)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List connected magic USB devices.
    List,
    /// Show details and current state of a device.
    Info(DeviceSel),
    /// Capture USB traffic from a device.
    Capture(CaptureArgs),
    /// Flash gateware to the Cynthion's FPGA (over Apollo).
    Flash(FlashArgs),
    /// Connect to the Cynthion's Apollo debugger (identity, firmware, reconfigure).
    Apollo(ApolloArgs),
    /// Flash the PD-bridge gateware and probe its registers (FUSB302B I2C lines).
    PdProbe,
    /// Flash the PD bridge, set the FUSB302B as a sink, and decode PD messages
    /// from a source on TARGET-C.
    PdListen(PdListenArgs),
    /// Act as a PD source: advertise Source_Capabilities to a consumer on
    /// TARGET-C and decode its replies.
    PdSource(PdListenArgs),
    /// Send custom PD message(s) — raw bytes and/or a structured VDM — to a
    /// device, tracing the full bidirectional exchange.
    PdSend(PdSendArgs),
    /// Decode a pcapng PD trace (LINKTYPE_USB_TYPE_C_PD) into human-readable form.
    PdDump(PdDumpArgs),
    /// Charge a device on TARGET-C at 5 V, sourced from a supply on AUX.
    Charge,
}

#[derive(Args)]
struct DeviceSel {
    /// Select a device whose serial number contains this string.
    #[arg(short, long)]
    device: Option<String>,
}

#[derive(Args)]
struct CaptureArgs {
    /// Select a device whose serial number contains this string.
    #[arg(short, long)]
    device: Option<String>,

    /// Capture speed.
    #[arg(short, long, value_enum, default_value_t = SpeedArg::Auto)]
    speed: SpeedArg,

    /// Write a pcap file ("-" for stdout). Without this, packet summaries are printed.
    #[arg(short, long)]
    output: Option<String>,

    /// Stop after this many packets.
    #[arg(short = 'n', long)]
    count: Option<u64>,

    /// Stop after this many seconds.
    #[arg(short = 't', long)]
    duration: Option<f64>,

    /// Drive VBUS through to the target so a bus-powered target powers on (experimental).
    #[arg(long)]
    vbus: bool,

    /// Also report out-of-band events (when writing a pcap they are otherwise hidden).
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Copy, Clone, ValueEnum)]
enum SpeedArg {
    Auto,
    Low,
    Full,
    High,
}

impl From<SpeedArg> for Speed {
    fn from(s: SpeedArg) -> Speed {
        match s {
            SpeedArg::Auto => Speed::Auto,
            SpeedArg::Low => Speed::Low,
            SpeedArg::Full => Speed::Full,
            SpeedArg::High => Speed::High,
        }
    }
}

#[derive(Args)]
struct FlashArgs {
    /// Bitstream file to flash. Defaults to the vendored firmware/*.bit.
    #[arg(long)]
    bit: Option<String>,

    /// Program persistent SPI flash instead of volatile FPGA SRAM.
    #[arg(long)]
    persistent: bool,
}

#[derive(Args)]
struct PdListenArgs {
    /// How long to listen for PD messages, in seconds.
    #[arg(short = 't', long, default_value_t = 5.0)]
    duration: f64,

    /// Which Cynthion Type-C port's FUSB302B to use.
    #[arg(long, value_enum, default_value_t = PortArg::TargetC)]
    port: PortArg,

    /// Also write the full PD trace to this pcapng file (LINKTYPE_USB_TYPE_C_PD).
    #[arg(long)]
    dump: Option<String>,
}

/// Arguments for `pd-send`.
#[derive(Args)]
struct PdSendArgs {
    /// Which Cynthion Type-C port's FUSB302B to use.
    #[arg(long, value_enum, default_value_t = PortArg::TargetC)]
    port: PortArg,

    /// PD PHY role to present before sending.
    #[arg(long, value_enum, default_value_t = RoleArg::Source)]
    role: RoleArg,

    /// How to bring up VBUS on TARGET-C (sources need VBUS to be believed).
    #[arg(long, value_enum, default_value_t = VbusArg::Auto)]
    vbus: VbusArg,

    /// Run an explicit source PD contract (Source_Caps → Accept → PS_RDY) first.
    #[arg(long)]
    negotiate: bool,

    /// A full raw PD message as hex (16-bit header first, little-endian, then data
    /// objects). Repeatable; sent in order. e.g. --raw 6111... .
    #[arg(long = "raw", value_name = "HEX")]
    raws: Vec<String>,

    /// Build and send a structured Vendor-Defined Message.
    #[arg(long)]
    vdm: bool,
    /// VDM Standard-or-Vendor ID (e.g. 0x05ac for Apple).
    #[arg(long, value_parser = parse_u16, requires = "vdm")]
    svid: Option<u16>,
    /// VDM command (bits 0–4 of the VDM header).
    #[arg(long, value_parser = parse_u8, requires = "vdm")]
    command: Option<u8>,
    /// VDM command type.
    #[arg(long = "vdm-type", value_enum, default_value_t = VdmTypeArg::Req)]
    vdm_type: VdmTypeArg,
    /// VDM object position (0 if unused).
    #[arg(long = "obj-pos", value_parser = parse_u8, default_value_t = 0)]
    obj_pos: u8,
    /// Additional Vendor Data Object(s) after the VDM header. Repeatable.
    #[arg(long = "vdo", value_parser = parse_u32)]
    vdos: Vec<u32>,
    /// Override the 16-bit PD message header for the VDM (forensic: any value).
    #[arg(long, value_parser = parse_u16, requires = "vdm")]
    header: Option<u16>,

    /// Seconds to keep tracing replies after the last send.
    #[arg(short = 't', long, default_value_t = 2.0)]
    listen: f64,

    /// Write the full PD trace to this pcapng file (LINKTYPE_USB_TYPE_C_PD).
    #[arg(long)]
    dump: Option<String>,
}

/// Arguments for `pd-dump`.
#[derive(Args)]
struct PdDumpArgs {
    /// The pcapng file to decode.
    file: String,

    /// Also show the raw link-layer bytes (pseudo-header + message) per packet.
    #[arg(long)]
    hex: bool,
}

#[derive(Copy, Clone, ValueEnum)]
enum RoleArg {
    /// Present Rp (we are the power source / DFP).
    Source,
    /// Present Rd (we are the sink / UFP).
    Sink,
    /// Leave the PHY as-is; just transmit.
    Raw,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum VbusArg {
    /// AUX supply if present, else CONTROL/host 5 V.
    Auto,
    /// Only route the AUX supply.
    Aux,
    /// Only route CONTROL/host 5 V.
    Control,
    /// Don't touch VBUS.
    None,
}

#[derive(Copy, Clone, ValueEnum)]
enum VdmTypeArg {
    Req,
    Ack,
    Nak,
    Busy,
}

/// Strip an optional `0x`/`0X` prefix and surrounding whitespace.
fn hex_digits(s: &str) -> &str {
    let s = s.trim();
    s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s)
}
fn parse_u8(s: &str) -> std::result::Result<u8, std::num::ParseIntError> {
    u8::from_str_radix(hex_digits(s), 16)
}
fn parse_u16(s: &str) -> std::result::Result<u16, std::num::ParseIntError> {
    u16::from_str_radix(hex_digits(s), 16)
}
fn parse_u32(s: &str) -> std::result::Result<u32, std::num::ParseIntError> {
    u32::from_str_radix(hex_digits(s), 16)
}

#[derive(Copy, Clone, ValueEnum)]
enum PortArg {
    #[value(name = "target-c")]
    TargetC,
    Aux,
}

impl From<PortArg> for usbmagic::flash::PdLine {
    fn from(p: PortArg) -> Self {
        match p {
            PortArg::TargetC => usbmagic::flash::PdLine::TargetC,
            PortArg::Aux => usbmagic::flash::PdLine::Aux,
        }
    }
}

impl From<PortArg> for usbmagic::PdPort {
    fn from(p: PortArg) -> Self {
        match p {
            PortArg::TargetC => usbmagic::PdPort::TargetC,
            PortArg::Aux => usbmagic::PdPort::Aux,
        }
    }
}

impl From<VbusArg> for usbmagic::VbusSource {
    fn from(a: VbusArg) -> Self {
        match a {
            VbusArg::Auto => usbmagic::VbusSource::Auto,
            VbusArg::Aux => usbmagic::VbusSource::Aux,
            VbusArg::Control => usbmagic::VbusSource::Control,
            VbusArg::None => usbmagic::VbusSource::None,
        }
    }
}

fn port_name(p: PortArg) -> &'static str {
    match p {
        PortArg::TargetC => "TARGET-C",
        PortArg::Aux => "AUX",
    }
}

#[derive(Args)]
struct ApolloArgs {
    /// After reading identity, reconfigure the FPGA from flash (restore gateware).
    #[arg(long)]
    reconfigure: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::List => cmd_list(),
        Command::Info(sel) => cmd_info(sel.device.as_deref()),
        Command::Capture(args) => cmd_capture(args),
        Command::Flash(args) => cmd_flash(args),
        Command::Apollo(args) => cmd_apollo(args),
        Command::PdProbe => cmd_pd_probe(),
        Command::PdListen(args) => cmd_pd_listen(args),
        Command::PdSource(args) => cmd_pd_source(args),
        Command::PdSend(args) => cmd_pd_send(args),
        Command::PdDump(args) => cmd_pd_dump(args),
        Command::Charge => cmd_charge(),
    }
}

/// Open the one selected device, or fail with a helpful message.
fn select(device: Option<&str>) -> Result<Box<dyn MagicDevice>> {
    let mut found = discover().context("enumerating USB devices")?;
    if found.is_empty() {
        bail!("no magic USB devices found");
    }

    if let Some(sel) = device {
        found.retain(|d| {
            d.description()
                .serial
                .as_deref()
                .is_some_and(|s| s.contains(sel))
        });
        match found.len() {
            0 => bail!("no device with serial containing {sel:?}"),
            1 => {}
            n => bail!("{n} devices match serial {sel:?}; be more specific"),
        }
    } else if found.len() > 1 {
        eprintln!("Multiple devices found; select one with --device <serial>:");
        for d in &found {
            print_device_line(d.description());
        }
        bail!("ambiguous device selection");
    }

    found
        .into_iter()
        .next()
        .unwrap()
        .open()
        .context("opening device")
}

fn print_device_line(d: &usbmagic::DeviceDescription) {
    println!(
        "  {:<9} {:04x}:{:04x}  bus {} addr {}{}{}",
        d.backend,
        d.vendor_id,
        d.product_id,
        d.bus_id,
        d.address,
        d.product
            .as_deref()
            .map(|p| format!("  {p}"))
            .unwrap_or_default(),
        d.serial
            .as_deref()
            .map(|s| format!("  [{s}]"))
            .unwrap_or_default(),
    );
}

fn cmd_list() -> Result<()> {
    let devices = discover().context("enumerating USB devices")?;
    if devices.is_empty() {
        println!("No magic USB devices found.");
        return Ok(());
    }
    for d in &devices {
        print_device_line(d.description());
    }
    Ok(())
}

fn cmd_info(device: Option<&str>) -> Result<()> {
    let mut dev = select(device)?;
    let d = dev.description().clone();
    let caps = dev.capabilities().clone();

    println!("Backend:   {}", d.backend);
    println!("USB ID:    {:04x}:{:04x}", d.vendor_id, d.product_id);
    if let Some(p) = &d.product {
        println!("Product:   {p}");
    }
    if let Some(s) = &d.serial {
        println!("Serial:    {s}");
    }
    println!("Bus:       {} addr {}", d.bus_id, d.address);
    let speeds = caps
        .supported_speeds
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    println!("Speeds:    {}", if speeds.is_empty() { "<none>" } else { &speeds });
    if let Some(v) = caps.protocol_version {
        println!("Protocol:  v{v}");
    }
    println!("VBUS ctrl: {}", if caps.can_control_vbus { "yes" } else { "no" });

    match dev.read_state() {
        Ok(s) => println!(
            "State:     capture {}, speed {}{}",
            if s.enable { "ON" } else { "off" },
            s.speed,
            if s.target_c_vbus_en {
                ", target-C VBUS on"
            } else {
                ""
            },
        ),
        Err(e) => println!("State:     <error reading: {e}>"),
    }
    Ok(())
}

fn cmd_capture(args: CaptureArgs) -> Result<()> {
    let requested: Speed = args.speed.into();
    let mut dev = select(args.device.as_deref())?;

    let supported = dev.capabilities().supported_speeds.clone();
    let speed = if supported.contains(&requested) {
        requested
    } else if requested == Speed::Auto {
        // This gateware doesn't advertise auto-detect; pick the fastest speed
        // it does support.
        let chosen = [Speed::High, Speed::Full, Speed::Low]
            .into_iter()
            .find(|s| supported.contains(s))
            .context("device reports no usable capture speeds")?;
        eprintln!("note: device has no auto-detect; capturing at {chosen} speed");
        chosen
    } else {
        let list = supported
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        bail!("device does not support {requested} speed (supported: {list})");
    };

    let opts = CaptureOptions {
        speed,
        vbus_passthrough: args.vbus,
    };

    // Anchor device-relative timestamps to wall-clock time for the pcap.
    let base_unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let mut pcap = match args.output.as_deref() {
        Some("-") => Some(PcapWriter::new(
            BufWriter::new(Box::new(std::io::stdout()) as Box<dyn Write>),
            base_unix_ns,
        )?),
        Some(path) => {
            let file = std::fs::File::create(path).with_context(|| format!("creating {path}"))?;
            Some(PcapWriter::new(
                BufWriter::new(Box::new(file) as Box<dyn Write>),
                base_unix_ns,
            )?)
        }
        None => None,
    };

    let stream = dev.start_capture(opts).context("starting capture")?;

    // A stop handle the Ctrl-C handler and the duration timer can trigger to
    // unblock the (otherwise blocking) capture read.
    let stopper = Arc::new(Mutex::new(stream.stop_handle()));
    {
        let s = stopper.clone();
        let _ = ctrlc::set_handler(move || {
            if let Ok(mut stop) = s.lock() {
                let _ = stop();
            }
        });
    }
    if let Some(secs) = args.duration {
        let s = stopper.clone();
        let dur = Duration::from_secs_f64(secs);
        std::thread::spawn(move || {
            std::thread::sleep(dur);
            if let Ok(mut stop) = s.lock() {
                let _ = stop();
            }
        });
    }

    eprintln!(
        "Capturing at {speed} speed{}... (Ctrl-C to stop)",
        args.duration
            .map(|s| format!(" for {s}s"))
            .unwrap_or_default()
    );

    let start = Instant::now();
    let mut packets: u64 = 0;
    let mut events: u64 = 0;

    for item in stream {
        let item = match item {
            Ok(i) => i,
            Err(e) => {
                eprintln!("capture error: {e}");
                break;
            }
        };
        match item.data {
            CaptureData::Packet(bytes) => {
                packets += 1;
                match pcap.as_mut() {
                    Some(w) => w.write_packet(item.timestamp_ns, &bytes)?,
                    None => print_packet_summary(packets, item.timestamp_ns, &bytes),
                }
                if let Some(max) = args.count {
                    if packets >= max {
                        break;
                    }
                }
            }
            CaptureData::Event(code) => {
                events += 1;
                if pcap.is_none() || args.verbose {
                    eprintln!("[{:>12} ns] event {code:#04x}", item.timestamp_ns);
                }
            }
        }
    }

    if let Ok(mut stop) = stopper.lock() {
        let _ = stop();
    }
    if let Some(mut w) = pcap {
        w.flush()?;
    }

    eprintln!(
        "Captured {packets} packets, {events} events in {:.2}s.",
        start.elapsed().as_secs_f64()
    );
    Ok(())
}

/// Print a one-line summary of a packet to stdout.
fn print_packet_summary(index: u64, ts_ns: u64, bytes: &[u8]) {
    const MAX: usize = 16;
    let hex: String = bytes
        .iter()
        .take(MAX)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let ellipsis = if bytes.len() > MAX { " ..." } else { "" };
    println!(
        "#{index:<6} [{ts_ns:>12} ns] {:>4} B  {hex}{ellipsis}",
        bytes.len()
    );
}

fn cmd_flash(args: FlashArgs) -> Result<()> {
    use usbmagic::flash::{self, FlashTarget};

    match flash::find()? {
        Some(d) => eprintln!(
            "Found Cynthion in {:?} mode (bus {} addr {}{}).",
            d.mode,
            d.bus_id,
            d.address,
            d.serial
                .as_deref()
                .map(|s| format!(", serial {s}"))
                .unwrap_or_default(),
        ),
        None => bail!("no Cynthion found"),
    }

    // Resolve the bitstream: explicit --bit, else the vendored firmware/*.bit.
    let path = match args.bit {
        Some(p) => p,
        None => default_firmware().context(
            "no --bit given and no vendored bitstream in firmware/ (run scripts/pull-gateware.sh)",
        )?,
    };
    let bytes = std::fs::read(&path).with_context(|| format!("reading {path}"))?;

    let target = if args.persistent {
        FlashTarget::Flash
    } else {
        FlashTarget::Sram
    };
    eprintln!(
        "Flashing {} ({} bytes) to {}...",
        path,
        bytes.len(),
        if args.persistent { "SPI flash" } else { "FPGA SRAM" }
    );
    flash::flash(&bytes, target)?;
    eprintln!("Done.");
    Ok(())
}

/// Find a vendored bitstream in `firmware/` (first `*.bit` alphabetically).
fn default_firmware() -> Option<String> {
    let mut bits: Vec<std::path::PathBuf> = std::fs::read_dir("firmware")
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "bit"))
        .collect();
    bits.sort();
    bits.first().map(|p| p.to_string_lossy().into_owned())
}

fn cmd_apollo(args: ApolloArgs) -> Result<()> {
    use usbmagic::flash::Apollo;

    eprintln!("Connecting to Apollo (will hand off the USB port if gateware is running)...");
    let apollo = Apollo::open().context("opening Apollo")?;

    println!("ID:        {}", apollo.id()?);
    println!("Firmware:  {}", apollo.firmware_version()?);
    let (major, minor) = apollo.usb_api_version()?;
    println!("USB API:   {major}.{minor}");

    match apollo.read_idcode() {
        Ok(idcode) => {
            let known = if idcode == usbmagic::flash::ECP5_12F_IDCODE {
                " (ECP5 LFE5U-12F)"
            } else {
                ""
            };
            println!("JTAG IDCODE: {idcode:#010x}{known}");
        }
        Err(e) => println!("JTAG IDCODE: <error: {e}>"),
    }

    if args.reconfigure {
        eprintln!("Reconfiguring FPGA from flash (restoring previous gateware)...");
        apollo.reconfigure()?;
        eprintln!("Done.");
    }
    Ok(())
}

fn cmd_pd_probe() -> Result<()> {
    use usbmagic::flash::Apollo;

    let path = "firmware/usbmagic-pd-bridge.bit";
    let bitstream = std::fs::read(path).with_context(|| format!("reading {path}"))?;

    let apollo = Apollo::open().context("opening Apollo")?;
    eprintln!("Flashing pd_bridge ({} bytes) to SRAM...", bitstream.len());
    let status = apollo.configure_sram(&bitstream)?;
    eprintln!("Configured (status {status:#010x}).");
    std::thread::sleep(std::time::Duration::from_millis(200));

    let (iw, dw) = apollo.register_widths()?;
    eprintln!("Register widths: instruction={iw} bits, data={dw} bits.");

    let id = apollo.register_read(1)?; // REG_ID
    println!(
        "REG_ID      = {id:#010x} {}",
        if id == 0x7550_4442 { "(uPDB ✓)" } else { "(unexpected!)" }
    );

    let gpio_in = apollo.register_read(3)?; // REG_GPIO_IN: bit0=SDA, bit1=INT#
    println!(
        "REG_GPIO_IN = {gpio_in:#x}  (SDA={}, FUSB302B_INT={})",
        gpio_in & 1,
        (gpio_in >> 1) & 1
    );

    probe_fusb302_id(&apollo);
    Ok(())
}

fn probe_fusb302_id(apollo: &usbmagic::flash::Apollo) {
    // Read the FUSB302B Device ID register (I2C 0x22, reg 0x01) over bit-banged I2C.
    match apollo.fusb302_read_register(usbmagic::flash::PdLine::TargetC, 0x22, 0x01) {
        Ok(id) => println!(
            "FUSB302B DeviceID (reg 0x01) = {id:#04x}  (version {:#x}, rev {:#x}){}",
            (id >> 4) & 0xf,
            id & 0x3,
            if id != 0x00 && id != 0xff { " ✓" } else { " (no device?)" }
        ),
        Err(e) => println!("FUSB302B read failed: {e}"),
    }
}

fn cmd_pd_listen(args: PdListenArgs) -> Result<()> {
    use std::time::Duration;
    use usbmagic::flash::Apollo;
    use usbmagic::PdLink;

    let path = "firmware/usbmagic-pd-bridge.bit";
    let bitstream = std::fs::read(path).with_context(|| format!("reading {path}"))?;

    let apollo = Apollo::open().context("opening Apollo")?;
    eprintln!("Flashing pd_bridge ({} bytes)...", bitstream.len());
    apollo.configure_sram(&bitstream)?;
    std::thread::sleep(Duration::from_millis(200));

    let portname = port_name(args.port);
    let mut pd = PdLink::new(apollo, args.port.into());
    pd.set_trace(make_trace(args.dump.as_deref())?);

    let cc = pd.setup_sink()?;
    if cc == 0 {
        bail!("no USB-C source detected on {portname} (CC lines idle) — plug a charger/source into {portname}");
    }
    eprintln!(
        "FUSB302B set as sink on {portname} CC{cc}; listening {:.0}s for PD messages...",
        args.duration
    );
    let rp_name = |bc: u8| match bc {
        0 => "none/vRa",
        1 => "default USB (~0.5 A)",
        2 => "1.5 A @ 5 V",
        _ => "3.0 A @ 5 V",
    };
    let s0 = pd.controller_read(0x40).unwrap_or(0);
    eprintln!(
        "  STATUS0 = {s0:#04x}  VBUS={}, source Rp = {}, BMC activity={}",
        if (s0 >> 7) & 1 == 1 { "present" } else { "absent" },
        rp_name(s0 & 0x03),
        (s0 >> 6) & 1,
    );

    let mut irq_seen = 0u8;
    let mut got_caps = false;
    // Bit-banged I2C is slow, so drive this by passes (and stop on success)
    // rather than a wall clock the I2C would blow past. Each pass: solicit, then
    // drain every message currently in the RX FIFO.
    let max_passes = (args.duration.max(1.0) * 3.0) as u32; // ~3 passes/sec budget
    for _pass in 0..max_passes {
        irq_seen |= pd.controller_read(0x42).unwrap_or(0);

        // Drain the whole RX FIFO this pass (GoodCRC + Source_Capabilities arrive
        // back-to-back).
        while let Some(msg) = pd.poll()? {
            if usbmagic::pd_message_name(&msg) == "Source_Capabilities" {
                got_caps = true;
            }
        }
        if got_caps {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let count = if let Some(t) = pd.trace_mut() {
        t.flush()?;
        t.count()
    } else {
        0
    };
    // INTERRUPT bits: I_CRC_CHK (0x10) = good PD message received; I_ACTIVITY
    // (0x40) = BMC activity seen; I_BC_LVL (0x01) = CC level changed.
    eprintln!(
        "Done — {count} PD message(s) captured. (latched INTERRUPT bits: {irq_seen:#04x} — \
         CRC_CHK={}, ACTIVITY={}, BC_LVL={})",
        (irq_seen >> 4) & 1,
        (irq_seen >> 6) & 1,
        irq_seen & 1,
    );
    if count == 0 {
        if irq_seen & 0x10 != 0 {
            eprintln!("Note: good PD messages were received (CRC_CHK latched) but the FIFO read returned none — RX-decode bug; I'll fix it.");
        } else if irq_seen & 0x40 != 0 {
            eprintln!("Note: BMC activity seen but no good CRC — messages are arriving garbled (wrong CC polarity or SpecRev).");
        } else {
            eprintln!("No BMC activity at all: this source isn't transmitting USB-PD on the measured CC (Type-C current only, or wrong port).");
        }
    }
    Ok(())
}

fn cmd_pd_source(args: PdListenArgs) -> Result<()> {
    use std::time::{Duration, Instant};
    use usbmagic::flash::Apollo;
    use usbmagic::{PdLink, PdMessage};

    let path = "firmware/usbmagic-pd-bridge.bit";
    let bitstream = std::fs::read(path).with_context(|| format!("reading {path}"))?;

    let apollo = Apollo::open().context("opening Apollo")?;
    eprintln!("Flashing pd_bridge ({} bytes)...", bitstream.len());
    apollo.configure_sram(&bitstream)?;
    std::thread::sleep(Duration::from_millis(200));

    let portname = port_name(args.port);
    let mut pd = PdLink::new(apollo, args.port.into());
    pd.set_trace(make_trace(args.dump.as_deref())?);

    let cc = pd.setup_source()?;
    if cc == 0 {
        bail!("no PD consumer (sink) detected on {portname} — is the device plugged into {portname}?");
    }
    let s0 = pd.controller_read(0x40).unwrap_or(0);
    eprintln!(
        "FUSB302B set as source on CC{cc} (VBUS {}); advertising Source_Capabilities for {:.0}s...",
        if (s0 >> 7) & 1 == 1 { "present" } else { "ABSENT" },
        args.duration
    );
    if (s0 >> 7) & 1 == 0 {
        eprintln!(
            "  warning: VBUS not detected — a sink won't negotiate without VBUS. \
             Bring it up first (e.g. `usbmagic charge`) or use `pd-send` which can route it."
        );
    }

    // Source_Capabilities advertising one Fixed PDO: 5 V @ 1.5 A.
    const PDO_5V_1A5: u32 = (100 << 10) | 150; // 50 mV & 10 mA units
    let start = Instant::now();
    while start.elapsed().as_secs_f64() < args.duration {
        let header = pd.next_source_header(1, 1);
        pd.send(&PdMessage::from_objects(header, &[PDO_5V_1A5]))?;

        // Listen for replies (GoodCRC, Request, …) for a short window.
        let window = Instant::now();
        while window.elapsed() < Duration::from_millis(300)
            && start.elapsed().as_secs_f64() < args.duration
        {
            if pd.poll()?.is_none() {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    let count = if let Some(t) = pd.trace_mut() {
        t.flush()?;
        t.count()
    } else {
        0
    };
    eprintln!("Done — {count} PD message(s) traced.");
    Ok(())
}

fn cmd_charge() -> Result<()> {
    use std::time::Duration;
    use usbmagic::flash::{vbus, Apollo, PdLine};

    let path = "firmware/usbmagic-pd-bridge.bit";
    let bitstream = std::fs::read(path).with_context(|| format!("reading {path}"))?;

    let apollo = Apollo::open().context("opening Apollo")?;
    eprintln!("Flashing pd_bridge ({} bytes)...", bitstream.len());
    apollo.configure_sram(&bitstream)?;
    std::thread::sleep(Duration::from_millis(200));

    // Safety: start with every VBUS switch open.
    apollo.set_vbus_switches(0)?;

    // 1. Present a sink on AUX so the supply turns on VBUS. We deliberately do
    //    NOT send a PD Request, so it stays at the default 5 V.
    let aux_cc = apollo.fusb302_setup_sink(PdLine::Aux)?;
    if aux_cc == 0 {
        bail!("no PD supply detected on AUX — plug the power supply into AUX");
    }
    let mut aux_vbus = false;
    for _ in 0..20 {
        let s = apollo.fusb302_read_register(PdLine::Aux, 0x22, 0x40)?;
        if (s >> 7) & 1 == 1 {
            aux_vbus = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !aux_vbus {
        bail!("AUX supply did not bring up VBUS");
    }
    eprintln!("AUX supply attached; VBUS up at 5 V.");

    // 2. Present a source (Rp) on TARGET-C so the consumer detects a source.
    let tc_cc = apollo.fusb302_setup_source(PdLine::TargetC)?;
    if tc_cc == 0 {
        eprintln!("warning: no sink detected on TARGET-C (is the device plugged in?) — routing VBUS anyway");
    } else {
        eprintln!("TARGET-C presenting source (Rp) on CC{tc_cc}.");
    }

    // 3. Route AUX 5 V into the board and out to TARGET-C via the TARGET-A rail.
    //    AUX_IN releases the AUX input shutoff; never enable CONTROL (host).
    let want = vbus::AUX_IN | vbus::AUX | vbus::TARGET_C;
    let got = apollo.set_vbus_switches(want)?;
    if got == want {
        eprintln!("Routed AUX 5 V -> TARGET-C (VBUS switches {want:#04x}, read-back verified).");
    } else {
        eprintln!(
            "Set VBUS switches to {want:#04x} (status read-back {got:#04x}); continuing — \
             VBUS presence is checked below."
        );
    }
    std::thread::sleep(Duration::from_millis(100));

    // 4. Confirm VBUS reached TARGET-C.
    let s = apollo.fusb302_read_register(PdLine::TargetC, 0x22, 0x40)?;
    if (s >> 7) & 1 == 1 {
        println!("TARGET-C: 5 V VBUS present + source presented — the device should now be charging.");
    } else {
        println!(
            "TARGET-C STATUS0={s:#04x}: VBUS not detected — check the device/cable on TARGET-C."
        );
    }
    eprintln!("(Leave it running to keep charging; power-cycle or `usbmagic apollo --reconfigure` to stop.)");
    Ok(())
}

/// Build a PD trace, optionally backed by a pcapng file with both ports as IDBs
/// (interface 0 = TARGET-C, 1 = AUX, matching [`usbmagic::PdLink`]'s convention).
/// The CLI owns trace/pcapng creation and hands the result to [`PdLink::set_trace`].
fn make_trace(dump: Option<&str>) -> Result<PdTrace> {
    let writer = match dump {
        Some(path) => {
            let f = std::fs::File::create(path).with_context(|| format!("creating {path}"))?;
            let w: Box<dyn Write> = Box::new(BufWriter::new(f));
            let ifaces = [
                IfaceDesc {
                    name: "TARGET-C",
                    linktype: usbmagic::LINKTYPE_USB_TYPE_C_PD,
                    snaplen: 4096,
                },
                IfaceDesc {
                    name: "AUX",
                    linktype: usbmagic::LINKTYPE_USB_TYPE_C_PD,
                    snaplen: 4096,
                },
            ];
            Some(PcapNgWriter::new(w, &ifaces)?)
        }
        None => None,
    };
    Ok(PdTrace::new(writer))
}

/// Decode a hex string (whitespace and `_` allowed) into bytes.
fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace() && *c != '_').collect();
    if s.len() % 2 != 0 {
        bail!("hex must have an even number of digits");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow::anyhow!("{e}")))
        .collect()
}

fn cmd_pd_send(args: PdSendArgs) -> Result<()> {
    use std::time::{Duration, Instant};
    use usbmagic::flash::Apollo;
    use usbmagic::PdLink;

    // Validate / parse message args up front (fail fast before touching hardware).
    let mut raw_msgs: Vec<Vec<u8>> = Vec::new();
    for h in &args.raws {
        let bytes = decode_hex(h).with_context(|| format!("bad --raw hex {h:?}"))?;
        if bytes.len() < 2 {
            bail!("--raw message {h:?} is too short (need at least the 2 header bytes)");
        }
        raw_msgs.push(bytes);
    }
    let vdm = if args.vdm {
        let svid = args.svid.context("--vdm requires --svid")?;
        let command = args.command.context("--vdm requires --command")?;
        Some(Vdm {
            svid,
            command,
            command_type: match args.vdm_type {
                VdmTypeArg::Req => 0,
                VdmTypeArg::Ack => 1,
                VdmTypeArg::Nak => 2,
                VdmTypeArg::Busy => 3,
            },
            object_position: args.obj_pos,
            objects: args.vdos.clone(),
        })
    } else {
        None
    };
    if raw_msgs.is_empty() && vdm.is_none() {
        bail!("nothing to send — pass --raw <hex> and/or --vdm --svid .. --command ..");
    }

    let path = "firmware/usbmagic-pd-bridge.bit";
    let bitstream = std::fs::read(path).with_context(|| format!("reading {path}"))?;
    let apollo = Apollo::open().context("opening Apollo")?;
    eprintln!("Flashing pd_bridge ({} bytes)...", bitstream.len());
    apollo.configure_sram(&bitstream)?;
    std::thread::sleep(Duration::from_millis(200));

    let portname = port_name(args.port);
    let mut pd = PdLink::new(apollo, args.port.into());
    pd.set_trace(make_trace(args.dump.as_deref())?);

    // PHY role + VBUS.
    match args.role {
        RoleArg::Source => {
            if !matches!(args.vbus, VbusArg::None) && matches!(args.port, PortArg::TargetC) {
                let src = pd.bring_up_vbus(args.vbus.into())?;
                eprintln!("VBUS on {portname} via {src}.");
            }
            let cc = pd.setup_source()?;
            if cc == 0 {
                bail!("no PD sink detected on {portname} — is the device plugged in?");
            }
            eprintln!("Presenting source (Rp) on {portname} CC{cc}.");
        }
        RoleArg::Sink => {
            let cc = pd.setup_sink()?;
            if cc == 0 {
                bail!("no source detected on {portname}");
            }
            eprintln!("Presenting sink (Rd) on {portname} CC{cc}.");
        }
        RoleArg::Raw => {}
    }

    if args.negotiate {
        if matches!(args.role, RoleArg::Source) {
            const PDO_5V_1A5: u32 = (100 << 10) | 150; // 5 V @ 1.5 A fixed
            if pd.negotiate_source(&[PDO_5V_1A5])?.is_some() {
                eprintln!("Got a Request from the sink — two-way PD achieved!");
            } else {
                eprintln!("No Request from sink yet; sending the rest without a contract.");
            }
        } else {
            eprintln!("note: --negotiate only applies to --role source; skipping.");
        }
    }

    // Brief drain between/after sends to capture replies.
    let drain_window = |pd: &mut PdLink, ms: u64| -> Result<()> {
        let w = Instant::now();
        while w.elapsed() < Duration::from_millis(ms) {
            if pd.poll()?.is_none() {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Ok(())
    };

    // Raw messages (header bytes verbatim, low byte first), then the VDM.
    for bytes in &raw_msgs {
        pd.send(&PdMessage { raw: bytes.clone() })?;
        drain_window(&mut pd, 150)?;
    }
    if let Some(v) = &vdm {
        pd.send_vdm(v, args.header)?;
        drain_window(&mut pd, 150)?;
    }

    // Keep tracing replies for the listen window.
    let start = Instant::now();
    while start.elapsed().as_secs_f64() < args.listen {
        if pd.poll()?.is_none() {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let count = if let Some(t) = pd.trace_mut() {
        t.flush()?;
        t.count()
    } else {
        0
    };
    eprintln!("Done — {count} PD message(s) traced.");

    // Diagnostics: was the partner transmitting at all? INTERRUPT (0x42) latches
    // I_ACTIVITY (BMC seen) and I_CRC_CHK (a good message arrived); STATUS0 0x40.
    let irq = pd.controller_read(0x42).unwrap_or(0);
    let s0 = pd.controller_read(0x40).unwrap_or(0);
    eprintln!(
        "  partner activity: BMC={} goodCRC={}  (INTERRUPT={irq:#04x}, STATUS0={s0:#04x}, \
         VBUS={})",
        (irq >> 6) & 1,
        (irq >> 4) & 1,
        if (s0 >> 7) & 1 == 1 { "present" } else { "absent" },
    );
    if (irq >> 4) & 1 == 0 {
        if (irq >> 6) & 1 == 1 {
            eprintln!(
                "  note: the partner IS transmitting (BMC=1) but no message decoded (goodCRC=0) — \
                 messages are arriving garbled. Likely CC polarity for RX, SpecRev, or we're \
                 colliding by transmitting over its replies (INTERRUPT collision bit 0x02)."
            );
        } else {
            eprintln!(
                "  note: no BMC activity from the partner — it may have fallen back to Type-C 5 V \
                 before our caps arrived, or isn't running PD on this CC."
            );
        }
    }
    if let Some(d) = &args.dump {
        eprintln!("Wrote pcapng trace to {d} (LINKTYPE_USB_TYPE_C_PD).");
    }
    Ok(())
}

fn cmd_pd_dump(args: PdDumpArgs) -> Result<()> {
    use usbmagic::{
        format_pd_message, parse_pcapng, parse_pd_pseudo_header, sop_name, LINKTYPE_USB_TYPE_C_PD,
    };

    let buf = std::fs::read(&args.file).with_context(|| format!("reading {}", args.file))?;
    let png = parse_pcapng(&buf).map_err(|e| anyhow::anyhow!("not a valid pcapng: {e}"))?;

    println!("{} interface(s):", png.interfaces.len());
    for (i, iface) in png.interfaces.iter().enumerate() {
        let known = if iface.linktype == LINKTYPE_USB_TYPE_C_PD {
            " = USB_TYPE_C_PD"
        } else {
            ""
        };
        println!(
            "  [{i}] {} (linktype {}{known})",
            iface.name.as_deref().unwrap_or("?"),
            iface.linktype,
        );
    }
    println!("{} packet(s):", png.packets.len());

    let base = png.packets.first().map(|p| p.ts).unwrap_or(0);
    for (idx, p) in png.packets.iter().enumerate() {
        let iface = png.interfaces.get(p.iface_id as usize);
        let port = iface.and_then(|i| i.name.as_deref()).unwrap_or("?");
        let tsresol = iface.map(|i| i.tsresol).unwrap_or(6);
        let ts_rel = p.ts.saturating_sub(base) as f64 / 10f64.powi(tsresol as i32);
        let lt = iface.map(|i| i.linktype).unwrap_or(0);

        if lt == LINKTYPE_USB_TYPE_C_PD {
            if let Some(ph) = parse_pd_pseudo_header(&p.data) {
                let msg = PdMessage {
                    raw: p.data[8..].to_vec(),
                };
                println!(
                    "{}",
                    format_pd_message((idx + 1) as u32, ts_rel, ph.direction, &msg)
                );
                let crc = ph
                    .crc
                    .map(|c| format!("{c:#010x}"))
                    .unwrap_or_else(|| "n/a (hw AUTO_CRC)".into());
                println!(
                    "       port={port} sop={} cc{} crc={crc}",
                    sop_name(ph.sop),
                    ph.cc
                );
                if args.hex {
                    let hex: String = p.data.iter().map(|b| format!("{b:02x}")).collect();
                    println!("       bytes={hex}");
                }
                continue;
            }
        }
        // Unknown / non-PD link type: show what we can.
        let hex: String = p.data.iter().map(|b| format!("{b:02x}")).collect();
        println!(
            "#{:<3} [{ts_rel:7.3}s] iface={port} linktype={lt} {} bytes raw={hex}",
            idx + 1,
            p.data.len(),
        );
    }
    Ok(())
}
