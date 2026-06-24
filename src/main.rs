//! `usbmagic` command-line tool: list, inspect, and capture from magic USB ports.

use std::io::{BufWriter, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};

use usbmagic::pcap::PcapWriter;
use usbmagic::{discover, CaptureData, CaptureOptions, MagicDevice, Speed};

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
    use std::time::{Duration, Instant};
    use usbmagic::flash::Apollo;
    use usbmagic::PdMessage;

    let path = "firmware/usbmagic-pd-bridge.bit";
    let bitstream = std::fs::read(path).with_context(|| format!("reading {path}"))?;

    let apollo = Apollo::open().context("opening Apollo")?;
    eprintln!("Flashing pd_bridge ({} bytes)...", bitstream.len());
    apollo.configure_sram(&bitstream)?;
    std::thread::sleep(Duration::from_millis(200));

    let line = usbmagic::flash::PdLine::from(args.port);
    let port = port_name(args.port);
    let cc = apollo.fusb302_setup_sink(line)?;
    if cc == 0 {
        bail!("no USB-C source detected on {port} (CC lines idle) — plug a charger/source into {port}");
    }
    eprintln!(
        "FUSB302B set as sink on {port} CC{cc}; listening {:.0}s for PD messages...",
        args.duration
    );
    let rp_name = |bc: u8| match bc {
        0 => "none/vRa",
        1 => "default USB (~0.5 A)",
        2 => "1.5 A @ 5 V",
        _ => "3.0 A @ 5 V",
    };
    let s0 = apollo.fusb302_read_register(line, 0x22, 0x40).unwrap_or(0);
    eprintln!(
        "  STATUS0 = {s0:#04x}  VBUS={}, source Rp = {}, BMC activity={}",
        if (s0 >> 7) & 1 == 1 { "present" } else { "absent" },
        rp_name(s0 & 0x03),
        (s0 >> 6) & 1,
    );

    let start = Instant::now();
    let mut count = 0u32;
    let mut irq_seen = 0u8;
    let mut got_caps = false;
    // Bit-banged I2C is slow, so drive this by passes (and stop on success)
    // rather than a wall clock the I2C would blow past. Each pass: solicit, then
    // drain every message currently in the RX FIFO.
    let max_passes = (args.duration.max(1.0) * 3.0) as u32; // ~3 passes/sec budget
    for _pass in 0..max_passes {
        irq_seen |= apollo.fusb302_read_register(line, 0x22, 0x42).unwrap_or(0);

        // Drain the whole RX FIFO this pass (GoodCRC + Source_Capabilities arrive
        // back-to-back).
        while let Some(raw) = apollo.fusb302_poll_message(line)? {
            count += 1;
            let msg = PdMessage { raw };
            if pd_message_name(&msg) == "Source_Capabilities" {
                got_caps = true;
            }
            print_pd_message(count, start.elapsed().as_secs_f64(), &msg);
        }
        if got_caps {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
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
    use usbmagic::PdMessage;

    let path = "firmware/usbmagic-pd-bridge.bit";
    let bitstream = std::fs::read(path).with_context(|| format!("reading {path}"))?;

    let apollo = Apollo::open().context("opening Apollo")?;
    eprintln!("Flashing pd_bridge ({} bytes)...", bitstream.len());
    apollo.configure_sram(&bitstream)?;
    std::thread::sleep(Duration::from_millis(200));

    let line = usbmagic::flash::PdLine::from(args.port);
    let port = port_name(args.port);
    let cc = apollo.fusb302_setup_source(line)?;
    if cc == 0 {
        bail!("no PD consumer (sink) detected on {port} — is the device plugged into {port}?");
    }
    let s0 = apollo.fusb302_read_register(line, 0x22, 0x40).unwrap_or(0);
    eprintln!(
        "FUSB302B set as source on CC{cc} (VBUS {}); advertising Source_Capabilities for {:.0}s...",
        if (s0 >> 7) & 1 == 1 { "present" } else { "ABSENT" },
        args.duration
    );
    if (s0 >> 7) & 1 == 0 {
        eprintln!(
            "  warning: VBUS not detected — a sink won't negotiate without VBUS. \
             (Current pd_bridge gateware can't switch VBUS; that's the next gateware addition.)"
        );
    }

    // Source_Capabilities: header (data msg type 1, source, DFP, Rev2.0, 1 PDO) +
    // one Fixed PDO: 5 V @ 1.5 A.
    const PDO_5V_1A5: u32 = (100 << 10) | 150; // 50 mV & 10 mA units
    let start = Instant::now();
    let mut msg_id = 0u16;
    let mut got = 0u32;
    while start.elapsed().as_secs_f64() < args.duration {
        let header: u16 = 0x1161 | ((msg_id & 0x7) << 9);
        let mut raw = header.to_le_bytes().to_vec();
        raw.extend_from_slice(&PDO_5V_1A5.to_le_bytes());
        if let Err(e) = apollo.fusb302_tx(line, &raw) {
            eprintln!("TX error: {e}");
        }
        msg_id = msg_id.wrapping_add(1);

        // Listen for replies (GoodCRC, Request, …) for a short window.
        let window = Instant::now();
        while window.elapsed() < Duration::from_millis(300)
            && start.elapsed().as_secs_f64() < args.duration
        {
            match apollo.fusb302_poll_message(line)? {
                Some(r) => {
                    got += 1;
                    print_pd_message(got, start.elapsed().as_secs_f64(), &PdMessage { raw: r });
                }
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }
    eprintln!("Done — {got} PD message(s) received from the consumer.");
    if got == 0 {
        eprintln!(
            "No reply. If VBUS is present and the device is a PD sink on TARGET-C, this may be a \
             CC-orientation or receiver detail — tell me and I'll iterate."
        );
    }
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

fn pd_message_name(msg: &usbmagic::PdMessage) -> &'static str {
    use usbmagic::pd::PdMessageClass;
    let mt = msg.message_type().unwrap_or(0);
    match msg.class() {
        Some(PdMessageClass::Control) => match mt {
            1 => "GoodCRC",
            2 => "GotoMin",
            3 => "Accept",
            4 => "Reject",
            5 => "Ping",
            6 => "PS_RDY",
            7 => "Get_Source_Cap",
            8 => "Get_Sink_Cap",
            9 => "DR_Swap",
            10 => "PR_Swap",
            11 => "VCONN_Swap",
            12 => "Wait",
            13 => "Soft_Reset",
            _ => "Control(?)",
        },
        Some(PdMessageClass::Data) => match mt {
            1 => "Source_Capabilities",
            2 => "Request",
            3 => "BIST",
            4 => "Sink_Capabilities",
            5 => "Battery_Status",
            6 => "Alert",
            15 => "Vendor_Defined",
            _ => "Data(?)",
        },
        Some(PdMessageClass::Extended) => "Extended",
        None => "(empty)",
    }
}

fn print_pd_message(index: u32, ts: f64, msg: &usbmagic::PdMessage) {
    use usbmagic::pd::Pdo;
    let hex: String = msg.raw.iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "#{index:<3} [{ts:7.3}s] {:<20} hdr={:#06x} obj={} raw={hex}",
        pd_message_name(msg),
        msg.header().unwrap_or(0),
        msg.num_data_objects().unwrap_or(0),
    );
    if pd_message_name(msg) == "Source_Capabilities" {
        for (i, o) in msg.objects().iter().enumerate() {
            let pdo = Pdo { raw: *o };
            if let (Some(mv), Some(ma)) = (pdo.fixed_voltage_mv(), pdo.fixed_max_current_ma()) {
                println!(
                    "       PDO{}: {:.2} V @ {:.2} A (fixed)",
                    i + 1,
                    mv as f64 / 1000.0,
                    ma as f64 / 1000.0
                );
            } else if let Some((min_mv, max_mv, max_ma)) = pdo.pps() {
                println!(
                    "       PDO{}: {:.2}–{:.2} V @ {:.2} A (PPS)",
                    i + 1,
                    min_mv as f64 / 1000.0,
                    max_mv as f64 / 1000.0,
                    max_ma as f64 / 1000.0
                );
            } else {
                println!("       PDO{}: {o:#010x}", i + 1);
            }
        }
    }
}
