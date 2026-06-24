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
    match apollo.fusb302_read_register(0x22, 0x01) {
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

    let cc = apollo.fusb302_setup_sink()?;
    if cc == 0 {
        bail!("no USB-C source detected on TARGET-C (CC lines idle) — plug a charger/source into TARGET-C");
    }
    eprintln!(
        "FUSB302B set as sink on CC{cc}; listening {:.0}s for PD messages...",
        args.duration
    );
    let rp_name = |bc: u8| match bc {
        0 => "none/vRa",
        1 => "default USB (~0.5 A)",
        2 => "1.5 A @ 5 V",
        _ => "3.0 A @ 5 V",
    };
    let s0 = apollo.fusb302_read_register(0x22, 0x40).unwrap_or(0);
    eprintln!(
        "  STATUS0 = {s0:#04x}  VBUS={}, source Rp = {}, BMC activity={}",
        if (s0 >> 7) & 1 == 1 { "present" } else { "absent" },
        rp_name(s0 & 0x03),
        (s0 >> 6) & 1,
    );

    let start = Instant::now();
    let mut count = 0u32;
    let mut activity_seen = (s0 >> 6) & 1 == 1;
    let mut max_bc = s0 & 0x03;
    let mut last_status = Instant::now();
    while start.elapsed().as_secs_f64() < args.duration {
        match apollo.fusb302_poll_message()? {
            Some(raw) => {
                count += 1;
                print_pd_message(count, start.elapsed().as_secs_f64(), &PdMessage { raw });
            }
            None => std::thread::sleep(Duration::from_millis(15)),
        }
        // Continuously watch for any BMC activity / a higher advertised Rp.
        if last_status.elapsed() >= Duration::from_millis(200) {
            last_status = Instant::now();
            let s = apollo.fusb302_read_register(0x22, 0x40).unwrap_or(0);
            activity_seen |= (s >> 6) & 1 == 1;
            max_bc = max_bc.max(s & 0x03);
        }
    }
    eprintln!(
        "Done — {count} PD message(s) captured. (max Rp seen: {}, any BMC activity: {})",
        rp_name(max_bc),
        if activity_seen { "yes" } else { "no" },
    );
    if count == 0 && !activity_seen {
        eprintln!(
            "No PD traffic: the source supplies VBUS but never drove the CC line (no BMC). \
             That's a non-PD / default-USB source. A USB-C PD charger advertises 1.5/3.0 A Rp \
             and sends Source_Capabilities — if you have one on TARGET-C and still see this, \
             say so and I'll dig into the FUSB302B receiver config."
        );
    }
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
            match (pdo.fixed_voltage_mv(), pdo.fixed_max_current_ma()) {
                (Some(mv), Some(ma)) => println!(
                    "       PDO{}: {:.2} V @ {:.2} A (fixed)",
                    i + 1,
                    mv as f64 / 1000.0,
                    ma as f64 / 1000.0
                ),
                _ => println!("       PDO{}: {o:#010x}", i + 1),
            }
        }
    }
}
