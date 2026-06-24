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

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::List => cmd_list(),
        Command::Info(sel) => cmd_info(sel.device.as_deref()),
        Command::Capture(args) => cmd_capture(args),
        Command::Flash(args) => cmd_flash(args),
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
