//! A Nix `external-builders` program for macOS that builds each Linux
//! derivation in a fresh Virtualization.framework guest.

mod dns;
mod entitlement;
mod machine;
mod request;
mod signals;

use std::{
   fs::{
      self,
      DirBuilder,
      File,
      OpenOptions,
      TryLockError,
   },
   io::{
      self,
      Write,
   },
   os::unix::fs::{
      DirBuilderExt as _,
      MetadataExt as _,
      OpenOptionsExt as _,
   },
   panic,
   path::{
      Path,
      PathBuf,
   },
   process::{
      ExitCode,
      Termination,
   },
   sync::{
      atomic::Ordering,
      mpsc::{
         self,
         Receiver,
         Sender,
      },
   },
   thread,
   time::Duration,
};

use machine::{
   BOOTED,
   Event,
   Failure,
   MacAddress,
   Outcome,
   Plan,
   Prepared,
   clamp_cpus,
   clamp_memory,
   nested_supported,
};
use misstep::{
   Report,
   Result,
   ResultExt as _,
   bail,
   install_panic_hook,
};
use pound::Parse;
use request::{
   Build,
   Sandbox,
   SandboxPath,
   closure_paths,
};
use signals::SignalSet;

#[derive(Parse)]
struct Arguments {
   /// the guest's uncompressed kernel Image.
   #[pound(long)]
   kernel:          PathBuf,
   /// the guest's initrd, whose init sandboxes and runs the builder.
   #[pound(long)]
   initrd:          PathBuf,
   /// guest memory in MiB.
   #[pound(long, default = "8192")]
   memory:          u64,
   /// guest CPUs, instead of the build's cores setting.
   #[pound(long)]
   cpus:            Option<u32>,
   /// the guest kernel's console log level.
   #[pound(long, default = "4")]
   loglevel:        u8,
   /// seconds the guest kernel may take to reach init.
   #[pound(long, default = "30")]
   boot_timeout:    u64,
   /// give builds /dev/kvm through nested virtualization where supported.
   #[pound(long)]
   kvm:             bool,
   /// a path to bind into the sandbox, as Nix's sandbox-paths.
   #[pound(long)]
   sandbox_path:    Vec<SandboxPath>,
   /// a file listing store paths, one per line, all bound into the sandbox.
   #[pound(long)]
   sandbox_closure: Vec<PathBuf>,
   /// MiB of sparse scratch disk the guest swaps to, 0 for none.
   #[pound(long, default = "65536")]
   scratch:         u64,
   /// the build.json Nix wrote.
   build:           PathBuf,
}

/// Writes a report in Nix's sandbox setup protocol, the error chain as the
/// message and each context as a trace.
fn write_setup_error(report: &Report, out: &mut impl Write) -> io::Result<()> {
   fn number(out: &mut impl Write, value: usize) -> io::Result<()> {
      out.write_all(&(value as u64).to_le_bytes())
   }

   fn string(out: &mut impl Write, text: &str) -> io::Result<()> {
      number(out, text.len())?;
      out.write_all(text.as_bytes())?;
      out.write_all(&[0; 8][..text.len().next_multiple_of(8) - text.len()])
   }

   let message = report
      .chain()
      .map(ToString::to_string)
      .collect::<Vec<_>>()
      .join(": ");

   let contexts = report.contexts();

   out.write_all(b"\x01\n")?;
   string(out, "Error")?;
   number(out, 0)?;
   string(out, "")?;
   string(out, &message)?;
   number(out, 0)?;
   number(out, contexts.len())?;

   for context in contexts.iter().rev() {
      number(out, 0)?;
      string(out, context.message())?;
   }

   out.flush()
}

/// Turns termination signals into an [`Event`], before any other thread so they
/// inherit the mask.
fn forward_signals(events: Sender<Event>) -> Result<()> {
   let set = [libc::SIGHUP, libc::SIGINT, libc::SIGTERM]
      .into_iter()
      .collect::<SignalSet>();

   set.block().context("blocking termination signals")?;

   thread::spawn(move || {
      if let Ok(signal) = set.wait() {
         let _gone = events.send(Event::Interrupted(signal));
      }
   });

   Ok(())
}

/// The guest's sparse swap disk in the build's top directory, removed once
/// the guest is gone since `--keep-failed` would otherwise keep it.
struct Scratch(PathBuf);

impl Scratch {
   fn create(path: &Path, mib: u64) -> Result<Self> {
      let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
      let scratch = Self(path.to_path_buf());

      file
         .set_len(mib.saturating_mul(1 << 20))
         .with_context(|| format!("sizing {} to {mib} MiB", path.display()))?;

      Ok(scratch)
   }
}

impl Drop for Scratch {
   fn drop(&mut self) {
      let _gone = fs::remove_file(&self.0);
   }
}

/// One of the uid's 256 guest MACs, locked so concurrent builds differ and DHCP
/// leases get reused.
struct MacLease {
   _lock:   File,
   address: MacAddress,
}

impl MacLease {
   #[expect(unsafe_code, reason = "libc has no safe credential calls")]
   fn acquire() -> Result<Self> {
      // SAFETY: getuid cannot fail.
      let uid = unsafe { libc::getuid() };
      let dir = PathBuf::from(format!("/tmp/{}-{uid}", env!("CARGO_PKG_NAME")));

      DirBuilder::new()
         .mode(0o700)
         .create(&dir)
         .with_context(|| format!("creating {}", dir.display()))
         .recover_if::<io::Error, _>(|error| {
            (error.kind() == io::ErrorKind::AlreadyExists).then_some(())
         })?;

      let found =
         fs::symlink_metadata(&dir).with_context(|| format!("inspecting {}", dir.display()))?;

      if !found.is_dir() || found.uid() != uid {
         bail!("{} is not a directory owned by uid {uid}", dir.display());
      }

      let [_, _, high, low] = uid.to_be_bytes();

      for slot in 0..=u8::MAX {
         let path = dir.join(slot.to_string());

         let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;

         let locked = file
            .try_lock()
            .map(|()| true)
            .with_context(|| format!("locking {}", path.display()))
            .recover_if::<TryLockError, _>(|error| {
               matches!(error, TryLockError::WouldBlock).then_some(false)
            })?;

         if locked {
            return Ok(Self {
               _lock:   file,
               address: MacAddress::from([0x02, 0x74, 0x72, high, low, slot]),
            });
         }
      }

      bail!("every guest MAC address for uid {uid} is in use")
   }
}

/// A validated guest and the host state that must outlive it.
struct Ready {
   prepared: Prepared,
   sandbox:  Sandbox,
   _scratch: Option<Scratch>,
   _lease:   Option<MacLease>,
}

impl Ready {
   fn prepare(arguments: Arguments) -> Result<Self> {
      let build = Build::load(&arguments.build)?;
      let network = build.networked()?;
      let kvm = arguments.kvm && nested_supported();

      if arguments.kvm && !kvm {
         writeln!(
            io::stderr(),
            "nested virtualization is unsupported here, builds get no /dev/kvm"
         )?;
      }

      let mut paths = arguments.sandbox_path;
      paths.extend(closure_paths(&arguments.sandbox_closure)?);
      let sandbox = build.stage(&paths, network, kvm)?;

      let scratch_path = (arguments.scratch > 0).then(|| build.top_tmp_dir.join("scratch.img"));

      let scratch = scratch_path
         .as_ref()
         .map(|path| Scratch::create(path, arguments.scratch))
         .transpose()?;

      let lease = network.then(MacLease::acquire).transpose()?;

      let mut cmdline = format!(
         "console=hvc0 rdinit=/init panic=-1 quiet loglevel={}",
         arguments.loglevel
      );

      if network {
         cmdline.push_str(" ip=dhcp");
      }

      let plan = Plan {
         kernel: arguments.kernel,
         initrd: arguments.initrd,
         cmdline,
         cpus: clamp_cpus(arguments.cpus.map_or_else(|| build.cores(), Ok)?),
         memory: clamp_memory(arguments.memory.saturating_mul(1 << 20)),
         store: build.real_store_dir,
         top: build.top_tmp_dir,
         system: build.system,
         network: lease.as_ref().map(|lease| lease.address),
         nested: kvm,
         boot: Duration::from_secs(arguments.boot_timeout),
         scratch: scratch_path,
      };

      Ok(Self {
         prepared: machine::prepare(&plan)?,
         sandbox,
         _scratch: scratch,
         _lease: lease,
      })
   }

   /// Writes sandbox.json and boots the guest. The scratch disk and the MAC
   /// lease go with `self` once the guest is gone.
   fn run(self, events: &Sender<Event>, received: &Receiver<Event>) -> Result<Outcome, Failure> {
      self.sandbox.write().map_err(Failure::Setup)?;
      self.prepared.run(events, received)
   }
}

/// How this process ends, which [`Termination`] turns into the status, signal
/// or setup error Nix reads the build's result from.
struct Ending(Result<Outcome, Failure>);

impl Termination for Ending {
   fn report(self) -> ExitCode {
      match self.0 {
         Ok(Outcome::Exit(code)) => ExitCode::from(code),
         Ok(Outcome::Signal(signal)) => {
            signal.raise();
            ExitCode::from(signal.exit_status())
         },
         Err(Failure::Setup(report)) => {
            let _gone = write_setup_error(&report, &mut io::stdout().lock());
            ExitCode::FAILURE
         },
         Err(Failure::Build(report)) => {
            let _gone = writeln!(io::stderr(), "{report:?}");
            ExitCode::FAILURE
         },
      }
   }
}

fn run() -> Result<Outcome, Failure> {
   install_panic_hook();
   let pretty = panic::take_hook();

   // Until the guest boots Nix only reads the setup protocol, and shows
   // anything else as an unstructured "previous messages" blob.
   panic::set_hook(Box::new(move |info| {
      if BOOTED.load(Ordering::Relaxed) {
         pretty(info);
      } else {
         let _gone = write_setup_error(&Report::msg(info), &mut io::stdout().lock());
      }
   }));

   entitlement::ensure().map_err(Failure::Setup)?;

   let arguments = match Arguments::try_parse() {
      Ok(arguments) => arguments,
      Err(error) if error.is_exit() => error.exit(),
      Err(error) => return Err(Failure::Setup(Report::msg(error))),
   };

   let (events, received) = mpsc::channel();
   forward_signals(events.clone()).map_err(Failure::Setup)?;

   Ready::prepare(arguments)
      .map_err(Failure::Setup)?
      .run(&events, &received)
}

fn main() -> Ending {
   Ending(run())
}
