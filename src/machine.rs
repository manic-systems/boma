//! One Linux guest per build on Virtualization.framework, booted straight
//! into the initrd's `/init`, which reports the builder's status back over
//! vsock before it powers the machine off.

#![expect(
   unsafe_code,
   reason = "Virtualization.framework is only reachable through objc2's unsafe bindings"
)]

use std::{
   error::Error,
   fmt::{
      self,
      Display,
      Formatter,
   },
   fs::File,
   io::{
      self,
      Read as _,
   },
   os::{
      fd::FromRawFd as _,
      unix::net::UnixStream,
   },
   path::{
      Path,
      PathBuf,
   },
   str::FromStr,
   sync::{
      atomic::{
         AtomicBool,
         Ordering,
      },
      mpsc::{
         Receiver,
         RecvTimeoutError,
         Sender,
      },
   },
   thread,
   time::{
      Duration,
      Instant,
   },
};

use block2::RcBlock;
use dispatch2::DispatchQueue;
use misstep::{
   OptionExt as _,
   Report,
   Result,
   ResultExt as _,
   bail,
   report,
};
use objc2::{
   AnyThread as _,
   DefinedClass as _,
   define_class,
   msg_send,
   rc::Retained,
   runtime::{
      Bool,
      ProtocolObject,
   },
};
use objc2_foundation::{
   NSArray,
   NSError,
   NSFileHandle,
   NSObject,
   NSObjectProtocol,
   NSProcessInfo,
   NSString,
   NSURL,
};
use objc2_virtualization::{
   VZDirectorySharingDeviceConfiguration,
   VZDiskImageCachingMode,
   VZDiskImageStorageDeviceAttachment,
   VZDiskImageSynchronizationMode,
   VZEntropyDeviceConfiguration,
   VZFileHandleSerialPortAttachment,
   VZGenericPlatformConfiguration,
   VZLinuxBootLoader,
   VZLinuxRosettaAvailability,
   VZLinuxRosettaDirectoryShare,
   VZMACAddress,
   VZNATNetworkDeviceAttachment,
   VZNetworkDeviceConfiguration,
   VZSerialPortConfiguration,
   VZSharedDirectory,
   VZSingleDirectoryShare,
   VZSocketDeviceConfiguration,
   VZStorageDeviceConfiguration,
   VZVirtioBlockDeviceConfiguration,
   VZVirtioConsoleDeviceSerialPortConfiguration,
   VZVirtioEntropyDeviceConfiguration,
   VZVirtioFileSystemDeviceConfiguration,
   VZVirtioNetworkDeviceConfiguration,
   VZVirtioSocketConnection,
   VZVirtioSocketDevice,
   VZVirtioSocketDeviceConfiguration,
   VZVirtioSocketListener,
   VZVirtioSocketListenerDelegate,
   VZVirtualMachine,
   VZVirtualMachineConfiguration,
   VZVirtualMachineDelegate,
};

use crate::{
   dns::{
      DNS_PORT,
      relay,
   },
   relay::{
      SOCKET_PORT_BASE,
      forward,
   },
   request::{
      AbsolutePath,
      System,
   },
   signals::Signal,
};

/// The vsock port the guest's `/init` reports its boot and the builder's
/// status on.
const STATUS_PORT: u32 = 1;

/// Whether the guest has said `boot`, after which Nix no longer reads the
/// sandbox setup protocol.
pub static BOOTED: AtomicBool = AtomicBool::new(false);

/// How long a status already being sent may trail the guest's power off.
const STATUS_GRACE: Duration = Duration::from_secs(2);

/// How the guest's builder ended.
#[derive(Clone, Copy)]
pub enum Outcome {
   Exit(u8),
   Signal(Signal),
}

/// One line the guest's `/init` sends, `boot` as it starts and then the
/// builder's status.
pub enum Message {
   Boot,
   Finished(Outcome),
}

impl FromStr for Message {
   type Err = Report;

   fn from_str(line: &str) -> Result<Self, Self::Err> {
      let bad = || format!("guest sent a malformed status {line:?}");
      let line = line.trim_end();

      if line == "boot" {
         return Ok(Self::Boot);
      }

      let (kind, number) = line.split_once(' ').with_context(bad)?;

      let outcome = match kind {
         "exit" => number.parse().map(Outcome::Exit).with_context(bad)?,
         "signal" => number.parse().map(Outcome::Signal).with_context(bad)?,
         _ => return Err(Report::msg(bad())),
      };

      Ok(Self::Finished(outcome))
   }
}

/// A failed run, split at the guest's `boot` since before it Nix is still
/// reading the sandbox setup protocol.
pub enum Failure {
   Setup(Report),
   Build(Report),
}

/// An [`NSError`]'s localized description, carried as an error so a report
/// keeps it apart from the context it failed in.
#[derive(Debug)]
pub struct FrameworkError {
   description: String,
   domain:      String,
   code:        isize,
}

impl From<&NSError> for FrameworkError {
   fn from(error: &NSError) -> Self {
      Self {
         description: error.localizedDescription().to_string(),
         domain:      error.domain().to_string(),
         code:        error.code(),
      }
   }
}

impl From<Retained<NSError>> for FrameworkError {
   fn from(error: Retained<NSError>) -> Self {
      Self::from(&*error)
   }
}

impl Display for FrameworkError {
   fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
      write!(
         formatter,
         "{} ({} {})",
         self.description, self.domain, self.code
      )
   }
}

impl Error for FrameworkError {}

/// What the main thread waits on.
pub enum Event {
   Started(Option<FrameworkError>),
   Connected,
   Message(Result<Message>),
   Stopped(Option<FrameworkError>),
   Interrupted(i32),
}

/// A guest network device's hardware address.
#[derive(Clone, Copy)]
pub struct MacAddress([u8; 6]);

impl From<[u8; 6]> for MacAddress {
   fn from(octets: [u8; 6]) -> Self {
      Self(octets)
   }
}

impl Display for MacAddress {
   fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
      for (index, octet) in self.0.iter().enumerate() {
         if index > 0 {
            formatter.write_str(":")?;
         }

         write!(formatter, "{octet:02x}")?;
      }

      Ok(())
   }
}

/// A finished guest description, every value resolved on the host.
pub struct Plan {
   pub kernel:  PathBuf,
   pub initrd:  PathBuf,
   pub cmdline: String,
   pub cpus:    u32,
   pub memory:  u64,
   pub store:   PathBuf,
   pub top:     PathBuf,
   pub system:  System,
   pub network: Option<MacAddress>,
   pub nested:  bool,
   pub boot:    Duration,
   pub scratch: Option<PathBuf>,
   pub sockets: Vec<AbsolutePath>,
}

/// A value touched only on the machine's queue.
struct Confined<T>(T);

#[expect(
   clippy::non_send_fields_in_send_ty,
   reason = "sending the framework's objects to their own queue is the point"
)]
/// SAFETY: Virtualization.framework objects may be used from any thread as long
/// as calls are serialized on the machine's queue, and every [`Confined`] is
/// unwrapped only inside `exec_sync` on that queue.
unsafe impl<T> Send for Confined<T> {}

impl<T> Confined<T> {
   fn into_inner(self) -> T {
      self.0
   }
}

struct Ivars {
   events:  Sender<Event>,
   /// Each forwarded socket's host path, listening on its index past
   /// [`SOCKET_PORT_BASE`].
   sockets: Vec<AbsolutePath>,
}

define_class!(
   /// SAFETY: [`NSObject`] has no subclassing requirements and [`Observer`]
   /// does not implement [`Drop`].
   #[unsafe(super(NSObject))]
   #[ivars = Ivars]
   struct Observer;

   unsafe impl NSObjectProtocol for Observer {}

   unsafe impl VZVirtualMachineDelegate for Observer {
      #[unsafe(method(guestDidStopVirtualMachine:))]
      fn guest_did_stop(&self, _machine: &VZVirtualMachine) {
         self.send(Event::Stopped(None));
      }

      #[unsafe(method(virtualMachine:didStopWithError:))]
      fn did_stop_with_error(&self, _machine: &VZVirtualMachine, error: &NSError) {
         self.send(Event::Stopped(Some(error.into())));
      }
   }

   unsafe impl VZVirtioSocketListenerDelegate for Observer {
      #[unsafe(method(listener:shouldAcceptNewConnection:fromSocketDevice:))]
      fn should_accept(
         &self,
         _listener: &VZVirtioSocketListener,
         connection: &VZVirtioSocketConnection,
         _device: &VZVirtioSocketDevice,
      ) -> Bool {
         // SAFETY: the connection owns a valid descriptor while it is alive,
         // and dup gives the reader its own.
         let (fd, port) = unsafe {
            (
               libc::dup(connection.fileDescriptor()),
               connection.destinationPort(),
            )
         };

         if port == DNS_PORT {
            if fd < 0 {
               return Bool::NO;
            }

            // SAFETY: fd is a fresh socket descriptor nothing else owns.
            relay(unsafe { UnixStream::from_raw_fd(fd) });
            return Bool::YES;
         }

         let forwarded = port
            .checked_sub(SOCKET_PORT_BASE)
            .and_then(|index| self.ivars().sockets.get(usize::try_from(index).ok()?));

         if let Some(path) = forwarded {
            if fd < 0 {
               return Bool::NO;
            }

            // SAFETY: fd is a fresh socket descriptor nothing else owns.
            forward(unsafe { UnixStream::from_raw_fd(fd) }, path.clone());
            return Bool::YES;
         }

         if fd < 0 {
            let error = Report::new(io::Error::last_os_error());

            self.send(Event::Message(Err(
               error.context("taking the status connection"),
            )));

            return Bool::NO;
         }

         // SAFETY: fd is a fresh descriptor nothing else owns.
         let mut stream = unsafe { File::from_raw_fd(fd) };
         let events = self.ivars().events.clone();
         self.send(Event::Connected);

         thread::spawn(move || {
            let mut line = String::new();

            let status = stream
               .by_ref()
               .take(64)
               .read_to_string(&mut line)
               .context("reading the guest status")
               .erase()
               .and_then(|_| line.parse());

            let _gone = events.send(Event::Message(status));
         });

         Bool::YES
      }
   }
);

impl Observer {
   fn new(events: Sender<Event>, sockets: Vec<AbsolutePath>) -> Retained<Self> {
      let this = Self::alloc().set_ivars(Ivars { events, sockets });
      // SAFETY: NSObject's init on a freshly allocated subclass instance.
      unsafe { msg_send![super(this), init] }
   }

   fn send(&self, event: Event) {
      let _gone = self.ivars().events.send(event);
   }
}

fn file_url(path: &Path) -> Result<Retained<NSURL>> {
   let text = path
      .to_str()
      .with_context(|| format!("{} is not UTF-8", path.display()))?;

   Ok(NSURL::fileURLWithPath(&NSString::from_str(text)))
}

/// Whether this host can give a guest `/dev/kvm`.
pub fn nested_supported() -> bool {
   // SAFETY: a class property with no preconditions.
   unsafe { VZGenericPlatformConfiguration::isNestedVirtualizationSupported() }
}

/// Clamps a CPU count to what both the host and the framework allow.
pub fn clamp_cpus(wanted: u32) -> u32 {
   let host = NSProcessInfo::processInfo().activeProcessorCount();

   // SAFETY: class properties with no preconditions.
   let (low, high) = unsafe {
      (
         VZVirtualMachineConfiguration::minimumAllowedCPUCount(),
         VZVirtualMachineConfiguration::maximumAllowedCPUCount(),
      )
   };

   let wanted = if wanted == 0 {
      host
   } else {
      usize::try_from(wanted).unwrap_or(usize::MAX)
   };

   u32::try_from(wanted.min(host).min(high).max(low)).unwrap_or(u32::MAX)
}

/// Clamps a memory size in bytes to what both the host and the framework allow.
pub fn clamp_memory(wanted: u64) -> u64 {
   let physical = NSProcessInfo::processInfo().physicalMemory();

   // SAFETY: class properties with no preconditions.
   let (low, high) = unsafe {
      (
         VZVirtualMachineConfiguration::minimumAllowedMemorySize(),
         VZVirtualMachineConfiguration::maximumAllowedMemorySize(),
      )
   };

   wanted.min(physical).min(high).max(low)
}

fn configure(plan: &Plan) -> Result<Retained<VZVirtualMachineConfiguration>> {
   let kernel = file_url(&plan.kernel)?;
   let initrd = file_url(&plan.initrd)?;
   let scratch = plan.scratch.as_deref().map(file_url).transpose()?;

   let shared = [
      ("store", file_url(&plan.store)?),
      ("build", file_url(&plan.top)?),
   ];

   // SAFETY: every call below builds fresh configuration objects that nothing
   // else references, with arguments checked on the Rust side.
   unsafe {
      let boot = VZLinuxBootLoader::initWithKernelURL(VZLinuxBootLoader::alloc(), &kernel);
      boot.setInitialRamdiskURL(Some(&initrd));
      boot.setCommandLine(&NSString::from_str(&plan.cmdline));

      let platform = VZGenericPlatformConfiguration::new();

      if plan.nested {
         platform.setNestedVirtualizationEnabled(true);
      }

      let output = NSFileHandle::initWithFileDescriptor(NSFileHandle::alloc(), libc::STDOUT_FILENO);

      let attachment =
         VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
            VZFileHandleSerialPortAttachment::alloc(),
            None,
            Some(&output),
         );

      let console = VZVirtioConsoleDeviceSerialPortConfiguration::new();
      console.setAttachment(Some(&attachment));

      let mut shares = Vec::<Retained<VZDirectorySharingDeviceConfiguration>>::new();

      for (tag, directory) in shared {
         let shared =
            VZSharedDirectory::initWithURL_readOnly(VZSharedDirectory::alloc(), &directory, false);

         let share =
            VZSingleDirectoryShare::initWithDirectory(VZSingleDirectoryShare::alloc(), &shared);

         let device = VZVirtioFileSystemDeviceConfiguration::initWithTag(
            VZVirtioFileSystemDeviceConfiguration::alloc(),
            &NSString::from_str(tag),
         );

         device.setShare(Some(&share));
         shares.push(Retained::into_super(device));
      }

      if plan.system == System::X86_64 {
         match VZLinuxRosettaDirectoryShare::availability() {
            VZLinuxRosettaAvailability::Installed => {},
            VZLinuxRosettaAvailability::NotInstalled => {
               bail!("Rosetta is not installed, run softwareupdate --install-rosetta")
            },
            _ => bail!("Rosetta is not supported on this host"),
         }

         let rosetta =
            VZLinuxRosettaDirectoryShare::initWithError(VZLinuxRosettaDirectoryShare::alloc())
               .map_err(FrameworkError::from)
               .context("sharing Rosetta")?;

         let device = VZVirtioFileSystemDeviceConfiguration::initWithTag(
            VZVirtioFileSystemDeviceConfiguration::alloc(),
            &NSString::from_str("rosetta"),
         );

         device.setShare(Some(&rosetta));
         shares.push(Retained::into_super(device));
      }

      let mut networks = Vec::<Retained<VZNetworkDeviceConfiguration>>::new();

      if let Some(mac) = plan.network {
         let text = NSString::from_str(&mac.to_string());

         let address = VZMACAddress::initWithString(VZMACAddress::alloc(), &text)
            .with_context(|| format!("{mac} is not a MAC address"))?;

         let device = VZVirtioNetworkDeviceConfiguration::new();
         device.setMACAddress(&address);
         device.setAttachment(Some(&VZNATNetworkDeviceAttachment::new()));
         networks.push(Retained::into_super(device));
      }

      let mut disks = Vec::<Retained<VZStorageDeviceConfiguration>>::new();

      if let Some(ref url) = scratch {
         let attachment =
            VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_cachingMode_synchronizationMode_error(
               VZDiskImageStorageDeviceAttachment::alloc(),
               url,
               false,
               VZDiskImageCachingMode::Cached,
               VZDiskImageSynchronizationMode::None,
            )
            .map_err(FrameworkError::from)
            .context("attaching the scratch disk")?;

         let device = VZVirtioBlockDeviceConfiguration::initWithAttachment(
            VZVirtioBlockDeviceConfiguration::alloc(),
            &attachment,
         );

         disks.push(Retained::into_super(device));
      }

      let config = VZVirtualMachineConfiguration::new();
      config.setBootLoader(Some(&boot));
      config.setPlatform(&platform);
      config.setCPUCount(usize::try_from(plan.cpus)?);
      config.setMemorySize(plan.memory);

      config.setSerialPorts(&NSArray::from_retained_slice(&[
         Retained::into_super(console) as Retained<VZSerialPortConfiguration>,
      ]));

      config.setDirectorySharingDevices(&NSArray::from_retained_slice(&shares));

      config.setEntropyDevices(&NSArray::from_retained_slice(&[Retained::into_super(
         VZVirtioEntropyDeviceConfiguration::new(),
      )
         as Retained<VZEntropyDeviceConfiguration>]));

      config.setSocketDevices(&NSArray::from_retained_slice(&[Retained::into_super(
         VZVirtioSocketDeviceConfiguration::new(),
      )
         as Retained<VZSocketDeviceConfiguration>]));

      config.setNetworkDevices(&NSArray::from_retained_slice(&networks));
      config.setStorageDevices(&NSArray::from_retained_slice(&disks));

      config
         .validateWithError()
         .map_err(FrameworkError::from)
         .context("invalid machine")?;

      Ok(config)
   }
}

/// Validates the guest, so a bad configuration fails before anything boots.
pub fn prepare(plan: Plan) -> Result<Prepared> {
   Ok(Prepared {
      config:  configure(&plan)?,
      boot:    plan.boot,
      dns:     plan.network.is_some(),
      sockets: plan.sockets,
   })
}

pub struct Prepared {
   config:  Retained<VZVirtualMachineConfiguration>,
   boot:    Duration,
   dns:     bool,
   sockets: Vec<AbsolutePath>,
}

impl Prepared {
   /// Boots the guest and waits for it to power off.
   pub fn run(
      self,
      events: &Sender<Event>,
      received: &Receiver<Event>,
   ) -> Result<Outcome, Failure> {
      let queue = DispatchQueue::new("machine", None);
      let observer = Observer::new(events.clone(), self.sockets);

      let listener = Confined(
         // SAFETY: a fresh listener with no preconditions.
         unsafe { VZVirtioSocketListener::new() },
      );

      let mut machine = None;
      let dns = self.dns;
      let setup = Confined((&self.config, &observer, &listener.0, &mut machine, &queue));

      queue.exec_sync(move || {
         let (config, observer, listener, slot, queue) = setup.into_inner();

         // SAFETY: on the machine's own queue, with a validated configuration.
         unsafe {
            let created = VZVirtualMachine::initWithConfiguration_queue(
               VZVirtualMachine::alloc(),
               config,
               queue,
            );

            created.setDelegate(Some(ProtocolObject::from_ref(&**observer)));
            listener.setDelegate(Some(ProtocolObject::from_ref(&**observer)));

            if let Some(device) = created.socketDevices().firstObject()
               && let Ok(device) = device.downcast::<VZVirtioSocketDevice>()
            {
               device.setSocketListener_forPort(listener, STATUS_PORT);
               if dns {
                  device.setSocketListener_forPort(listener, DNS_PORT);
               }
               for port in (SOCKET_PORT_BASE..).take(observer.ivars().sockets.len()) {
                  device.setSocketListener_forPort(listener, port);
               }
            }

            let started = events_block(observer.ivars().events.clone());
            created.startWithCompletionHandler(&started);
            *slot = Some(Confined(created));
         }
      });

      let Some(created) = machine else {
         return Err(Failure::Setup(report!("the machine was not created")));
      };

      let result = wait(&queue, &created.0, received, self.boot);
      queue.exec_sync(move || drop(created.into_inner()));

      result.map_err(|error| {
         if BOOTED.load(Ordering::Relaxed) {
            Failure::Build(error)
         } else {
            Failure::Setup(error)
         }
      })
   }
}

/// Hard-stops the machine, for a guest that will not power off by itself.
fn halt(queue: &DispatchQueue, machine: &VZVirtualMachine) {
   let held = Confined(machine);

   queue.exec_sync(move || {
      let machine = held.into_inner();
      // SAFETY: on the machine's queue, stopping a started machine.
      unsafe { machine.stopWithCompletionHandler(&RcBlock::new(|_: *mut NSError| {})) };
   });
}

/// Waits for power off, and treats a second `boot` as a kernel panic since
/// resets reboot the guest.
fn wait(
   queue: &DispatchQueue,
   machine: &VZVirtualMachine,
   received: &Receiver<Event>,
   boot: Duration,
) -> Result<Outcome> {
   let start = Instant::now();
   let mut pending = 0_usize;
   let mut outcome = None;

   let stopped = loop {
      let event = if BOOTED.load(Ordering::Relaxed) {
         received.recv().context("lost the machine's events")?
      } else {
         match received.recv_timeout(boot.saturating_sub(start.elapsed())) {
            Ok(event) => event,
            Err(RecvTimeoutError::Timeout) => {
               halt(queue, machine);
               bail!("the guest did not reach init within {} s", boot.as_secs());
            },
            Err(RecvTimeoutError::Disconnected) => bail!("lost the machine's events"),
         }
      };

      match event {
         Event::Started(None) => {},
         Event::Started(Some(error)) => {
            bail!(Report::new(error).context("starting the machine"))
         },
         Event::Connected => pending += 1,
         Event::Message(message) => {
            pending = pending.saturating_sub(1);

            match message {
               Ok(Message::Boot) if outcome.is_some() => {
                  halt(queue, machine);
                  break None;
               },
               Ok(Message::Boot) if BOOTED.load(Ordering::Relaxed) => {
                  halt(queue, machine);
                  bail!("the guest rebooted, likely a kernel panic");
               },
               Ok(Message::Boot) => BOOTED.store(true, Ordering::Relaxed),
               Ok(Message::Finished(finished)) => outcome = Some(Ok(finished)),
               Err(error) if !BOOTED.load(Ordering::Relaxed) => {
                  halt(queue, machine);
                  return Err(error);
               },
               Err(error) => outcome = Some(Err(error)),
            }
         },
         Event::Stopped(error) => break error,
         Event::Interrupted(signal) => {
            halt(queue, machine);
            bail!("stopped the machine on signal {signal}");
         },
      }
   };

   if let Some(error) = stopped {
      bail!(Report::new(error).context("the machine stopped with an error"));
   }

   while pending > 0 && outcome.is_none() {
      match received.recv_timeout(STATUS_GRACE) {
         Ok(Event::Message(Ok(Message::Finished(finished)))) => outcome = Some(Ok(finished)),
         Ok(Event::Message(Err(error))) => outcome = Some(Err(error)),
         Ok(Event::Message(Ok(Message::Boot))) => pending = pending.saturating_sub(1),
         Ok(_) => {},
         Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
      }
   }

   match outcome {
      Some(Ok(outcome)) => Ok(outcome),
      Some(Err(error)) => Err(error),
      None => bail!("the guest powered off without reporting a status"),
   }
}

fn events_block(events: Sender<Event>) -> RcBlock<dyn Fn(*mut NSError)> {
   RcBlock::new(move |error: *mut NSError| {
      // SAFETY: the framework passes nil or a valid NSError for the call.
      let error = unsafe { error.as_ref() }.map(FrameworkError::from);
      let _gone = events.send(Event::Started(error));
   })
}
