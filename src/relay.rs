//! Guest vsock connections spliced to streams on the host.

use std::{
   io::{
      self,
      Read,
      Write,
   },
   net::Shutdown,
   os::unix::net::UnixStream,
   path::PathBuf,
   thread,
};

/// The first vsock port a forwarded socket listens on, the rest follow in
/// `--socket` order.
pub const SOCKET_PORT_BASE: u32 = 1024;

/// Copies both ways until each side has closed its half.
pub fn splice<Upstream: Read + Write + Send + 'static>(
   mut guest: UnixStream,
   mut upstream_reader: Upstream,
   mut upstream_writer: Upstream,
   close: fn(&Upstream, Shutdown) -> io::Result<()>,
) -> io::Result<()> {
   let mut guest_reader = guest.try_clone()?;

   let forward = thread::spawn(move || {
      let _copied = io::copy(&mut guest_reader, &mut upstream_writer);
      let _closed = close(&upstream_writer, Shutdown::Write);
   });

   let _copied = io::copy(&mut upstream_reader, &mut guest);
   let _closed = guest.shutdown(Shutdown::Write);
   let _joined = forward.join();
   Ok(())
}

/// Splices one guest connection to the host's unix socket at `path`, closing
/// it when nothing listens there. Errors only end the connection.
pub fn forward(guest: UnixStream, path: PathBuf) {
   thread::spawn(move || -> io::Result<()> {
      match UnixStream::connect(&path) {
         Ok(upstream) => splice(guest, upstream.try_clone()?, upstream, UnixStream::shutdown),
         Err(_) => guest.shutdown(Shutdown::Both),
      }
   });
}
