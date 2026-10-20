//! DNS for networked guests, spliced over TCP and vsock to the host's resolver,
//! since the NAT's 192.168.64.1 answers nothing behind a local resolver.

use std::{
   fs,
   io,
   net::{
      IpAddr,
      Shutdown,
      SocketAddr,
      TcpStream,
   },
   os::unix::net::UnixStream,
   thread,
   time::Duration,
};

/// The vsock port a networked guest's resolver forwards to.
pub const DNS_PORT: u32 = 53;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// The `nameserver` lines of /etc/resolv.conf, which macOS keeps in step
/// with its primary resolvers.
fn upstreams() -> Vec<SocketAddr> {
   let Ok(text) = fs::read_to_string("/etc/resolv.conf") else {
      return Vec::new();
   };

   text
      .lines()
      .filter_map(|line| line.strip_prefix("nameserver"))
      .filter_map(|address| {
         let address = address.trim();

         let bare = address
            .split_once('%')
            .map_or(address, |(bare, _scope)| bare);

         bare.parse::<IpAddr>().ok()
      })
      .map(|address| SocketAddr::new(address, 53))
      .collect()
}

fn connect() -> Option<TcpStream> {
   upstreams()
      .iter()
      .find_map(|address| TcpStream::connect_timeout(address, CONNECT_TIMEOUT).ok())
}

/// Splices one guest connection to the first upstream that answers, closing
/// it when none does. Errors only end the connection, the guest retries.
pub fn relay(guest: UnixStream) {
   thread::spawn(move || -> io::Result<()> {
      let Some(upstream) = connect() else {
         return guest.shutdown(Shutdown::Both);
      };

      let (mut guest_reader, mut upstream_writer) = (guest.try_clone()?, upstream.try_clone()?);

      let forward = thread::spawn(move || {
         let _copied = io::copy(&mut guest_reader, &mut upstream_writer);
         let _closed = upstream_writer.shutdown(Shutdown::Write);
      });

      let (mut upstream_reader, mut guest_writer) = (upstream, guest);
      let _copied = io::copy(&mut upstream_reader, &mut guest_writer);
      let _closed = guest_writer.shutdown(Shutdown::Write);
      let _joined = forward.join();
      Ok(())
   });
}
