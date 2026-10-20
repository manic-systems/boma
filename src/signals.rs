//! Host signal masks, and the signals the Linux guest reports by number.

#![expect(unsafe_code, reason = "libc has no safe signal calls")]

use std::{
   io,
   iter,
   mem::MaybeUninit,
   num::ParseIntError,
   ptr,
   str::FromStr,
};

/// A signal the guest's builder died of, by its Linux number.
#[derive(Clone, Copy)]
pub struct Signal(u8);

impl FromStr for Signal {
   type Err = ParseIntError;

   fn from_str(number: &str) -> Result<Self, Self::Err> {
      number.parse().map(Self)
   }
}

impl Signal {
   /// The Darwin equivalent, for signals that kill by default on both.
   const fn darwin(self) -> Option<libc::c_int> {
      Some(match self.0 {
         1 => libc::SIGHUP,
         2 => libc::SIGINT,
         3 => libc::SIGQUIT,
         4 => libc::SIGILL,
         5 => libc::SIGTRAP,
         6 => libc::SIGABRT,
         7 => libc::SIGBUS,
         8 => libc::SIGFPE,
         9 => libc::SIGKILL,
         10 => libc::SIGUSR1,
         11 => libc::SIGSEGV,
         12 => libc::SIGUSR2,
         13 => libc::SIGPIPE,
         14 => libc::SIGALRM,
         15 => libc::SIGTERM,
         24 => libc::SIGXCPU,
         25 => libc::SIGXFSZ,
         26 => libc::SIGVTALRM,
         27 => libc::SIGPROF,
         31 => libc::SIGSYS,
         _ => return None,
      })
   }

   /// The shell's status for a process this signal killed.
   pub const fn exit_status(self) -> u8 {
      128_u8.saturating_add(self.0)
   }

   /// Kills this process with the same signal, its default action restored
   /// and the signal unblocked on this thread.
   ///
   /// # Returns
   ///
   /// Returns where Darwin has no equivalent.
   pub fn raise(self) {
      let Some(signal) = self.darwin() else {
         return;
      };
      // SAFETY: restoring a signal's default action has no preconditions.
      unsafe { libc::signal(signal, libc::SIG_DFL) };
      let _unblocked = iter::once(signal).collect::<SignalSet>().unblock();
      // SAFETY: raise delivers to this thread, which no longer blocks it.
      unsafe { libc::raise(signal) };
   }
}

/// A [`sigset_t`](libc::sigset_t), which every libc signal-mask call takes.
pub struct SignalSet(libc::sigset_t);

impl FromIterator<libc::c_int> for SignalSet {
   fn from_iter<I>(signals: I) -> Self
   where
      I: IntoIterator<Item = libc::c_int>,
   {
      let mut set = MaybeUninit::<libc::sigset_t>::uninit();
      // SAFETY: sigemptyset initializes the set before sigaddset reads it.
      unsafe {
         libc::sigemptyset(set.as_mut_ptr());
         for signal in signals {
            libc::sigaddset(set.as_mut_ptr(), signal);
         }
         Self(set.assume_init())
      }
   }
}

impl SignalSet {
   /// Blocks the set on this thread and every thread it spawns afterwards.
   pub fn block(&self) -> io::Result<()> {
      self.mask(libc::SIG_BLOCK)
   }

   pub fn unblock(&self) -> io::Result<()> {
      self.mask(libc::SIG_UNBLOCK)
   }

   fn mask(&self, how: libc::c_int) -> io::Result<()> {
      // SAFETY: the set is initialized, and the old mask is not asked for.
      match unsafe { libc::pthread_sigmask(how, &raw const self.0, ptr::null_mut()) } {
         0 => Ok(()),
         code => Err(io::Error::from_raw_os_error(code)),
      }
   }

   /// Waits for one of the set's signals, which must be blocked on every
   /// thread so none is delivered elsewhere first.
   pub fn wait(&self) -> io::Result<libc::c_int> {
      let mut signal = 0;
      // SAFETY: the set is initialized and signal is a valid out pointer.
      match unsafe { libc::sigwait(&raw const self.0, &raw mut signal) } {
         0 => Ok(signal),
         code => Err(io::Error::from_raw_os_error(code)),
      }
   }
}
