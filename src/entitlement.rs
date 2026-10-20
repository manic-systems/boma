use std::{
   env,
   ffi::c_void,
   fs,
   os::unix::process::CommandExt as _,
   path::Path,
   process::{
      self,
      Command,
   },
   ptr,
};

use misstep::{
   Report,
   Result,
   ResultExt as _,
   bail,
};
use objc2::rc::Retained;
use objc2_foundation::NSString;

const KEY: &str = "com.apple.security.virtualization";
const ENTITLEMENTS: &str = include_str!("entitlements.plist");
const RESIGNED: &str = "BOMA_RESIGNED";

#[expect(
   unsafe_code,
   reason = "Security.framework has no safe bindings in the tree"
)]
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
   fn SecTaskCreateFromSelf(allocator: *const c_void) -> *mut c_void;

   fn SecTaskCopyValueForEntitlement(
      task: *mut c_void,
      entitlement: *const c_void,
      error: *mut *mut c_void,
   ) -> *const c_void;
}

#[expect(
   unsafe_code,
   reason = "CoreFoundation has no safe bindings in the tree"
)]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
   static kCFBooleanTrue: *const c_void;

   fn CFRelease(object: *const c_void);
}

#[expect(
   unsafe_code,
   reason = "Security.framework has no safe bindings in the tree"
)]
fn entitled() -> bool {
   let key = NSString::from_str(KEY);

   // SAFETY: a null allocator selects the default one.
   let task = unsafe { SecTaskCreateFromSelf(ptr::null()) };

   if task.is_null() {
      return false;
   }

   // SAFETY: task is a live SecTask, NSString is toll-free bridged to CFString,
   // and a null error pointer is allowed.
   let value = unsafe {
      SecTaskCopyValueForEntitlement(task, Retained::as_ptr(&key).cast(), ptr::null_mut())
   };

   // SAFETY: kCFBooleanTrue is a framework constant initialized before main.
   let granted = !value.is_null() && value == unsafe { kCFBooleanTrue };

   // SAFETY: both came from Create or Copy calls, so each holds one reference
   // this function owns, and value is only released when non-null.
   unsafe {
      if !value.is_null() {
         CFRelease(value);
      }

      CFRelease(task);
   }

   granted
}

/// Signs this executable with the virtualization entitlement and re-runs it,
/// for `cargo install`.
pub fn ensure() -> Result<()> {
   if entitled() {
      return Ok(());
   }

   if env::var_os(RESIGNED).is_some() {
      bail!("{KEY} is still missing after signing");
   }

   let exe = env::current_exe().context("locating this executable")?;

   resign(&exe).with_context(|| {
      format!(
         "{} lacks {KEY}, run it once as its owner to sign it",
         exe.display()
      )
   })?;

   let error = Command::new(&exe)
      .args(env::args_os().skip(1))
      .env(RESIGNED, "1")
      .exec();

   Err(error)
      .with_context(|| format!("re-running {}", exe.display()))
      .map_err(Report::erase)
}

/// Signs a copy and renames it over, since re-signing a running binary in place
/// gets it killed.
fn resign(exe: &Path) -> Result<()> {
   let staged = exe.with_extension("signing");

   let plist = env::temp_dir().join(format!(
      "{}-{}.entitlements",
      env!("CARGO_PKG_NAME"),
      process::id()
   ));

   fs::write(&plist, ENTITLEMENTS).with_context(|| format!("writing {}", plist.display()))?;

   fs::copy(exe, &staged)
      .with_context(|| format!("copying {} to {}", exe.display(), staged.display()))?;

   let status = Command::new("/usr/bin/codesign")
      .args(["--force", "--sign", "-", "--entitlements"])
      .arg(&plist)
      .arg(&staged)
      .status()
      .context("running codesign");

   let _gone = fs::remove_file(&plist);

   if !status?.success() {
      let _gone = fs::remove_file(&staged);
      bail!("codesign could not sign {}", staged.display());
   }

   fs::rename(&staged, exe)
      .with_context(|| format!("replacing {} with {}", exe.display(), staged.display()))?;

   Ok(())
}
