use std::{
   collections::{
      BTreeMap,
      BTreeSet,
   },
   env,
   fs,
   io,
   path::{
      Path,
      PathBuf,
   },
   time::{
      SystemTime,
      UNIX_EPOCH,
   },
};

use misstep::{
   OptionExt as _,
   Result,
   ResultExt as _,
   ensure,
};
use pound::{
   FromArg,
   ValueError,
};
use serde::{
   Deserialize,
   Serialize,
};

/// The external-builders protocol revision this program speaks.
#[derive(Deserialize)]
#[serde(try_from = "u64")]
struct Version;

impl TryFrom<u64> for Version {
   type Error = String;

   fn try_from(version: u64) -> Result<Self, Self::Error> {
      if version == 1 {
         Ok(Self)
      } else {
         Err(format!("unsupported build.json version {version}"))
      }
   }
}

/// What the guest runs on, from the derivation's `system`.
#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum System {
   #[serde(rename = "aarch64-linux")]
   Aarch64,
   #[serde(rename = "x86_64-linux")]
   X86_64,
}

/// The parts of Nix's build.json the host acts on. The guest reads the
/// same file for the rest.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Build {
   #[serde(rename = "version")]
   _version:           Version,
   pub env:            BTreeMap<String, String>,
   pub top_tmp_dir:    PathBuf,
   tmp_dir:            PathBuf,
   tmp_dir_in_sandbox: PathBuf,
   store_dir:          PathBuf,
   pub real_store_dir: PathBuf,
   pub system:         System,
}

#[derive(Deserialize)]
struct Attrs {
   #[serde(rename = "outputHash")]
   output_hash: Option<String>,
   #[serde(rename = "__impure", default)]
   impure:      bool,
}

impl Build {
   pub fn load(path: &Path) -> Result<Self> {
      let text = fs::read(path).with_context(|| format!("reading {}", path.display()))?;

      serde_json::from_slice(&text)
         .with_context(|| format!("parsing {}", path.display()))
         .erase()
   }

   /// Whether Nix would run this derivation without a network namespace, a
   /// fixed-output or impure derivation. The guest decides by the same rule.
   pub fn networked(&self) -> Result<bool> {
      let hash = self
         .env
         .get("outputHash")
         .is_some_and(|hash| !hash.is_empty());

      let impure = self.env.get("__impure").is_some_and(|flag| flag == "1");

      if hash || impure {
         return Ok(true);
      }

      let Some(inside) = self.env.get("NIX_ATTRS_JSON_FILE") else {
         return Ok(false);
      };

      let relative = Path::new(inside)
         .strip_prefix(&self.tmp_dir_in_sandbox)
         .with_context(|| format!("NIX_ATTRS_JSON_FILE {inside} is outside the build directory"))?;

      let file = self.tmp_dir.join(relative);
      let text = fs::read(&file).with_context(|| format!("reading {}", file.display()))?;

      let attrs = serde_json::from_slice::<Attrs>(&text)
         .with_context(|| format!("parsing {}", file.display()))?;

      Ok(attrs.output_hash.is_some_and(|hash| !hash.is_empty()) || attrs.impure)
   }

   /// `NIX_BUILD_CORES`, where 0 asks for every core.
   pub fn cores(&self) -> Result<u32> {
      let cores = self
         .env
         .get("NIX_BUILD_CORES")
         .context("build.json has no NIX_BUILD_CORES")?;

      cores
         .parse::<u32>()
         .with_context(|| format!("NIX_BUILD_CORES {cores} is not a count"))
         .erase()
   }

   /// Resolves the guest's sandbox paths, staging every source outside the
   /// store under the build's top directory, the only other host directory
   /// the guest sees.
   pub fn stage(&self, paths: &[SandboxPath], network: bool, kvm: bool) -> Result<Sandbox> {
      let mut placed = Vec::new();
      let mut seen = BTreeSet::new();

      for (index, path) in paths.iter().enumerate() {
         if !seen.insert(path.target.as_str()) {
            continue;
         }

         if let Some(source) = self.resolve(&path.source, path.optional, &index.to_string())? {
            placed.push(Placed {
               target: path.target.clone(),
               source,
               optional: path.optional,
            });
         }
      }

      let ca_file = if network { self.ca_file()? } else { None };

      if network {
         self.stage_services()?;
      }

      Ok(Sandbox {
         file: self.top_tmp_dir.join("sandbox.json"),
         paths: placed,
         kvm,
         ca_file,
      })
   }

   /// A store source as is, or a staged copy of a regular file elsewhere.
   /// [`None`] for a missing optional source.
   fn resolve(&self, source: &Path, optional: bool, name: &str) -> Result<Option<PathBuf>> {
      let real = source
         .strip_prefix(&self.store_dir)
         .ok()
         .map(|relative| self.real_store_dir.join(relative));

      let found = real
         .as_ref()
         .map_or_else(|| fs::metadata(source), fs::symlink_metadata)
         .map(Some)
         .with_context(|| format!("sandbox path {}", source.display()))
         .recover_if::<io::Error, _>(|error| {
            (optional && error.kind() == io::ErrorKind::NotFound).then_some(None)
         })?;

      let Some(found) = found else {
         return Ok(None);
      };

      if real.is_some() {
         return Ok(Some(source.to_path_buf()));
      }

      if optional && !found.is_file() {
         return Ok(None);
      }

      ensure!(
         found.is_file(),
         "sandbox path {} is outside the store and not a regular file",
         source.display()
      );

      let staging = self.top_tmp_dir.join("sandbox-paths");
      fs::create_dir_all(&staging).with_context(|| format!("creating {}", staging.display()))?;
      let staged = staging.join(name);

      fs::copy(source, &staged)
         .with_context(|| format!("staging {} for the guest", source.display()))?;

      Ok(Some(staged))
   }

   /// Nix binds the daemon host's /etc/services into a fixed-output chroot,
   /// and the guest takes it from `<topTmpDir>/services`.
   fn stage_services(&self) -> Result<()> {
      fs::copy("/etc/services", self.top_tmp_dir.join("services"))
         .map(|_bytes| ())
         .context("staging /etc/services for the guest")
         .recover_if::<io::Error, _>(|error| {
            (error.kind() == io::ErrorKind::NotFound).then_some(())
         })
   }

   /// The CA bundle Nix's `ssl-cert-file` defaults to, the first of these
   /// that exists.
   fn ca_file(&self) -> Result<Option<PathBuf>> {
      let candidates = ["NIX_SSL_CERT_FILE", "SSL_CERT_FILE"]
         .into_iter()
         .filter_map(env::var_os)
         .map(PathBuf::from)
         .chain(
            [
               "/etc/ssl/certs/ca-certificates.crt",
               "/nix/var/nix/profiles/default/etc/ssl/certs/ca-bundle.crt",
            ]
            .map(PathBuf::from),
         );

      for candidate in candidates {
         if let Some(found) = self.resolve(&candidate, true, "ca-file")? {
            return Ok(Some(found));
         }
      }

      Ok(None)
   }
}

/// The guest's sandbox.json, written just before the guest boots so the
/// clock it carries is current.
pub struct Sandbox {
   file:    PathBuf,
   paths:   Vec<Placed>,
   kvm:     bool,
   ca_file: Option<PathBuf>,
}

impl Sandbox {
   /// Writes the file with the host's wall clock, since the guest has no RTC.
   pub fn write(&self) -> Result<()> {
      let clock_nanos = SystemTime::now()
         .duration_since(UNIX_EPOCH)
         .context("the host clock is before 1970")?
         .as_nanos();

      let text = serde_json::to_vec(&SandboxFile {
         paths:       &self.paths,
         kvm:         self.kvm,
         ca_file:     self.ca_file.as_deref(),
         clock_nanos: u64::try_from(clock_nanos)
            .context("the host clock is past 64-bit nanoseconds")?,
      })
      .context("serializing sandbox.json")?;

      fs::write(&self.file, text)
         .with_context(|| format!("writing {}", self.file.display()))
         .erase()
   }
}

/// Every store path a closure file lists, `closureInfo`'s `store-paths`, as an
/// identity sandbox path, since Nix adds the closure of each store source.
pub fn closure_paths(files: &[PathBuf]) -> Result<Vec<SandboxPath>> {
   let mut paths = Vec::new();

   for file in files {
      let text = fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;

      for line in text.lines().filter(|line| !line.is_empty()) {
         paths.push(SandboxPath {
            target:   line.to_owned(),
            source:   PathBuf::from(line),
            optional: false,
         });
      }
   }

   Ok(paths)
}

/// `TARGET=SOURCE` or `PATH`, with a trailing `?` when a missing source is
/// fine, as in Nix's `sandbox-paths`.
#[derive(Clone)]
pub struct SandboxPath {
   target:   String,
   source:   PathBuf,
   optional: bool,
}

impl FromArg for SandboxPath {
   fn from_arg(raw: &str) -> Result<Self, ValueError> {
      let (spec, optional) = raw
         .strip_suffix('?')
         .map_or((raw, false), |bare| (bare, true));

      let (target, source) = spec.split_once('=').unwrap_or((spec, spec));

      if !target.starts_with('/') || !source.starts_with('/') {
         return Err(ValueError::new(raw, "sandbox paths are absolute"));
      }

      Ok(Self {
         target: target.to_owned(),
         source: PathBuf::from(source),
         optional,
      })
   }
}

#[derive(Serialize)]
struct Placed {
   target:   String,
   source:   PathBuf,
   optional: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SandboxFile<'sandbox> {
   paths:       &'sandbox [Placed],
   kvm:         bool,
   #[serde(skip_serializing_if = "Option::is_none")]
   ca_file:     Option<&'sandbox Path>,
   clock_nanos: u64,
}
