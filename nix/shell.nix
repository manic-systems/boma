{
  mkShell,
  rustc,
  cargo,
  rust-analyzer,
  rustfmt,
  clippy,
  taplo,
  rustPlatform,
  darwin,
  extraPackages ? [ ],
}:
mkShell {
  strictDeps = true;

  nativeBuildInputs = [
    rustc
    cargo
    rust-analyzer
    rustfmt
    clippy
    taplo
    darwin.sigtool
  ]
  ++ extraPackages;

  env.RUST_SRC_PATH = "${rustPlatform.rustLibSrc}";
}
