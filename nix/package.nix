{
  lib,
  rustPlatform,
  darwin,
}:
let
  cargoTOML = (lib.importTOML ../Cargo.toml).package;
in
rustPlatform.buildRustPackage {
  pname = cargoTOML.name;
  inherit (cargoTOML) version;

  src =
    let
      fs = lib.fileset;
      s = ../.;
    in
    fs.toSource {
      root = s;
      fileset = fs.unions [
        (s + /src)
        (s + /Cargo.lock)
        (s + /Cargo.toml)
      ];
    };

  cargoLock.lockFile = ../Cargo.lock;

  strictDeps = true;
  enableParallelBuilding = true;

  nativeBuildInputs = [ darwin.sigtool ];

  # Virtualization.framework refuses processes without this entitlement, and
  # signing after fixup keeps strip from invalidating the signature.
  postFixup = ''
    codesign --entitlements ${../src/entitlements.plist} --force --sign - $out/bin/${cargoTOML.name}
  '';

  meta = {
    inherit (cargoTOML) description;
    license = lib.licenses.eupl12;
    maintainers = with lib.maintainers; [ amaanq ];
    platforms = lib.platforms.darwin;
    mainProgram = cargoTOML.name;
  };
}
