self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    concatMap
    getExe
    mapAttrsToList
    mkAfter
    mkEnableOption
    mkIf
    mkOption
    optional
    optionals
    types
    ;

  name = (lib.importTOML ../Cargo.toml).package.name;
  cfg = config.services.${name};

  # Nix binds the closure of every store source in sandbox-paths, so the guest gets the same list.
  storeSources = lib.pipe cfg.sandboxPaths [
    builtins.attrValues
    (map (source: lib.removeSuffix "?" source))
    (builtins.filter (source: lib.hasPrefix "${builtins.storeDir}/" source))
    (map (
      source:
      builtins.substring 0 (builtins.stringLength (
        lib.head (builtins.match "(${builtins.storeDir}/[^/]+).*" source)
      )) source
    ))
  ];
  closure = pkgs.closureInfo { rootPaths = storeSources; };

  args = [
    "--kernel"
    "${cfg.kernel}"
    "--initrd"
    "${cfg.initrd}"
    "--memory"
    (toString cfg.memory)
    "--loglevel"
    (toString cfg.loglevel)
    "--boot-timeout"
    (toString cfg.bootTimeout)
    "--scratch"
    (toString cfg.scratch)
  ]
  ++ optionals (storeSources != [ ]) [
    "--sandbox-closure"
    "${closure}/store-paths"
  ]
  ++ optionals (cfg.cpus != null) [
    "--cpus"
    (toString cfg.cpus)
  ]
  ++ optional cfg.kvm "--kvm"
  ++ concatMap (path: [
    "--sandbox-path"
    path
  ]) (mapAttrsToList (target: source: "${target}=${source}") cfg.sandboxPaths);
in
{
  options.services.${name} = {
    enable = mkEnableOption "building Linux derivations in a fresh Virtualization.framework guest per derivation";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalMD "this flake's package";
      description = "The external builder program.";
    };

    kernel = mkOption {
      type = types.path;
      description = "The guest's uncompressed kernel Image.";
    };

    initrd = mkOption {
      type = types.path;
      description = "The guest's initrd, whose /init sandboxes and runs the builder.";
    };

    memory = mkOption {
      type = types.ints.positive;
      default = 8192;
      description = "Guest memory in MiB, clamped to physical memory.";
    };

    scratch = mkOption {
      type = types.ints.unsigned;
      default = 65536;
      description = "MiB of sparse scratch disk each guest swaps its tmpfs to, 0 for none.";
    };

    cpus = mkOption {
      type = types.nullOr types.ints.positive;
      default = null;
      description = "Guest CPUs, or null for each build's cores setting.";
    };

    systems = mkOption {
      type = types.listOf (
        types.enum [
          "aarch64-linux"
          "x86_64-linux"
        ]
      );
      default = [ "aarch64-linux" ];
      description = "Systems routed to the guest. x86_64-linux runs under Rosetta.";
    };

    sandboxPaths = mkOption {
      type = types.attrsOf types.str;
      default = { };
      example = lib.literalExpression ''{ "/bin/sh" = "''${pkgs.pkgsLinux.busybox-sandbox-shell}/bin/busybox"; }'';
      description = ''
        Paths bound into every build's sandbox, as Nix's sandbox-paths. The daemon does not
        pass its own sandbox-paths to external builders. The closure of each store source is
        bound too, a trailing `?` makes a missing source fine.
      '';
    };

    kvm = mkOption {
      type = types.bool;
      default = false;
      description = "Give builds /dev/kvm through nested virtualization where the host supports it.";
    };

    loglevel = mkOption {
      type = types.ints.between 0 8;
      default = 4;
      description = "The guest kernel's console log level, its messages land in build logs.";
    };

    bootTimeout = mkOption {
      type = types.ints.positive;
      default = 30;
      description = "Seconds the guest kernel may take to reach init before the build fails.";
    };

    allowCaseInsensitiveStore = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Allow a case-insensitive /nix volume. Guests write outputs straight into the host store,
        so Linux trees with names differing only in case silently clobber each other there.
      '';
    };
  };

  config = mkIf cfg.enable {
    nix.settings = {
      extra-experimental-features = [ "external-builders" ];
      external-builders = builtins.toJSON [
        {
          inherit (cfg) systems;
          program = getExe cfg.package;
          inherit args;
        }
      ];
    };

    system.checks.text = mkIf (!cfg.allowCaseInsensitiveStore) (mkAfter ''
      if [ "$(id -u)" -eq 0 ]; then
      probe=$(mktemp -d /nix/var/case-probe.XXXXXX)
      touch "$probe/a" "$probe/A"
      count=$(ls "$probe" | wc -l)
      rm -rf "$probe"
      if [ "$count" -ne 2 ]; then
        printf >&2 'error: /nix is case-insensitive, Linux builds in the guest would clobber files\n'
        printf >&2 'that differ only in case. Move /nix to a case-sensitive APFS volume or set\n'
        printf >&2 'services.${name}.allowCaseInsensitiveStore.\n'
        exit 2
      fi
      fi
    '');
  };
}
