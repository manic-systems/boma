# boma

boma builds Linux derivations on Apple Silicon Macs. It's a Nix [external-builders] program, so
instead of shipping a build off to some Linux box, Nix hands it to boma, which boots a throwaway
Virtualization.framework VM just for that build. x86_64-linux works too, through Rosetta.

The VM boots straight into an initrd with the host store and the build directory mounted over virtiofs.

boma doesn't ship a kernel or initrd. [The guest](#the-guest) covers what yours needs to do.

## Usage

On nix-darwin, import `darwinModules.default` and set

```nix
services.boma = {
  enable = true;
  kernel = "${guest-kernel}/Image";
  initrd = "${guest-initrd}/initrd";
  sandboxPaths."/bin/sh" = "${busybox}/bin/busybox";
};
```

`cargo install boma` works too, but run `boma` once yourself afterwards. It signs itself with the
virtualization entitlement on first run, and Nix's build users can't write to `~/.cargo/bin`.

## Caveats

- Remote builders take priority over external builders, so if `/etc/nix/machines` lists a Linux machine
  for a system, Nix will keep sending builds there.
- `/nix` has to be case-sensitive, since outputs get written straight into the host store. The module
  won't activate on a case-insensitive volume unless you set `allowCaseInsensitiveStore`.
- Fixed-output derivations get network access through the VM's NAT. DNS is relayed to the first
  `nameserver` in `/etc/resolv.conf` that accepts TCP, so scoped resolvers (`/etc/resolver/*`,
  Tailscale split DNS) don't apply inside builds.

## How it works

boma reads the `build.json` Nix writes, boots the guest with one CPU per build core, and pipes the
guest console into the build log. The guest reports over vsock once when it boots and again when the
builder exits, and boma exits with the builder's status. If the guest reboots, which usually means a
kernel panic, or never comes up at all, boma kills it and fails the build.

## The guest

The kernel has to be an uncompressed arm64 `Image` with the virtio console, virtiofs, vsock, virtio-net
and virtio-blk drivers built in. boma boots it with `console=hvc0 rdinit=/init`, so the initrd's `/init`
is where the actual sandboxing happens. It's expected to

- mount the virtiofs shares tagged `store` and `build`, plus `rosetta` for x86_64-linux builds
- read `build.json` and `sandbox.json` from the build share, set the clock from `clockNanos` since the
  guest has no RTC, and set up Nix's Linux sandbox from the two
- send `boot` to host vsock port 1 as soon as it starts, then print Nix's sandbox-ready marker on the
  console
- run the builder, send `exit <code>` or `signal <number>` (the Linux signal number) on a new connection
  to the same port, and power off

Networked builds also get `ip=dhcp` on the kernel command line and a DNS relay on vsock port 53. When
`--scratch` is nonzero, a sparse virtio-blk disk shows up for the guest to swap to.

Each `--socket` path is listed in `sandbox.json` under `sockets` with a vsock port, counting up from
1024. The guest should listen on the same path and pass each connection through to that port, where
boma connects it to the host's socket.

## License

[EUPL-1.2](LICENSE)

[external-builders]: https://nix.dev/manual/nix/latest/command-ref/conf-file#conf-external-builders
