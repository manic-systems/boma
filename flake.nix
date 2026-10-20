{
  inputs = {
    nixpkgs.url = "https://channels.nixos.org/nixpkgs-unstable/nixexprs.tar.xz";

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, ... }@inputs:
    let
      inherit (inputs) nixpkgs fenix;
      inherit (nixpkgs) lib;
      systems = [ "aarch64-darwin" ];
      linuxSystems = [
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAllSystems = lib.genAttrs systems;
      forDevSystems = lib.genAttrs (systems ++ linuxSystems);
      pkgsFor = system: nixpkgs.legacyPackages.${system};
      name = (lib.importTOML ./Cargo.toml).package.name;
    in
    {
      packages = forAllSystems (
        system:
        let
          package = (pkgsFor system).callPackage ./nix/package.nix { };
        in
        {
          ${name} = package;
          default = package;
        }
      );

      devShells = forDevSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.callPackage ./nix/shell.nix {
            rustfmt = fenix.packages.${system}.latest.rustfmt or pkgs.rustfmt;
          };
        }
      );

      checks = forAllSystems (system: {
        ${name} = self.packages.${system}.${name};
      });

      darwinModules.default = import ./nix/darwin-module.nix self;
    };
}
