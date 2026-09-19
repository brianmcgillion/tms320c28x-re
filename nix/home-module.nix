# SPDX-License-Identifier: MIT
#
# Link the built plugin into Binary Ninja's plugin directory. No `binaryninja`
# option: nix/plugin.nix needs no installation to compile.
{ self, version }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.tms320c28x;

  pluginDir =
    if pkgs.stdenv.hostPlatform.isDarwin then
      "Library/Application Support/Binary Ninja/plugins/tms320c28x"
    else
      ".binaryninja/plugins/tms320c28x";
in
{
  options.programs.tms320c28x = {
    enable = lib.mkEnableOption "the TMS320C28x Binary Ninja plugin";

    package = lib.mkOption {
      type = lib.types.package;
      # From source, so the module works without overlays.default applied.
      default = pkgs.callPackage "${self}/nix/plugin.nix" {
        src = self;
        inherit version;
      };
      defaultText = lib.literalMD "`tms320c28x-binja` built from this flake";
      description = "The plugin directory to install.";
    };
  };

  config = lib.mkIf cfg.enable {
    home.file.${pluginDir}.source = cfg.package;
  };
}
