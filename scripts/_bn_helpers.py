"""Shared helpers for BN headless validation scripts."""

import os
import shutil
import subprocess
import sys
import ctypes


def find_bn_dir():
    """Find Binary Ninja install directory from PATH or BINARYNINJADIR env."""
    # Check env var first
    bn_dir = os.environ.get("BINARYNINJADIR", "")
    if bn_dir and os.path.isfile(os.path.join(bn_dir, "libbinaryninjacore.so.1")):
        return bn_dir

    # Derive from `which binaryninja`
    bn_bin = shutil.which("binaryninja")
    if bn_bin:
        real = os.path.realpath(bn_bin)
        prefix = os.path.dirname(os.path.dirname(real))
        candidate = os.path.join(prefix, "opt", "binaryninja")
        if os.path.isfile(os.path.join(candidate, "libbinaryninjacore.so.1")):
            return candidate

    print("ERROR: Binary Ninja not found. Install BN or set BINARYNINJADIR.")
    sys.exit(1)


def init_bn():
    """Initialize BN headless with our plugin. Returns the binaryninja module."""
    bn_dir = find_bn_dir()

    sys.path.insert(0, os.path.join(bn_dir, "python"))
    os.environ["LD_LIBRARY_PATH"] = bn_dir + ":" + os.environ.get("LD_LIBRARY_PATH", "")

    # Load BN core and our plugin
    ctypes.CDLL(os.path.join(bn_dir, "libbinaryninjacore.so.1"))
    plugin_path = os.path.expanduser("~/.binaryninja/plugins/libtms320c28x_binja.so")
    if not os.path.isfile(plugin_path):
        print(f"ERROR: Plugin not found at {plugin_path}")
        sys.exit(1)

    plugin = ctypes.CDLL(plugin_path)
    plugin.CorePluginInit.restype = ctypes.c_bool
    if not plugin.CorePluginInit():
        print("ERROR: CorePluginInit returned false")
        sys.exit(1)

    import binaryninja
    return binaryninja


def load_c28x(binaryninja, filepath):
    """Load a C28x binary (ELF, COFF, or raw) with proper address handling.

    In headless mode, Python BinaryView plugins don't auto-register.
    This function handles ELF word→byte conversion manually.
    """
    import struct

    with open(filepath, "rb") as f:
        header = f.read(4)

    # Check format
    if header[:4] == b"\x7fELF":
        # ELF — use our Python ELF loader for word→byte conversion.
        # Must load as Raw first (not BN's ELF loader which uses wrong addresses).
        import importlib.util
        elf_mod_path = os.path.join(os.path.dirname(__file__), "..", "binja", "elf_plugin.py")
        if os.path.exists(elf_mod_path):
            # Load file as Raw BinaryView
            raw_bv = binaryninja.BinaryViewType["Raw"].open(filepath)
            if raw_bv is None:
                return None

            # Import and instantiate our ELF view
            spec = importlib.util.spec_from_file_location("elf_plugin", elf_mod_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            if mod.C28xELFView.is_valid_for_data(raw_bv):
                view = mod.C28xELFView(raw_bv)
                if view.init():
                    view.update_analysis_and_wait()
                    return view

            raw_bv.file.close()

        # Fallback
        return binaryninja.load(filepath, options={"loader.platform": "tms320c28x"})

    elif len(header) >= 2 and (header[0] | (header[1] << 8)) == 0x00C2:
        # COFF — use our Python COFF loader
        import importlib.util
        coff_mod_path = os.path.join(os.path.dirname(__file__), "..", "binja", "coff_plugin.py")
        if os.path.exists(coff_mod_path):
            raw_bv = binaryninja.load(filepath)
            if raw_bv is None:
                return None

            spec = importlib.util.spec_from_file_location("coff_plugin", coff_mod_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            if mod.TICOFFView.is_valid_for_data(raw_bv):
                view = mod.TICOFFView(raw_bv)
                if view.init():
                    view.update_analysis_and_wait()
                    return view

            raw_bv.file.close()

        return binaryninja.load(filepath, options={"loader.platform": "tms320c28x"})

    else:
        # Raw binary — use BN's loader with platform hint
        return binaryninja.load(filepath, options={"loader.platform": "tms320c28x"})
