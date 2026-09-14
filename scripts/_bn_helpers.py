"""Shared helpers for BN headless validation scripts."""

import os
import shutil
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


def load_binja_module(name):
    """Import one `binja` module as part of its package.

    These were each loaded standalone with spec_from_file_location, which gives
    the module no parent package -- so `from .memmap import ...` raised
    ImportError and the modules could not share code at all. Binary Ninja
    imports the shipped `tms320c28x/` folder as a package, so this is also the
    faithful thing to do.
    """
    import importlib

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)
    return importlib.import_module(f"binja.{name}")


def native_plugin_path():
    """The deployed Rust library: inside the `tms320c28x/` package, or flat.

    package.sh ships it beside __init__.py, which loads it from its own
    directory; the flat path is only what older deploys left behind.
    """
    plugins = os.path.expanduser("~/.binaryninja/plugins")
    for p in (
        os.path.join(plugins, "tms320c28x", "libtms320c28x_binja.so"),
        os.path.join(plugins, "libtms320c28x_binja.so"),
    ):
        if os.path.isfile(p):
            return p
    return None


def init_bn():
    """Initialize BN headless with our plugin. Returns the binaryninja module."""
    bn_dir = find_bn_dir()

    sys.path.insert(0, os.path.join(bn_dir, "python"))
    os.environ["LD_LIBRARY_PATH"] = bn_dir + ":" + os.environ.get("LD_LIBRARY_PATH", "")

    # Load BN core and our plugin
    ctypes.CDLL(os.path.join(bn_dir, "libbinaryninjacore.so.1"))
    plugin_path = native_plugin_path()
    if plugin_path is None:
        print("ERROR: libtms320c28x_binja.so not found in ~/.binaryninja/plugins")
        sys.exit(1)

    plugin = ctypes.CDLL(plugin_path)
    plugin.CorePluginInit.restype = ctypes.c_bool
    if not plugin.CorePluginInit():
        print("ERROR: CorePluginInit returned false")
        sys.exit(1)

    import binaryninja

    return binaryninja


def find_func(bv, name):
    """Find a function by source name, tolerating cl2000's leading underscore.

    The case-insensitive fallback is deliberate and only runs when the exact
    match fails, so it can widen a lookup but never narrow one.
    """
    for f in bv.functions:
        fn = f.name
        if fn == name or fn == f"_{name}" or fn.endswith(f"_{name}"):
            return f
        if fn.lower() == name.lower() or fn.lower() == f"_{name.lower()}":
            return f
    return None


def get_hlil_text(func):
    """HLIL as text, or None when BN cannot produce it."""
    try:
        hlil = func.hlil
        if hlil:
            return str(hlil)
    except Exception:
        pass
    return None


def load_c28x(binaryninja, filepath):
    """Load a C28x binary (ELF, COFF, or raw) with proper address handling.

    In headless mode, Python BinaryView plugins don't auto-register.
    This function handles ELF word→byte conversion manually.
    """

    with open(filepath, "rb") as f:
        header = f.read(4)

    # Check format
    if header[:4] == b"\x7fELF":
        # ELF — use our Python ELF loader for word→byte conversion.
        # Must load as Raw first (not BN's ELF loader which uses wrong addresses).
        elf_mod_path = os.path.join(
            os.path.dirname(__file__), "..", "binja", "elf_plugin.py"
        )
        if os.path.exists(elf_mod_path):
            # Load file as Raw BinaryView
            raw_bv = binaryninja.BinaryViewType["Raw"].open(filepath)
            if raw_bv is None:
                return None

            mod = load_binja_module("elf_plugin")

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
        coff_mod_path = os.path.join(
            os.path.dirname(__file__), "..", "binja", "coff_plugin.py"
        )
        if os.path.exists(coff_mod_path):
            raw_bv = binaryninja.load(filepath)
            if raw_bv is None:
                return None

            mod = load_binja_module("coff_plugin")

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
