# SPDX-License-Identifier: MIT
"""TMS320C28x Binary Ninja plugin.

Architecture support (decoder, lifter, calling convention) is provided by
the native Rust library. Python provides BinaryView plugins for:
  - ELF (word→byte address conversion)
  - TI COFF
  - Raw flash images (F28335)
  - Analysis cleanup tools
"""

import os
import ctypes

_plugin_dir = os.path.dirname(os.path.abspath(__file__))
_native_names = [
    "libtms320c28x_binja.so",  # Linux
    "libtms320c28x_binja.dylib",  # macOS
    "tms320c28x_binja.dll",  # Windows
]

for _name in _native_names:
    _path = os.path.join(_plugin_dir, _name)
    if os.path.exists(_path):
        try:
            _lib = ctypes.CDLL(_path)
            _lib.CorePluginInit.restype = ctypes.c_bool
            _lib.CorePluginInit()
            break
        except Exception as _e:
            try:
                from binaryninja import log_warn

                log_warn(f"C28x: failed to load native library {_name}: {_e}")
            except ImportError:
                pass

# Binary Ninja imports only this package's __init__ for a plugin folder — it
# does NOT separately import the sibling modules. Import them here so their
# BinaryView plugins and PluginCommands register. The dev deploy now ships the
# same folder (scripts/run_all_tests.sh), so this runs there too; it used to
# copy each module in as its own top-level plugin file, which is why they could
# not share one. Each import is guarded so one failure can't suppress the rest.
_command_modules = (
    "coff_plugin",  # TI COFF BinaryView
    "elf_plugin",  # C28x ELF BinaryView
    "flash",  # raw F28335 flash BinaryView
    "tools",  # Plugins > TMS320C28x > cleanup/memory-map/PIE/inline-data
    "dis_sidecar",  # Plugins > TMS320C28x > Import dumped.dis (seed funcs + data)
)
for _mod in _command_modules:
    try:
        __import__(f"{__name__}.{_mod}")
    except Exception as _e:
        try:
            from binaryninja import log_warn

            log_warn(f"C28x: failed to load plugin module {_mod}: {_e}")
        except ImportError:
            pass
