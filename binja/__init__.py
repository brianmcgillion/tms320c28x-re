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
    "libtms320c28x_binja.so",      # Linux
    "libtms320c28x_binja.dylib",    # macOS
    "tms320c28x_binja.dll",         # Windows
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
