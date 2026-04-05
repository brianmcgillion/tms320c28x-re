# SPDX-License-Identifier: MIT
"""TMS320C28x Binary Ninja architecture plugin.

When loaded as a BN plugin (via ~/.binaryninja/plugins/), registration
is handled by the loader script. When imported directly, call register()
on the classes yourself.
"""

from .arch import TMS320C28x
from .view import TICOFFView

__all__ = ["TMS320C28x", "TICOFFView"]
