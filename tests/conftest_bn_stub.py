"""A stand-in `binaryninja` module so binja/ can be imported without a licence.

binja/ is the half that ships to users and had no test coverage at all, because
every module imports `binaryninja` at import time. This installs enough of a
stub to import them and exercise their pure logic.

BackgroundTaskThread must be a real class -- binja/tools.py subclasses it, and a
MagicMock attribute cannot be subclassed.
"""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


class _BackgroundTaskThread:
    def __init__(self, *args, **kwargs):
        self.progress = ""

    def start(self):
        pass


class _BinaryView:
    """Real class, like _BackgroundTaskThread and for the same reason.

    binja/flash.py, coff_plugin.py and elf_plugin.py subclass BinaryView and
    call `register()` at import time. Against a MagicMock the subclass could
    not even be created, so those three modules were simply not importable
    under the stub and their logic could not be tested at all.
    """

    def __init__(self, *args, **kwargs):
        self.parent_view = kwargs.get("parent_view")
        self.file = kwargs.get("file_metadata")

    @classmethod
    def register(cls, *args, **kwargs):
        pass

    def __getattr__(self, name):
        return MagicMock()


def install() -> None:
    """Idempotent, and never shadows a real binaryninja.

    sys.modules is process-global: installing over a licensed install makes
    every later module in the run believe it has BN when it has a MagicMock.
    """
    if sys.modules.get("binaryninja") is not None:
        return
    try:
        import binaryninja  # noqa: F401

        return
    except ImportError:
        pass

    bn = types.ModuleType("binaryninja")
    bn._c28x_stub = True
    bn.BackgroundTaskThread = _BackgroundTaskThread
    bn.BinaryView = _BinaryView
    for name in (
        "PluginCommand",
        "SectionSemantics",
        "SegmentFlag",
        "Symbol",
        "SymbolType",
        "Type",
        "BinaryViewType",
        "Architecture",
        "Platform",
        "interaction",
        "Endianness",
    ):
        setattr(bn, name, MagicMock())
    for name in ("log_info", "log_warn", "log_error", "log_debug"):
        setattr(bn, name, lambda *a, **k: None)

    for sub in (
        "architecture",
        "binaryview",
        "enums",
        "types",
        "interaction",
        "plugin",
    ):
        mod = types.ModuleType(f"binaryninja.{sub}")
        mod.__getattr__ = lambda _name: MagicMock()  # type: ignore[attr-defined]
        sys.modules[f"binaryninja.{sub}"] = mod
        setattr(bn, sub, mod)

    sys.modules["binaryninja"] = bn
