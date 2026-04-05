"""Remove false function entries created by BN's orphan block detection.

BN's auto-analysis creates functions at unconditional branch targets that
are actually mid-function blocks or shared epilogues. This script identifies
and removes them based on:
  1. Not a call target (LCR/LC/FFC/XCALL)
  2. No ADDB SP prologue
  3. No user-defined symbol

Run from Binary Ninja's Python console:
    exec(open("/home/brian/projects/code/github.com/brianmcgillion/tms320c28x-re/scripts/cleanup_false_functions.py").read())
"""

import sys
from pathlib import Path

_root = str(Path(__file__).resolve().parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

from c28x.decoder import Decoder
from c28x.types import BranchType
from c28x.util import bytes_to_opcode16

import binaryninja
from binaryninja import SymbolType

# Get the active binary view
bv = None
try:
    ctx = binaryninja.UIContext.allContexts()
    if ctx:
        bv = ctx[0].getCurrentViewFrame().getCurrentBinaryView()
except Exception:
    pass

if bv is None:
    print("Could not get active view. Set bv manually and re-run.")
else:
    print(f"Binary: {bv.file.filename}")
    print(f"Architecture: {bv.arch}")
    print(f"Functions before cleanup: {len(bv.functions)}")

    CODE_START = 0x610000
    CODE_END = 0x64C000

    data = bv.read(CODE_START, CODE_END - CODE_START)
    if len(data) < 1000:
        print(f"ERROR: Could not read code region (got {len(data)} bytes)")
    else:
        d = Decoder(objmode=1)

        # Pass 1: collect all direct call targets
        call_targets = set()
        offset = 0
        while offset < len(data) - 3:
            chunk = data[offset:offset + 4]
            insn = d.decode(chunk, addr=CODE_START + offset)
            if insn:
                if insn.branch_type == BranchType.CALL and insn.branch_target is not None:
                    call_targets.add(insn.branch_target)
                offset += insn.size
            else:
                offset += 2

        # Pass 2: collect addresses with ADDB SP prologues
        prologue_addrs = set()
        offset = 0
        while offset < len(data) - 1:
            op16 = bytes_to_opcode16(data[offset:offset + 2])
            if (op16 & 0xFF80) == 0xFE00:
                prologue_addrs.add(CODE_START + offset)
            offset += 2

        # Collect addresses with user-defined or imported symbols
        symbol_addrs = set()
        for sym in bv.get_symbols():
            if sym.type in (SymbolType.FunctionSymbol, SymbolType.ImportedFunctionSymbol):
                symbol_addrs.add(sym.address)

        # Identify false function entries
        false_funcs = []
        for func in bv.functions:
            addr = func.start
            if addr < CODE_START or addr >= CODE_END:
                continue
            # Keep if it's a call target
            if addr in call_targets:
                continue
            # Keep if it has a prologue
            if addr in prologue_addrs:
                continue
            # Keep if it has a symbol
            if addr in symbol_addrs:
                continue
            # Keep the entry point
            if addr == bv.entry_point:
                continue
            false_funcs.append(func)

        print(f"\nAnalysis:")
        print(f"  Call targets: {len(call_targets)}")
        print(f"  Prologue addresses: {len(prologue_addrs)}")
        print(f"  Symbol addresses: {len(symbol_addrs)}")
        print(f"  False function candidates: {len(false_funcs)}")

        if not false_funcs:
            print("\nNo false functions found.")
        else:
            # Show first 20 for review
            print(f"\nFirst 20 false function candidates:")
            for func in sorted(false_funcs, key=lambda f: f.start)[:20]:
                # Read first instruction at func start
                first_bytes = bv.read(func.start, 4)
                first_insn = d.decode(first_bytes, func.start) if first_bytes else None
                name = first_insn.name if first_insn else "???"
                print(f"  0x{func.start:06X}  {func.name:<30s}  first: {name}")

            print(f"\nRemove {len(false_funcs)} false function entries? (y/n)")
            # Auto-proceed in script mode; in interactive mode, uncomment the input:
            # response = input()
            # if response.strip().lower() != 'y':
            #     print("Aborted.")
            # else:

            print("Removing false functions...")
            removed = 0
            for func in false_funcs:
                bv.remove_user_function(func)
                removed += 1
                if removed % 100 == 0:
                    print(f"  Removed {removed}/{len(false_funcs)}...")

            print(f"\nRemoved {removed} false function entries.")

            # Trigger re-analysis
            print("Running analysis update...")
            bv.update_analysis_and_wait()

            print(f"\nFunctions after cleanup: {len(bv.functions)}")
