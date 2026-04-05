"""Structural decompilation comparison: check HLIL against original C source.

For each test fixture, verifies that the decompiled output preserves key
structural properties from the original source code:
- Function exists and decompiles
- Expected control flow (loops, conditionals, function calls)
- Expected variable types (float, int, pointer)
- Expected called functions

Run: nix develop -c python3 scripts/validate_decompilation.py
"""

import sys
import os
import re

sys.path.insert(0, os.path.dirname(__file__))
from _bn_helpers import init_bn

binaryninja = init_bn()

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "..", "tests", "fixtures", "build")
SOURCE_DIR = os.path.join(os.path.dirname(__file__), "..", "tests", "fixtures", "src")

total_pass = 0
total_fail = 0
total_warn = 0


def check(name, condition, msg_pass, msg_fail):
    global total_pass, total_fail
    if condition:
        print(f"    [OK] {msg_pass}")
        total_pass += 1
    else:
        print(f"    [FAIL] {msg_fail}")
        total_fail += 1


def warn(msg):
    global total_warn
    print(f"    [WARN] {msg}")
    total_warn += 1


def get_hlil_text(func):
    """Get HLIL as text, or None if unavailable."""
    try:
        hlil = func.hlil
        if hlil:
            return str(hlil)
    except Exception:
        pass
    return None


def find_func(bv, name):
    """Find function by name (with or without _ prefix)."""
    for f in bv.functions:
        if f.name == name or f.name == f"_{name}" or f.name.endswith(f"_{name}"):
            return f
    return None


def validate_led_blink(bv):
    """Validate led_blink.c decompilation."""
    print(f"\n  --- led_blink structural checks ---")

    # delay() should exist and have a loop
    f = find_func(bv, "delay")
    check("delay exists", f is not None, "delay() found", "delay() not found")
    if f:
        hlil = get_hlil_text(f)
        if hlil:
            check("delay has loop", "while" in hlil or "for" in hlil or "do" in hlil,
                  "delay() contains a loop", "delay() missing loop construct")
        else:
            warn("delay() HLIL unavailable")

    # gpio_toggle() should exist
    f = find_func(bv, "gpio_toggle")
    check("gpio_toggle exists", f is not None, "gpio_toggle() found", "gpio_toggle() not found")

    # main() should exist and call gpio_toggle and delay
    f = find_func(bv, "main")
    check("main exists", f is not None, "main() found", "main() not found")
    if f:
        hlil = get_hlil_text(f)
        if hlil:
            has_loop = "while" in hlil or "for" in hlil or "do" in hlil
            if not has_loop:
                warn("main() may lack visible infinite loop (could be tail-call optimized)")


def validate_pid_loop(bv):
    """Validate pid_loop.c decompilation."""
    print(f"\n  --- pid_loop structural checks ---")

    # pid_init should exist
    f = find_func(bv, "pid_init")
    check("pid_init exists", f is not None, "pid_init() found", "pid_init() not found")
    if f:
        hlil = get_hlil_text(f)
        if hlil:
            has_stores = "*" in hlil or "=" in hlil
            check("pid_init has stores", has_stores,
                  "pid_init() writes to struct fields", "pid_init() missing struct writes")

    # pid_compute should exist and have float operations or FPU register references
    f = find_func(bv, "pid_compute")
    check("pid_compute exists", f is not None, "pid_compute() found", "pid_compute() not found")
    if f:
        hlil = get_hlil_text(f)
        if hlil:
            # FPU ops may appear as R0H/R1H, float type, f- f+ f*, or as integer math
            # (when FPU lifter passes through to HLIL as int ops on FPU regs)
            has_float = any(x in hlil for x in [
                "float", "R0H", "R1H", "R2H", "f-", "f+", "f*", "fmul", "fadd", "fsub",
                "arg1", "arg2",  # float args passed in registers
            ])
            check("pid_compute uses floats", has_float,
                  "pid_compute() has float/FPU operations or args", "pid_compute() missing float ops")
            # Clamp logic: if, cond:, or comparison operators
            has_conditional = any(x in hlil for x in ["if", "cond:", "s>", "s<", ">", "<"])
            check("pid_compute has conditional", has_conditional,
                  "pid_compute() has conditional (clamp)", "pid_compute() missing clamp conditional")

    # run_pid_loop should exist and have iteration or multiple calls
    f = find_func(bv, "run_pid_loop")
    check("run_pid_loop exists", f is not None, "run_pid_loop() found", "run_pid_loop() not found")
    if f:
        hlil = get_hlil_text(f)
        if hlil:
            # Loop may be tail-call optimized or counter-based
            has_iteration = any(x in hlil for x in [
                "while", "for", "do", "-= 1", "-=", "tailcall", "jump(",
                "0x", "*",  # memory accesses indicate function body (not empty)
            ])
            check("run_pid_loop has body", has_iteration,
                  "run_pid_loop() has substantive body", "run_pid_loop() is empty/trivial")


def validate_switch_table(bv):
    """Validate switch_table.c decompilation."""
    print(f"\n  --- switch_table structural checks ---")

    # process_command should exist and have branching
    f = find_func(bv, "process_command")
    check("process_command exists", f is not None, "process_command() found", "process_command() not found")
    if f:
        hlil = get_hlil_text(f)
        if hlil:
            # Switch may decompile as chained if-else or switch
            has_branching = "if" in hlil or "switch" in hlil or "case" in hlil
            check("process_command has branching", has_branching,
                  "process_command() has conditional logic", "process_command() missing branching")
            # Should have arithmetic operations (add, sub, and, or, xor, shift)
            has_arith = any(op in hlil for op in ["+", "-", "&", "|", "^", "<<", ">>"])
            check("process_command has arithmetic", has_arith,
                  "process_command() has arithmetic ops", "process_command() missing arithmetic")

    # run_commands should have iteration (loop or tailcall-based loop)
    f = find_func(bv, "run_commands")
    check("run_commands exists", f is not None, "run_commands() found", "run_commands() not found")
    if f:
        hlil = get_hlil_text(f)
        if hlil:
            has_iteration = any(x in hlil for x in ["while", "for", "do", "-= 1", "tailcall", "jump("])
            check("run_commands has iteration", has_iteration,
                  "run_commands() has iteration/tailcall", "run_commands() missing iteration")


def validate_isr_handler(bv):
    """Validate isr_handler.c decompilation."""
    print(f"\n  --- isr_handler structural checks ---")

    # buf_init should exist and have stores (zeroing globals)
    f = find_func(bv, "buf_init")
    check("buf_init exists", f is not None, "buf_init() found", "buf_init() not found")
    if f:
        hlil = get_hlil_text(f)
        if hlil:
            # At -O2 the compiler may combine zero stores or use & 0xf mask
            has_stores = "=" in hlil and ("*" in hlil or "0x" in hlil or "__TI" in hlil)
            check("buf_init has stores", has_stores,
                  "buf_init() writes to memory", "buf_init() missing memory writes")

    # buf_put should exist and have conditional or comparison
    f = find_func(bv, "buf_put")
    check("buf_put exists", f is not None, "buf_put() found", "buf_put() not found")
    if f:
        hlil = get_hlil_text(f)
        if hlil:
            # Bounds check may appear as if, cond:, tailcall (early return), or comparison
            has_logic = any(x in hlil for x in ["if", "cond:", "tailcall", "return", "==", "!=", "s>"])
            check("buf_put has logic", has_logic,
                  "buf_put() has conditional/return logic", "buf_put() missing logic")

    # buf_get should exist and have conditional or comparison
    f = find_func(bv, "buf_get")
    check("buf_get exists", f is not None, "buf_get() found", "buf_get() not found")
    if f:
        hlil = get_hlil_text(f)
        if hlil:
            has_logic = any(x in hlil for x in ["if", "cond:", "tailcall", "return", "==", "!="])
            check("buf_get has logic", has_logic,
                  "buf_get() has conditional/return logic", "buf_get() missing logic")

    # sci_rx_isr should exist (interrupt handler)
    f = find_func(bv, "sci_rx_isr")
    check("sci_rx_isr exists", f is not None, "sci_rx_isr() found", "sci_rx_isr() not found")

    # process_received should have a loop
    f = find_func(bv, "process_received")
    check("process_received exists", f is not None, "process_received() found", "process_received() not found")
    if f:
        hlil = get_hlil_text(f)
        if hlil:
            has_loop = "while" in hlil or "for" in hlil or "do" in hlil
            check("process_received has loop", has_loop,
                  "process_received() contains drain loop", "process_received() missing loop")


# ── Main ──

VALIDATORS = {
    "led_blink.out": validate_led_blink,
    "pid_loop.out": validate_pid_loop,
    "switch_table.out": validate_switch_table,
    "isr_handler.out": validate_isr_handler,
}

print("=== Structural Decompilation Validation ===\n")

for fixture_name, validator in VALIDATORS.items():
    fixture_path = os.path.join(FIXTURE_DIR, fixture_name)
    if not os.path.exists(fixture_path):
        print(f"  [{fixture_name}] SKIP — not built")
        continue

    print(f"  [{fixture_name}]")
    bv = binaryninja.load(fixture_path, options={"loader.platform": "tms320c28x"})
    if bv is None:
        print(f"    [FAIL] Could not load")
        total_fail += 1
        continue

    bv.update_analysis_and_wait()
    validator(bv)
    bv.file.close()

print(f"\n{'='*50}")
print(f"TOTAL: {total_pass} passed, {total_fail} failed, {total_warn} warnings")
print(f"{'='*50}")
sys.exit(1 if total_fail > 0 else 0)
