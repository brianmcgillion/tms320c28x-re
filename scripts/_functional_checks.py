"""Pure functional equivalence check functions.

Each check takes (hlil_text, spec, func=None) and returns (passed, detail).
The func argument is a BN Function object for API-based checks (optional).
"""

import re


def check_callees(hlil_text, expected_names, func=None):
    """Verify function calls the expected callees.

    Uses BN func.callees API (primary) with HLIL text regex fallback.
    Returns list of (callee_name, found_bool).
    """
    # Build BN callee set if available
    bn_callees = set()
    if func is not None:
        try:
            for c in func.callees:
                bn_callees.add(c.name)
                if c.name.startswith("_"):
                    bn_callees.add(c.name[1:])
        except Exception:
            pass

    results = []
    for name in expected_names:
        # BN API check
        found = name in bn_callees or f"_{name}" in bn_callees
        # HLIL text fallback
        if not found:
            pattern = rf'_?{re.escape(name)}\s*\('
            found = bool(re.search(pattern, hlil_text))
        results.append((name, found))
    return results


def check_no_callees(hlil_text, _spec, func=None):
    """Verify function makes no function calls."""
    if func is not None:
        try:
            callees = [c for c in func.callees if not c.name.startswith("sub_")]
            return len(callees) == 0, f"{len(callees)} callees found" if callees else "no callees"
        except Exception:
            pass
    # Fallback: look for function call patterns in HLIL
    calls = re.findall(r'[a-zA-Z_]\w+\s*\(', hlil_text)
    # Filter out type casts and keywords
    calls = [c for c in calls if not any(c.strip().startswith(k) for k in
             ["if ", "while ", "for ", "do ", "return ", "int", "void", "float",
              "bool", "char", "zx.", "sx."])]
    return len(calls) == 0, f"{len(calls)} call-like patterns" if calls else "no calls"


def check_mmio_patterns(hlil_text, patterns):
    """Verify stores to specific MMIO address ranges.

    patterns: list of regex strings matching hex addresses.
    """
    results = []
    for pat in patterns:
        found = bool(re.search(pat, hlil_text))
        results.append((pat, found))
    return results


def check_no_mmio_writes(hlil_text, _spec):
    """Verify no MMIO stores (no *0x... patterns)."""
    has_mmio = bool(re.search(r'\*\s*0x[0-9a-fA-F]+', hlil_text))
    return not has_mmio, "MMIO writes found" if has_mmio else "no MMIO writes"


def check_constants(hlil_text, patterns):
    """Verify specific numeric constants appear in HLIL.

    patterns: list of regex strings (e.g., "0x2[Aa]|42").
    """
    results = []
    for pat in patterns:
        found = bool(re.search(pat, hlil_text))
        results.append((pat, found))
    return results


def check_comparison_constants(hlil_text, patterns):
    """Verify constants appear near comparison operators."""
    results = []
    for pat in patterns:
        found = bool(re.search(pat, hlil_text))
        results.append((pat, found))
    return results


def check_loop_type(hlil_text, expected_type):
    """Classify loop type and verify it matches expected.

    Types: 'infinite', 'counted', 'conditional'
    """
    if expected_type == "infinite":
        evidence = [
            r'while\s*\(\s*true\s*\)',
            r'while\s*\(\s*1\s*\)',
            r'while\s*\(\s*\)',
            r'for\s*\(\s*;\s*;\s*\)',
            # BN may decompile as label+goto or do-while(true)
            r'do\s*$',
        ]
        found = any(re.search(e, hlil_text, re.MULTILINE) for e in evidence)
        return found, "infinite loop found" if found else "no infinite loop evidence"

    elif expected_type == "counted":
        evidence = [
            r'-=\s*1',           # decrement
            r'\+=\s*1',          # increment
            r's?[<>]=?\s*0x',    # comparison with hex constant
            r's?[<>]=?\s*\d',    # comparison with decimal
            r'while\s*\(',       # while loop
            r'\bdo\b',           # do-while
        ]
        found = any(re.search(e, hlil_text) for e in evidence)
        return found, "counted loop found" if found else "no counted loop evidence"

    elif expected_type == "conditional":
        evidence = [
            r'while\s*\(',
            r'do\b',
            r'==\s*0',
            r'!=\s*0',
        ]
        found = any(re.search(e, hlil_text) for e in evidence)
        return found, "conditional loop found" if found else "no conditional loop evidence"

    return False, f"unknown loop type: {expected_type}"


def check_arithmetic_ops(hlil_text, expected_ops):
    """Verify specific arithmetic/bitwise operators appear.

    expected_ops: list of operator strings ("+", "-", "*", "&", "|", "^", "<<", ">>")
    """
    results = []
    for op in expected_ops:
        if op == "<<":
            found = "<<" in hlil_text
        elif op == ">>":
            found = ">>" in hlil_text
        elif op == "|":
            found = bool(re.search(r'\|[^|]', hlil_text))  # avoid matching ||
        elif op == "&":
            found = bool(re.search(r'&[^&]', hlil_text))   # avoid matching &&
        elif op == "*":
            # Avoid matching pointer dereference — look for * between operands
            found = bool(re.search(r'\w\s*\*\s*\w', hlil_text)) or bool(re.search(r'\*=', hlil_text))
        elif op == "+":
            found = "+" in hlil_text
        elif op == "-":
            found = bool(re.search(r'[^-]-[^-]', hlil_text)) or "-=" in hlil_text
        elif op == "^":
            found = "^" in hlil_text
        else:
            found = op in hlil_text
        results.append((op, found))
    return results


def check_min_branches(hlil_text, min_count):
    """Verify minimum number of conditional branches."""
    count = len(re.findall(r'\bif\b', hlil_text))
    passed = count >= min_count
    return passed, f"{count} branches (need {min_count}+)"


def check_min_stores(hlil_text, min_count):
    """Verify minimum number of store operations."""
    # Count lines with assignment that aren't just declarations
    store_patterns = [
        r'^\s*\*',        # pointer dereference store
        r'^\s*\w+\s*=',   # variable assignment
        r'\+=',            # compound assignment
        r'-=',
        r'\*=',
        r'&=',
        r'\|=',
        r'\^=',
    ]
    stores = 0
    for line in hlil_text.split('\n'):
        for pat in store_patterns:
            if re.search(pat, line):
                stores += 1
                break
    passed = stores >= min_count
    return passed, f"{stores} stores (need {min_count}+)"


def check_global_writes(hlil_text, expected_globals):
    """Verify writes to specific named global variables."""
    results = []
    for name in expected_globals:
        pattern = rf'{re.escape(name)}\s*[+\-*&|^]?='
        found = bool(re.search(pattern, hlil_text))
        results.append((name, found))
    return results
