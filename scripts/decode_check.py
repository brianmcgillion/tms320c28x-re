"""Decode hex words with the pure-Python c28x decoder under a chosen isa/ dir.

Helper for verifying an isa/*.yaml decode fix WITHOUT a Rust rebuild: the Python
decoder loads the YAML tables at runtime, so editing a temp copy of isa/ and
decoding here reflects exactly what the regenerated Rust tables would produce
(both are generated from the same YAML). Compare the output to TI's dumped.dis.

Usage:
    python scripts/decode_check.py <isa_dir> <hexbytes> [<hexbytes> ...]

  <isa_dir>   directory containing instructions/*.yaml (e.g. a temp copy of isa/)
  <hexbytes>  little-endian instruction bytes, e.g. 4de83100  (>= 2 bytes)

Each line prints:  <hexbytes>  mnem=<NAME>  len=<words>  bt=<branch_type>  ops=<...>
or  <hexbytes>  DECODE_FAIL.

Example fix loop:
    cp -r isa /tmp/isa_try && $EDITOR /tmp/isa_try/instructions/fpu.yaml
    python scripts/decode_check.py /tmp/isa_try 4de83100 00e00c00 01e848fe
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from c28x.isa import ISA
from c28x.decoder import Decoder


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    isa_dir = Path(argv[1])
    if not (isa_dir / "instructions").is_dir():
        print(f"error: {isa_dir} has no instructions/ subdir")
        return 2
    dec = Decoder(isa=ISA(isa_dir=isa_dir), objmode=1)
    for hx in argv[2:]:
        try:
            data = bytes.fromhex(hx)
        except ValueError:
            print(f"{hx}  BAD_HEX")
            continue
        if len(data) < 2:
            print(f"{hx}  TOO_SHORT")
            continue
        if len(data) < 4:
            data = data + b"\x00\x00"
        insn = dec.decode(data, addr=0)
        if insn is None:
            print(f"{hx}  DECODE_FAIL")
            continue
        ops = ", ".join(o.name for o in insn.operands)
        bt = insn.branch_type.name
        tgt = "" if insn.branch_target is None else f" tgt=0x{insn.branch_target // 2:06X}"
        print(f"{hx}  mnem={insn.name}  yaml={insn.yaml_name}  len={insn.size // 2}  "
              f"bt={bt}{tgt}  ops=[{ops}]")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
