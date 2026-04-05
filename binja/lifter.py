# SPDX-License-Identifier: MIT
"""LLIL lifter for TMS320C28x instructions.

Uses a two-tier dispatch:
1. Explicit per-instruction handler (_lift_{yaml_name}) for complex cases
2. Semantic-type handler (_sem_{type}) for the bulk of instructions

All IL generation is defensive — no operation should crash BN:
- No flags= kwargs (BN Python IL API doesn't support them)
- No il.unimplemented() as expression argument
- Unsigned masking on all il.const() values
- Bounds checks on operand array access
- None guards on xar_index and branch_target
"""

from __future__ import annotations

from c28x.operands import AddressingMode
from c28x.types import BranchType, DecodedInstruction, Operand, OperandType


# Masks for unsigned conversion
_MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF}


class Lifter:

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _c(self, il, size, value):
        """Safe il.const — masks to unsigned."""
        return il.const(size, int(value) & _MASK.get(size, 0xFFFFFFFF))

    def _op(self, ops, idx):
        """Safe operand access — returns None if out of bounds."""
        return ops[idx] if idx < len(ops) else None

    # ------------------------------------------------------------------ #
    # Main entry                                                           #
    # ------------------------------------------------------------------ #

    def lift(self, insn: DecodedInstruction, addr: int, il) -> bool:
        try:
            return self._lift_inner(insn, addr, il)
        except Exception:
            return False

    def _lift_inner(self, insn, addr, il):
        # Tier 1: explicit per-instruction handler
        handler = getattr(self, f"_lift_{insn.yaml_name.lower()}", None)
        if handler:
            return handler(insn, addr, il)

        # Tier 2: semantic-type handler
        sem_type = insn.semantics.get("type", "") if insn.semantics else ""
        if not sem_type:
            sem_type = self._infer_sem_type(insn)
        sem_handler = getattr(self, f"_sem_{sem_type}", None)
        if sem_handler:
            return sem_handler(insn, addr, il)

        # Tier 3: branch-type fallback
        if insn.branch_type == BranchType.RETURN:
            il.append(il.ret(il.reg(4, "RPC")))
            return True
        if insn.branch_type == BranchType.UNCONDITIONAL and insn.branch_target is not None:
            if self._is_prologue_at(il, insn.branch_target):
                il.append(il.tailcall(il.const_pointer(4, insn.branch_target)))
            else:
                il.append(il.jump(il.const_pointer(4, insn.branch_target)))
            return True
        if insn.branch_type == BranchType.CALL and insn.branch_target is not None:
            il.append(il.call(il.const_pointer(4, insn.branch_target)))
            return True

        return False

    # ------------------------------------------------------------------ #
    # Operand reading/writing                                              #
    # ------------------------------------------------------------------ #

    def _read_op(self, op: Operand, il, size: int = 2):
        if op is None:
            return self._c(il, size, 0)
        if op.type == OperandType.REGISTER:
            return il.reg(size, op.name)
        if op.type == OperandType.IMMEDIATE:
            return self._c(il, size, op.value)
        if op.type in (OperandType.LOC16, OperandType.LOC32):
            loc_size = 4 if op.type == OperandType.LOC32 else 2
            return self._read_loc(op, il, loc_size)
        return self._c(il, size, 0)

    def _read_loc(self, op, il, size):
        r = op.resolved
        if r is None:
            return self._c(il, size, 0)
        if r.mode == AddressingMode.REGISTER_DIRECT:
            return il.reg(size, r.register)
        addr_expr = self._loc_address(r, il, size)
        if r.mode == AddressingMode.INDIRECT_PRE_DEC and r.xar_index is not None:
            xar = f"XAR{r.xar_index}"
            il.append(il.set_reg(4, xar, il.sub(4, il.reg(4, xar), self._c(il, 4, size))))
        result = il.load(size, addr_expr)
        if r.mode == AddressingMode.INDIRECT_POST_INC and r.xar_index is not None:
            xar = f"XAR{r.xar_index}"
            il.append(il.set_reg(4, xar, il.add(4, il.reg(4, xar), self._c(il, 4, size))))
        return result

    def _write_loc(self, op, il, size, value):
        if op is None:
            il.append(il.nop())
            return
        r = op.resolved
        if r is None:
            il.append(il.nop())
            return
        if r.mode == AddressingMode.REGISTER_DIRECT:
            il.append(il.set_reg(size, r.register, value))
            return
        if r.mode == AddressingMode.INDIRECT_PRE_DEC and r.xar_index is not None:
            xar = f"XAR{r.xar_index}"
            il.append(il.set_reg(4, xar, il.sub(4, il.reg(4, xar), self._c(il, 4, size))))
        addr_expr = self._loc_address(r, il, size)
        il.append(il.store(size, addr_expr, value))
        if r.mode == AddressingMode.INDIRECT_POST_INC and r.xar_index is not None:
            xar = f"XAR{r.xar_index}"
            il.append(il.set_reg(4, xar, il.add(4, il.reg(4, xar), self._c(il, 4, size))))

    def _loc_address(self, r, il, size=2):
        if r.mode == AddressingMode.DP_DIRECT:
            dp_base = il.shift_left(4, il.zero_extend(4, il.reg(2, "DP")), self._c(il, 4, 6))
            word_addr = il.add(4, dp_base, self._c(il, 4, r.offset))
            return il.shift_left(4, word_addr, self._c(il, 4, 1))
        if r.mode == AddressingMode.SP_RELATIVE:
            word_addr = il.sub(4, il.zero_extend(4, il.reg(2, "SP")), self._c(il, 4, r.offset))
            return il.shift_left(4, word_addr, self._c(il, 4, 1))
        if r.mode in (AddressingMode.INDIRECT, AddressingMode.INDIRECT_POST_INC,
                       AddressingMode.INDIRECT_PRE_DEC):
            if r.xar_index is not None and 0 <= r.xar_index <= 7:
                return il.reg(4, f"XAR{r.xar_index}")
            return self._c(il, 4, 0)
        if r.mode == AddressingMode.INDIRECT_AR0:
            if r.xar_index is not None and 0 <= r.xar_index <= 7:
                return il.add(4, il.reg(4, f"XAR{r.xar_index}"),
                              il.shift_left(4, il.zero_extend(4, il.reg(2, "AR0")), self._c(il, 4, 1)))
            return self._c(il, 4, 0)
        if r.mode == AddressingMode.INDIRECT_AR1:
            if r.xar_index is not None and 0 <= r.xar_index <= 7:
                return il.add(4, il.reg(4, f"XAR{r.xar_index}"),
                              il.shift_left(4, il.zero_extend(4, il.reg(2, "AR1")), self._c(il, 4, 1)))
            return self._c(il, 4, 0)
        return self._c(il, 4, 0)

    # ------------------------------------------------------------------ #
    # Semantic type inference                                              #
    # ------------------------------------------------------------------ #

    def _infer_sem_type(self, insn):
        n = insn.yaml_name.upper()
        for prefix, typ in [
            ("MOV", "mov"), ("DMOV", "mov"), ("PUSH", "push"), ("POP", "pop"),
            ("ADD", "add"), ("SUB", "sub"), ("CMP", "cmp"),
            ("AND", "and"), ("OR_", "or"), ("ORB", "or"), ("XOR", "xor"), ("NOT", "not"),
            ("NEG", "neg"), ("MPY", "mpy"), ("IMPY", "mpy"), ("QMPY", "mpy"), ("SQR", "mpy"),
            ("LSL", "lsl"), ("LSR", "lsr"), ("ASR", "asr"), ("SFR", "asr"),
            ("LSLL", "lsl"), ("LSRL", "lsr"), ("ASRL", "asr"),
        ]:
            if n.startswith(prefix):
                return typ
        if any(n.startswith(p) for p in ("CLRC", "SETC", "EALLOW", "EDIS", "ASP",
                "NASP", "LPADDR", "IDLE", "ABORTI", "RPT", "NOP", "NORM",
                "PREAD", "PWRITE", "XPREAD", "XPWRITE", "IN_", "OUT_",
                "UOUT", "IACK", "SPM", "ZAPA", "MAC", "DMAC", "IMACL",
                "QMACL", "XMAC")):
            return "system"
        if any(n.startswith(p) for p in ("TBIT", "TCLR", "TSET", "TEST")):
            return "system"
        if any(n.startswith(p) for p in ("MAX", "MIN", "SAT")):
            return "system"
        if any(n.startswith(p) for p in ("ABSF", "ADDF", "SUBF", "MPYF", "CMPF",
                "EINV", "EISQRT", "F32TO", "I16TO", "I32TO", "UI16", "UI32",
                "FRAC", "MACF", "MAXF", "MINF", "MOV32", "ZEROF", "MOVST",
                "SWAPF", "NEGF", "F32_", "FPU_")):
            return "fpu"
        if any(n.startswith(p) for p in ("FLIP", "ROL", "ROR", "CSB", "ABS")):
            return "system"
        if any(n.startswith(p) for p in ("TRAP", "INTR", "ESTOP")):
            return "trap"
        if any(n.startswith(p) for p in ("B_", "SB_", "BF_", "SBF", "BANZ",
                "BAR", "XB_", "LOOP")):
            return "cond_branch"
        if any(n.startswith(p) for p in ("LB", "LC", "LCR", "FFC", "XCALL")):
            return "call_or_branch"
        if any(n.startswith(p) for p in ("LRET", "IRET", "XRETC")):
            return "return"
        return ""

    # ------------------------------------------------------------------ #
    # Semantic handlers                                                    #
    # ------------------------------------------------------------------ #

    def _sem_mov(self, insn, addr, il):
        n = insn.yaml_name.upper()
        ops = insn.operands

        # Special cases
        if n == "MOVL_P_ACC":
            il.append(il.set_reg(4, "P", il.reg(4, "ACC")))
            return True
        if n == "MOV_TL_0" or n == "MOV_LOC16_0":
            if ops:
                self._write_loc(ops[0], il, 2, self._c(il, 2, 0))
            else:
                il.append(il.nop())
            return True

        # MOVL XARn, #const22
        if "CONST22" in n:
            dest = self._dest_reg_from_name(n)
            if dest and ops:
                il.append(il.set_reg(dest[1], dest[0], self._c(il, dest[1], ops[0].value)))
                return True

        # MOVB XARn, #const8
        if "MOVB_XAR" in n and "CONST8" in n:
            dest = self._dest_reg_from_name(n)
            if dest and ops:
                il.append(il.set_reg(dest[1], dest[0], il.zero_extend(dest[1], self._c(il, 1, ops[0].value))))
                return True
        if "MOVB_AR" in n and "CONST8" in n:
            dest = self._dest_reg_from_name(n)
            if dest and ops:
                il.append(il.set_reg(2, dest[0], il.zero_extend(2, self._c(il, 1, ops[0].value))))
                return True

        # MOVZ ARn, loc16
        if n.startswith("MOVZ_AR") and "LOC16" in n:
            dest = self._dest_reg_from_name(n)
            if dest and ops:
                xar = f"X{dest[0]}" if not dest[0].startswith("X") else dest[0]
                il.append(il.set_reg(4, xar, il.zero_extend(4, self._read_op(ops[0], il, 2))))
                return True

        # MOVL XARn, loc32
        if n.startswith("MOVL_XAR") and "LOC32" in n:
            dest = self._dest_reg_from_name(n)
            if dest and ops:
                il.append(il.set_reg(dest[1], dest[0], self._read_op(ops[0], il, 4)))
                return True

        # MOVL loc32, XARn
        if n.startswith("MOVL_LOC32_XAR"):
            for i in range(8):
                if f"XAR{i}" in n:
                    if ops:
                        self._write_loc(ops[0], il, 4, il.reg(4, f"XAR{i}"))
                    return True

        if n == "MOVL_LOC32_ACC":
            if ops:
                self._write_loc(ops[0], il, 4, il.reg(4, "ACC"))
            return True
        if n == "MOVL_ACC_LOC32":
            if ops:
                il.append(il.set_reg(4, "ACC", self._read_op(ops[0], il, 4)))
            return True
        if n.startswith("MOVL_LOC32_P"):
            if ops: self._write_loc(ops[0], il, 4, il.reg(4, "P"))
            return True
        if n.startswith("MOVL_LOC32_XT"):
            if ops: self._write_loc(ops[0], il, 4, il.reg(4, "XT"))
            return True
        if n == "MOVL_P_LOC32":
            if ops: il.append(il.set_reg(4, "P", self._read_op(ops[0], il, 4)))
            return True
        if n in ("MOVL_XT_LOC32", "MOVDL_XT_LOC32"):
            if ops: il.append(il.set_reg(4, "XT", self._read_op(ops[0], il, 4)))
            return True

        # MOV AX, loc16 / MOV loc16, AX
        if n == "MOV_AX_LOC16":
            op0 = self._op(ops, 0)
            op1 = self._op(ops, 1)
            if op0 and op1:
                il.append(il.set_reg(2, op0.name, self._read_op(op1, il, 2)))
            return True
        if n == "MOV_LOC16_AX":
            op0 = self._op(ops, 0)
            op1 = self._op(ops, 1)
            if op0 and op1:
                self._write_loc(op0, il, 2, il.reg(2, op1.name))
            return True

        # MOV ACC, loc16 (sign-extend)
        if n == "MOV_ACC_LOC16":
            if ops:
                il.append(il.set_reg(4, "ACC", il.sign_extend(4, self._read_op(ops[0], il, 2))))
            return True
        if n == "MOVU_ACC_LOC16":
            if ops:
                il.append(il.set_reg(4, "ACC", il.zero_extend(4, self._read_op(ops[0], il, 2))))
            return True

        # MOV ACC, #const16 << shift
        if n == "MOV_ACC_CONST16_SHIFT":
            if ops:
                val = self._c(il, 4, ops[0].value)
                op1 = self._op(ops, 1)
                if op1 and op1.value:
                    val = il.shift_left(4, val, self._c(il, 4, op1.value))
                il.append(il.set_reg(4, "ACC", val))
            return True

        if n == "MOV_LOC16_CONST16":
            op0 = self._op(ops, 0)
            op1 = self._op(ops, 1)
            if op0 and op1:
                self._write_loc(op0, il, 2, self._c(il, 2, op1.value))
            return True

        if n == "MOVB_AX_CONST8":
            op0 = self._op(ops, 0)
            op1 = self._op(ops, 1)
            if op0 and op1:
                il.append(il.set_reg(2, op0.name, il.zero_extend(2, self._c(il, 1, op1.value))))
            return True
        if n == "MOVB_ACC_CONST8":
            if ops:
                il.append(il.set_reg(4, "ACC", il.zero_extend(4, self._c(il, 1, ops[0].value))))
            return True

        if n in ("MOV_DP_CONST10", "MOVW_DP_CONST16"):
            if ops:
                il.append(il.set_reg(2, "DP", self._c(il, 2, ops[0].value)))
            return True

        # Phase 6: conditional moves (emit unconditionally — condition usually UNC)
        if n == "MOV_LOC16_AX_COND":
            op0, op1 = self._op(ops, 0), self._op(ops, 1)
            if op0 and op1:
                self._write_loc(op0, il, 2, il.reg(2, op1.name))
            return True

        if n == "MOVB_LOC16_CONST8_COND":
            op0, op1 = self._op(ops, 0), self._op(ops, 1)
            if op0 and op1:
                self._write_loc(op0, il, 2,
                    il.zero_extend(2, self._c(il, 1, op1.value)))
            return True

        if n == "MOVL_LOC32_ACC_COND":
            if ops:
                self._write_loc(ops[0], il, 4, il.reg(4, "ACC"))
            return True

        if n == "MOVX_TL_LOC16":
            if ops:
                il.append(il.set_reg(4, "XT",
                    il.sign_extend(4, self._read_op(ops[0], il, 2))))
            return True

        if n == "ZALR_ACC_LOC16":
            if ops:
                src = il.shift_left(4,
                    il.zero_extend(4, self._read_op(ops[0], il, 2)),
                    self._c(il, 4, 16))
                il.append(il.set_reg(4, "ACC",
                    il.or_expr(4, src, self._c(il, 4, 0x8000))))
            return True

        # Generic: single dest register <- loc16/loc32
        dest = self._dest_reg_from_name(n)
        if dest and ops:
            op = ops[0]
            if op.type in (OperandType.LOC16, OperandType.LOC32):
                src_size = 4 if op.type == OperandType.LOC32 else 2
                src = self._read_op(op, il, src_size)
                if src_size < dest[1]:
                    src = il.zero_extend(dest[1], src)
                il.append(il.set_reg(dest[1], dest[0], src))
                return True

        il.append(il.nop())
        return True

    def _sem_push(self, insn, addr, il):
        n = insn.yaml_name.upper()
        ops = insn.operands

        if n == "PUSH_LOC16" and ops:
            il.append(il.push(2, self._read_op(ops[0], il, 2)))
            return True

        pair_map = {
            "PUSH_AR1_AR0": [("AR1", 2), ("AR0", 2)],
            "PUSH_AR3_AR2": [("AR3", 2), ("AR2", 2)],
            "PUSH_AR5_AR4": [("AR5", 2), ("AR4", 2)],
            "PUSH_AR1H_AR0H": [("AR1", 2), ("AR0", 2)],
            "PUSH_DP_ST1": [("DP", 2), ("ST1", 2)],
            "PUSH_T_ST0": [("T", 2), ("ST0", 2)],
        }
        if n in pair_map:
            for reg, sz in pair_map[n]:
                il.append(il.push(sz, il.reg(sz, reg)))
            return True

        single = {"PUSH_DP": ("DP",2), "PUSH_IFR": ("IFR",2), "PUSH_P": ("P",4),
                   "PUSH_RPC": ("RPC",4), "PUSH_ST0": ("ST0",2), "PUSH_ST1": ("ST1",2),
                   "PUSH_XT": ("XT",4), "PUSH_DBGIER": ("DBGIER",2)}
        if n in single:
            reg, sz = single[n]
            il.append(il.push(sz, il.reg(sz, reg)))
            return True

        il.append(il.nop())
        return True

    def _sem_pop(self, insn, addr, il):
        n = insn.yaml_name.upper()
        ops = insn.operands

        if n == "POP_LOC16" and ops:
            op = ops[0]
            if op.resolved and op.resolved.mode == AddressingMode.REGISTER_DIRECT:
                il.append(il.set_reg(2, op.resolved.register, il.pop(2)))
            else:
                self._write_loc(op, il, 2, il.pop(2))
            return True

        pair_map = {
            "POP_AR1_AR0": [("AR0",2), ("AR1",2)],
            "POP_AR3_AR2": [("AR2",2), ("AR3",2)],
            "POP_AR5_AR4": [("AR4",2), ("AR5",2)],
            "POP_AR1H_AR0H": [("AR0",2), ("AR1",2)],
            "POP_DP_ST1": [("ST1",2), ("DP",2)],
            "POP_T_ST0": [("ST0",2), ("T",2)],
        }
        if n in pair_map:
            for reg, sz in pair_map[n]:
                il.append(il.set_reg(sz, reg, il.pop(sz)))
            return True

        single = {"POP_DP": ("DP",2), "POP_IFR": ("IFR",2), "POP_P": ("P",4),
                   "POP_RPC": ("RPC",4), "POP_ST0": ("ST0",2), "POP_ST1": ("ST1",2),
                   "POP_XT": ("XT",4), "POP_DBGIER": ("DBGIER",2)}
        if n in single:
            reg, sz = single[n]
            il.append(il.set_reg(sz, reg, il.pop(sz)))
            return True

        il.append(il.nop())
        return True

    def _sem_add(self, insn, addr, il):
        return self._sem_arith(insn, addr, il, "add")

    def _sem_sub(self, insn, addr, il):
        return self._sem_arith(insn, addr, il, "sub")

    def _sem_arith(self, insn, addr, il, op_name):
        n = insn.yaml_name.upper()
        ops = insn.operands
        fn = il.add if op_name == "add" else il.sub

        # INC/DEC
        if n.startswith("INC") or n.startswith("DEC"):
            if ops:
                op = ops[0]
                sz = 4 if op.type == OperandType.LOC32 else 2
                val = self._read_op(op, il, sz)
                f = il.add if n.startswith("INC") else il.sub
                self._write_loc(op, il, sz, f(sz, val, self._c(il, sz, 1)))
            return True

        # ACC ± loc16
        if "ACC_LOC16" in n and "SHIFT" not in n and "ADDU" not in n and "SUBU" not in n and "ADDCU" not in n:
            if ops:
                src = il.sign_extend(4, self._read_op(ops[0], il, 2))
                il.append(il.set_reg(4, "ACC", fn(4, il.reg(4, "ACC"), src)))
            return True

        # ACC ± loc16 unsigned
        if any(p in n for p in ("ADDU_ACC", "SUBU_ACC", "ADDCU_ACC")):
            if ops:
                src = il.zero_extend(4, self._read_op(ops[0], il, 2))
                il.append(il.set_reg(4, "ACC", fn(4, il.reg(4, "ACC"), src)))
            return True

        # AX ± loc16
        if "AX_LOC1" in n:
            op0 = self._op(ops, 0)
            op1 = self._op(ops, 1)
            if op0 and op1:
                il.append(il.set_reg(2, op0.name, fn(2, il.reg(2, op0.name), self._read_op(op1, il, 2))))
            return True

        # loc16 ± AX
        if "LOC16_AX" in n:
            op0 = self._op(ops, 0)
            op1 = self._op(ops, 1)
            if op0 and op1:
                val = self._read_op(op0, il, 2)
                self._write_loc(op0, il, 2, fn(2, val, il.reg(2, op1.name)))
            return True

        # ACC ± #const8
        if "CONST8" in n and "ACC" in n:
            if ops:
                il.append(il.set_reg(4, "ACC", fn(4, il.reg(4, "ACC"), il.zero_extend(4, self._c(il, 1, ops[0].value)))))
            return True

        # AX ± #const8
        if "AX_CONST8" in n:
            op0 = self._op(ops, 0)
            op1 = self._op(ops, 1)
            if op0 and op1:
                il.append(il.set_reg(2, op0.name, fn(2, il.reg(2, op0.name), il.zero_extend(2, self._c(il, 1, op1.value)))))
            return True

        # SP ± #const7
        if "SP_CONST7" in n:
            if ops:
                il.append(il.set_reg(2, "SP", fn(2, il.reg(2, "SP"), self._c(il, 2, ops[0].value))))
            return True

        # XARn ± #const7
        if "XARN_CONST7" in n:
            op0 = self._op(ops, 0)
            op1 = self._op(ops, 1)
            if op0 and op1 and 0 <= op0.value <= 7:
                xar = f"XAR{op0.value}"
                il.append(il.set_reg(4, xar, fn(4, il.reg(4, xar), self._c(il, 4, op1.value))))
            return True

        # ACC ± loc32
        if "ACC_LOC32" in n or "ADDL_ACC" in n or "SUBL_ACC" in n:
            if ops:
                il.append(il.set_reg(4, "ACC", fn(4, il.reg(4, "ACC"), self._read_op(ops[0], il, 4))))
            return True

        # P ± loc32
        if "P_LOC32" in n:
            if ops:
                il.append(il.set_reg(4, "P", fn(4, il.reg(4, "P"), self._read_op(ops[0], il, 4))))
            return True

        # loc32 ± ACC
        if "LOC32_ACC" in n:
            if ops:
                val = self._read_op(ops[0], il, 4)
                self._write_loc(ops[0], il, 4, fn(4, val, il.reg(4, "ACC")))
            return True

        # loc16 ± #const16
        if "LOC16_CONST16" in n:
            op0 = self._op(ops, 0)
            op1 = self._op(ops, 1)
            if op0 and op1:
                val = self._read_op(op0, il, 2)
                self._write_loc(op0, il, 2, fn(2, val, self._c(il, 2, op1.value)))
            return True

        # ACC ± #const16 << shift
        if "CONST16_SHIFT" in n:
            if ops:
                val = self._c(il, 4, ops[0].value)
                op1 = self._op(ops, 1)
                if op1 and op1.value:
                    val = il.shift_left(4, val, self._c(il, 4, op1.value))
                il.append(il.set_reg(4, "ACC", fn(4, il.reg(4, "ACC"), val)))
            return True

        # ACC ± loc16 << 16
        if "SHIFT16" in n:
            if ops:
                src = il.shift_left(4, il.zero_extend(4, self._read_op(ops[0], il, 2)), self._c(il, 4, 16))
                il.append(il.set_reg(4, "ACC", fn(4, il.reg(4, "ACC"), src)))
            return True

        # ACC ± loc16 << shift (1-15 or T)
        if "SHIFT" in n and "LOC16" in n:
            if ops:
                src = il.sign_extend(4, self._read_op(ops[0], il, 2))
                op1 = self._op(ops, 1)
                if op1 and op1.type == OperandType.IMMEDIATE and op1.value:
                    src = il.shift_left(4, src, self._c(il, 4, op1.value))
                il.append(il.set_reg(4, "ACC", fn(4, il.reg(4, "ACC"), src)))
            return True

        # ACC ± loc16 << shift (0-15)
        if "SHIFT0_15" in n:
            if ops:
                src = self._read_op(ops[0], il, 2)
                op1 = self._op(ops, 1)
                if op1 and op1.value:
                    src = il.shift_left(4, il.zero_extend(4, src), self._c(il, 4, op1.value))
                else:
                    src = il.zero_extend(4, src)
                il.append(il.set_reg(4, "ACC", fn(4, il.reg(4, "ACC"), src)))
            return True

        # ADRK/SBRK
        if n in ("ADRK_IMM8", "SBRK_CONST8"):
            il.append(il.nop())
            return True

        # Phase 6: additional arithmetic
        if n == "ADDCL_ACC_LOC32":
            if ops:
                il.append(il.set_reg(4, "ACC",
                    il.add(4, il.reg(4, "ACC"), self._read_op(ops[0], il, 4))))
            return True

        if n == "SUBRL_LOC32_ACC":
            if ops:
                val = self._read_op(ops[0], il, 4)
                self._write_loc(ops[0], il, 4, il.sub(4, il.reg(4, "ACC"), val))
            return True

        if n == "MINL_ACC_LOC32":
            il.append(il.nop())  # No conditional in LLIL
            return True

        il.append(il.nop())
        return True

    def _sem_cmp(self, insn, addr, il):
        n = insn.yaml_name.upper()
        ops = insn.operands

        if "AX_LOC1" in n:
            op0 = self._op(ops, 0)
            op1 = self._op(ops, 1)
            if op0 and op1:
                il.append(il.sub(2, il.reg(2, op0.name), self._read_op(op1, il, 2)))
                return True
        if "AX_CONST8" in n:
            op0 = self._op(ops, 0)
            op1 = self._op(ops, 1)
            if op0 and op1:
                il.append(il.sub(2, il.reg(2, op0.name), il.zero_extend(2, self._c(il, 1, op1.value))))
                return True
        if "LOC16_CONST16" in n:
            op0 = self._op(ops, 0)
            op1 = self._op(ops, 1)
            if op0 and op1:
                il.append(il.sub(2, self._read_op(op0, il, 2), self._c(il, 2, op1.value)))
                return True
        if "ACC_LOC32" in n or n == "CMPL_ACC_LOC32":
            if ops:
                il.append(il.sub(4, il.reg(4, "ACC"), self._read_op(ops[0], il, 4)))
                return True

        il.append(il.nop())
        return True

    def _sem_neg(self, insn, addr, il):
        n = insn.yaml_name.upper()
        if "ACC" in n:
            il.append(il.set_reg(4, "ACC", il.neg_expr(4, il.reg(4, "ACC"))))
            return True
        if "AX" in n and insn.operands:
            ax = insn.operands[0].name
            il.append(il.set_reg(2, ax, il.neg_expr(2, il.reg(2, ax))))
            return True
        il.append(il.nop())
        return True

    def _sem_and(self, insn, addr, il):
        return self._sem_bitwise(insn, addr, il, "and_expr")

    def _sem_or(self, insn, addr, il):
        return self._sem_bitwise(insn, addr, il, "or_expr")

    def _sem_xor(self, insn, addr, il):
        return self._sem_bitwise(insn, addr, il, "xor_expr")

    def _sem_bitwise(self, insn, addr, il, il_op):
        n = insn.yaml_name.upper()
        ops = insn.operands
        fn = getattr(il, il_op)

        if "ACC_LOC16" in n:
            if ops:
                il.append(il.set_reg(4, "ACC", fn(4, il.reg(4, "ACC"), il.zero_extend(4, self._read_op(ops[0], il, 2)))))
            return True
        if "AX_LOC16" in n:
            op0 = self._op(ops, 0)
            op1 = self._op(ops, 1)
            if op0 and op1:
                il.append(il.set_reg(2, op0.name, fn(2, il.reg(2, op0.name), self._read_op(op1, il, 2))))
            return True
        if "LOC16_AX" in n:
            op0 = self._op(ops, 0)
            op1 = self._op(ops, 1)
            if op0 and op1:
                self._write_loc(op0, il, 2, fn(2, self._read_op(op0, il, 2), il.reg(2, op1.name)))
            return True
        if "CONST16_SHIFT" in n:
            if ops:
                val = self._c(il, 4, ops[0].value)
                op1 = self._op(ops, 1)
                if op1 and op1.value:
                    val = il.shift_left(4, val, self._c(il, 4, op1.value))
                il.append(il.set_reg(4, "ACC", fn(4, il.reg(4, "ACC"), val)))
            return True
        if "LOC16_CONST16" in n:
            op0 = self._op(ops, 0)
            op1 = self._op(ops, 1)
            if op0 and op1:
                self._write_loc(op0, il, 2, fn(2, self._read_op(op0, il, 2), self._c(il, 2, op1.value)))
            return True
        if "AX_CONST8" in n or "B_AX" in n:
            op0 = self._op(ops, 0)
            op1 = self._op(ops, 1)
            if op0 and op1:
                il.append(il.set_reg(2, op0.name, fn(2, il.reg(2, op0.name), il.zero_extend(2, self._c(il, 1, op1.value)))))
            return True

        il.append(il.nop())
        return True

    def _sem_not(self, insn, addr, il):
        n = insn.yaml_name.upper()
        if "ACC" in n:
            il.append(il.set_reg(4, "ACC", il.not_expr(4, il.reg(4, "ACC"))))
        elif "AX" in n and insn.operands:
            il.append(il.set_reg(2, insn.operands[0].name, il.not_expr(2, il.reg(2, insn.operands[0].name))))
        else:
            il.append(il.nop())
        return True

    def _sem_lsl(self, insn, addr, il):
        return self._sem_shift(insn, addr, il, "shift_left")

    def _sem_lsr(self, insn, addr, il):
        return self._sem_shift(insn, addr, il, "logical_shift_right")

    def _sem_asr(self, insn, addr, il):
        return self._sem_shift(insn, addr, il, "arith_shift_right")

    def _sem_shift(self, insn, addr, il, il_op):
        n = insn.yaml_name.upper()
        ops = insn.operands
        fn = getattr(il, il_op)

        if "ACC_P" in n:
            il.append(il.nop())  # 64-bit shifts can't be expressed in LLIL
            return True
        if "ACC" in n:
            if ops and ops[0].type == OperandType.IMMEDIATE:
                sh = self._c(il, 4, ops[0].value)
            else:
                sh = il.zero_extend(4, il.reg(2, "T"))
            il.append(il.set_reg(4, "ACC", fn(4, il.reg(4, "ACC"), sh)))
            return True
        if "AX" in n:
            op0 = self._op(ops, 0)
            ax = op0.name if op0 and op0.type == OperandType.REGISTER else "AL"
            op1 = self._op(ops, 1)
            if op1 and op1.type == OperandType.IMMEDIATE:
                sh = self._c(il, 2, op1.value)
            else:
                sh = il.zero_extend(2, il.reg(2, "T"))
            il.append(il.set_reg(2, ax, fn(2, il.reg(2, ax), sh)))
            return True

        il.append(il.nop())
        return True

    def _sem_cond_branch(self, insn, addr, il):
        cond_op = None
        for op in insn.operands:
            if op.type == OperandType.CONDITION:
                cond_op = op
                break

        # Unconditional: only when explicit cond4 operand is UNC (0xF)
        if cond_op is not None and cond_op.value == 0xF:
            if insn.branch_target is not None:
                if self._is_prologue_at(il, insn.branch_target):
                    il.append(il.tailcall(il.const_pointer(4, insn.branch_target)))
                else:
                    il.append(il.jump(il.const_pointer(4, insn.branch_target)))
            else:
                il.append(il.nop())
            return True

        if insn.branch_target is None:
            il.append(il.nop())
            return True

        # No cond4 operand → implicit condition (SBF, BAR, LOOP, etc.)
        # These should have explicit _lift_* handlers; nop as fallback
        if cond_op is None:
            il.append(il.nop())
            return True

        cond_il = self._flag_condition(cond_op.value, il)
        if cond_il is None:
            il.append(il.nop())
            return True

        try:
            from binaryninja import Architecture, LowLevelILLabel
            arch = Architecture["tms320c28x"]
            t = il.get_label_for_address(arch, insn.branch_target)
            f = il.get_label_for_address(arch, addr + insn.size)
            # Use fresh labels as fallback if address resolution fails
            if t is None:
                t = LowLevelILLabel()
            if f is None:
                f = LowLevelILLabel()
            il.append(il.if_expr(cond_il, t, f))
        except Exception:
            il.append(il.nop())
        return True

    def _sem_call_or_branch(self, insn, addr, il):
        if insn.branch_type == BranchType.CALL:
            if insn.branch_target is not None:
                il.append(il.call(il.const_pointer(4, insn.branch_target)))
            else:
                n = insn.yaml_name.upper()
                if "XAR7" in n:
                    il.append(il.call(il.reg(4, "XAR7")))
                elif "XARN" in n and insn.operands and 0 <= insn.operands[0].value <= 7:
                    il.append(il.call(il.reg(4, f"XAR{insn.operands[0].value}")))
                elif "AL" in n:
                    il.append(il.call(il.zero_extend(4, il.reg(2, "AL"))))
                else:
                    il.append(il.nop())
            return True
        # Branch
        if insn.branch_target is not None:
            il.append(il.jump(il.const_pointer(4, insn.branch_target)))
        else:
            n = insn.yaml_name.upper()
            if "XAR7" in n:
                il.append(il.jump(il.reg(4, "XAR7")))
            elif "AL" in n:
                il.append(il.jump(il.zero_extend(4, il.reg(2, "AL"))))
            else:
                il.append(il.nop())
        return True

    def _sem_return(self, insn, addr, il):
        n = insn.yaml_name.upper()
        if "LRETR" in n:
            il.append(il.set_reg(4, "RPC", il.pop(4)))
            il.append(il.ret(il.reg(4, "RPC")))
        elif "IRET" in n:
            il.append(il.ret(il.pop(4)))
        else:
            il.append(il.ret(il.reg(4, "RPC")))
        return True

    def _sem_branch(self, insn, addr, il):
        if insn.branch_target is not None:
            if self._is_prologue_at(il, insn.branch_target):
                il.append(il.tailcall(il.const_pointer(4, insn.branch_target)))
            else:
                il.append(il.jump(il.const_pointer(4, insn.branch_target)))
        else:
            n = insn.yaml_name.upper()
            if "XAR7" in n:
                il.append(il.jump(il.reg(4, "XAR7")))
            elif "AL" in n:
                il.append(il.jump(il.zero_extend(4, il.reg(2, "AL"))))
            else:
                il.append(il.nop())
        return True

    def _sem_call(self, insn, addr, il):
        return self._sem_call_or_branch(insn, addr, il)

    # ------------------------------------------------------------------ #
    # FPU IL lifting (Phases 1-3)                                          #
    # ------------------------------------------------------------------ #

    # Conversion lookup tables
    _REG_CONV = {
        "I16TOF32_RAH_RBH": "i16tof32", "UI16TOF32_RAH_RBH": "ui16tof32",
        "I32TOF32_RAH_RBH": "i32tof32", "UI32TOF32_RAH_RBH": "ui32tof32",
        "F32TOI16_RAH_RBH": "f32toi16", "F32TOI16R_RAH_RBH": "f32toi16",
        "F32TOUI16_RAH_RBH": "f32toui16", "F32TOUI16R_RAH_RBH": "f32toui16",
        "F32TOI32_RAH_RBH": "f32toi32", "F32TOUI32_RAH_RBH": "f32toui32",
    }
    _MEM_CONV = {
        "I16TOF32_RAH_MEM16": ("i16tof32", 2),
        "UI16TOF32_RAH_MEM16": ("ui16tof32", 2),
        "I32TOF32_RAH_MEM32": ("i32tof32", 4),
        "F32TOI32_RAH_MEM32": ("f32toi32", 4),
        "F32TOUI32_RAH_MEM32": ("f32toui32", 4),
    }

    def _fpu_intrinsic(self, il, name, dest_reg, inputs):
        """Emit an FPU intrinsic: dest_reg = name(inputs...)."""
        try:
            from binaryninja import RegisterOrFlag
            il.append(il.intrinsic(
                [RegisterOrFlag.register(il.arch, dest_reg)],
                name, inputs))
        except Exception:
            il.append(il.nop())

    def _fpu_intrinsic_void(self, il, name, inputs):
        """Emit an FPU intrinsic with no output register (e.g., cmpf32)."""
        try:
            il.append(il.intrinsic([], name, inputs))
        except Exception:
            il.append(il.nop())

    def _sem_fpu(self, insn, addr, il):
        n = insn.yaml_name.upper()
        ops = insn.operands

        # --- Phase 1: MOV32 load/store ---
        if n == "MOV32_RAH_MEM32":
            rah = self._op(ops, 0)
            mem = self._op(ops, 1)
            if rah and mem:
                il.append(il.set_reg(4, rah.name, self._read_op(mem, il, 4)))
            else:
                il.append(il.nop())
            return True

        if n == "MOV32_MEM32_RAH":
            mem = self._op(ops, 0)
            rah = self._op(ops, 1)
            if mem and rah:
                self._write_loc(mem, il, 4, il.reg(4, rah.name))
            else:
                il.append(il.nop())
            return True

        if n == "MOV32_MEM32_RAH_COND":
            mem = self._op(ops, 0)
            rah = self._op(ops, 1)
            if mem and rah:
                self._write_loc(mem, il, 4, il.reg(4, rah.name))
            else:
                il.append(il.nop())
            return True

        if n == "MOV32_RAH_RBH":
            rah = self._op(ops, 0)
            rbh = self._op(ops, 1)
            if rah and rbh:
                il.append(il.set_reg(4, rah.name, il.reg(4, rbh.name)))
            else:
                il.append(il.nop())
            return True

        if n == "MOV32_MEM32_STF":
            mem = self._op(ops, 0)
            if mem:
                self._write_loc(mem, il, 4, il.reg(4, "STF"))
            else:
                il.append(il.nop())
            return True

        if n == "MOV32_STF_MEM32":
            mem = self._op(ops, 0)
            if mem:
                il.append(il.set_reg(4, "STF", self._read_op(mem, il, 4)))
            else:
                il.append(il.nop())
            return True

        if n == "ZEROF32_RAH":
            rah = self._op(ops, 0)
            if rah:
                il.append(il.set_reg(4, rah.name, self._c(il, 4, 0)))
            else:
                il.append(il.nop())
            return True

        # --- Phase 2: FPU arithmetic intrinsics ---

        # 3-register: RaH = op(RbH, RcH)
        if n in ("ADDF32_RAH_RBH_RCH", "SUBF32_RAH_RBH_RCH",
                 "MPYF32_RAH_RBH_RCH", "MACF32_RAH_RBH_RCH"):
            rah = self._op(ops, 0)
            rbh = self._op(ops, 1)
            rch = self._op(ops, 2)
            if rah and rbh and rch:
                iname = n.split("_")[0].lower()  # "addf32", "subf32", etc.
                self._fpu_intrinsic(il, iname, rah.name,
                                    [il.reg(4, rbh.name), il.reg(4, rch.name)])
            else:
                il.append(il.nop())
            return True

        # 2-register unary: RaH = op(RbH)
        if n in ("ABSF32_RAH_RBH", "EINVF32_RAH_RBH", "EISQRTF32_RAH_RBH",
                 "FRACF32_RAH_RBH"):
            rah = self._op(ops, 0)
            rbh = self._op(ops, 1)
            if rah and rbh:
                iname = n.split("_")[0].lower()
                self._fpu_intrinsic(il, iname, rah.name, [il.reg(4, rbh.name)])
            else:
                il.append(il.nop())
            return True

        # 2-register min/max: RaH = op(RaH, RbH)
        if n in ("MAXF32_RAH_RBH", "MINF32_RAH_RBH"):
            rah = self._op(ops, 0)
            rbh = self._op(ops, 1)
            if rah and rbh:
                iname = n.split("_")[0].lower()
                self._fpu_intrinsic(il, iname, rah.name,
                                    [il.reg(4, rah.name), il.reg(4, rbh.name)])
            else:
                il.append(il.nop())
            return True

        # Compare: sets flags, no register output
        if n == "CMPF32_RAH_RBH":
            rah = self._op(ops, 0)
            rbh = self._op(ops, 1)
            if rah and rbh:
                self._fpu_intrinsic_void(il, "cmpf32",
                                         [il.reg(4, rah.name), il.reg(4, rbh.name)])
            else:
                il.append(il.nop())
            return True

        if n == "CMPF32_RAH_0":
            rah = self._op(ops, 0)
            if rah:
                self._fpu_intrinsic_void(il, "cmpf32",
                                         [il.reg(4, rah.name), self._c(il, 4, 0)])
            else:
                il.append(il.nop())
            return True

        # --- Phase 3: FPU conversions ---

        if n in self._REG_CONV:
            rah = self._op(ops, 0)
            rbh = self._op(ops, 1)
            if rah and rbh:
                self._fpu_intrinsic(il, self._REG_CONV[n], rah.name,
                                    [il.reg(4, rbh.name)])
            else:
                il.append(il.nop())
            return True

        if n in self._MEM_CONV:
            iname, mem_size = self._MEM_CONV[n]
            rah = self._op(ops, 0)
            mem = self._op(ops, 1)
            if rah and mem:
                self._fpu_intrinsic(il, iname, rah.name,
                                    [self._read_op(mem, il, mem_size)])
            else:
                il.append(il.nop())
            return True

        # MOVST0 — move FPU status to CPU
        if n == "MOVST0_FLAG":
            il.append(il.nop())
            return True

        # Catch-all for remaining FPU (SWAPF, packed 16-bit ops, etc.)
        il.append(il.nop())
        return True

    def _sem_fpu_parallel(self, insn, addr, il):
        # Parallel FPU ops are pipeline scheduling hints; emit nop
        il.append(il.nop())
        return True

    # ------------------------------------------------------------------ #
    # Integer multiply (Phase 4)                                           #
    # ------------------------------------------------------------------ #

    def _sem_mpy(self, insn, addr, il):
        n = insn.yaml_name.upper()
        ops = insn.operands

        # Simple 16x16 signed: dest = T * loc16
        if n == "MPY_ACC_T_LOC16":
            if ops:
                src = self._read_op(ops[0], il, 2)
                il.append(il.set_reg(4, "ACC",
                    il.mult(4, il.sign_extend(4, il.reg(2, "T")),
                                il.sign_extend(4, src))))
            return True

        if n == "MPY_P_T_LOC16":
            if ops:
                src = self._read_op(ops[0], il, 2)
                il.append(il.set_reg(4, "P",
                    il.mult(4, il.sign_extend(4, il.reg(2, "T")),
                                il.sign_extend(4, src))))
            return True

        # Unsigned 16x16
        if n == "MPYU_ACC_T_LOC16":
            if ops:
                src = self._read_op(ops[0], il, 2)
                il.append(il.set_reg(4, "ACC",
                    il.mult(4, il.zero_extend(4, il.reg(2, "T")),
                                il.zero_extend(4, src))))
            return True

        if n == "MPYU_P_T_LOC16":
            if ops:
                src = self._read_op(ops[0], il, 2)
                il.append(il.set_reg(4, "P",
                    il.mult(4, il.zero_extend(4, il.reg(2, "T")),
                                il.zero_extend(4, src))))
            return True

        # Mixed signed*unsigned
        if n in ("MPYXU_ACC_T_LOC16", "MPYXU_P_T_LOC16"):
            dest = "ACC" if "ACC" in n else "P"
            if ops:
                src = self._read_op(ops[0], il, 2)
                il.append(il.set_reg(4, dest,
                    il.mult(4, il.sign_extend(4, il.reg(2, "T")),
                                il.zero_extend(4, src))))
            return True

        # 8-bit immediate multiply
        if n in ("MPYB_ACC_T_CONST8", "MPYB_P_T_CONST8"):
            dest = "ACC" if "ACC" in n else "P"
            if ops:
                il.append(il.set_reg(4, dest,
                    il.mult(4, il.sign_extend(4, il.reg(2, "T")),
                                il.zero_extend(4, self._c(il, 1, ops[0].value)))))
            return True

        # loc16 * const16
        if n in ("MPY_ACC_LOC16_CONST16", "MPY_P_LOC16_CONST16"):
            dest = "ACC" if "ACC" in n else "P"
            op0, op1 = self._op(ops, 0), self._op(ops, 1)
            if op0 and op1:
                il.append(il.set_reg(4, dest,
                    il.mult(4, il.sign_extend(4, self._read_op(op0, il, 2)),
                                il.sign_extend(4, self._c(il, 2, op1.value)))))
            return True

        # Multiply-accumulate: ACC += P; P = T * loc16
        if n in ("MPYA_P_T_LOC16", "MPYA_P_LOC16_CONST16"):
            il.append(il.set_reg(4, "ACC", il.add(4, il.reg(4, "ACC"), il.reg(4, "P"))))
            if ops:
                src = self._read_op(ops[0], il, 2)
                il.append(il.set_reg(4, "P",
                    il.mult(4, il.sign_extend(4, il.reg(2, "T")),
                                il.sign_extend(4, src))))
            return True

        # Multiply-subtract: ACC -= P; P = T * loc16
        if n == "MPYS_P_T_LOC16":
            il.append(il.set_reg(4, "ACC", il.sub(4, il.reg(4, "ACC"), il.reg(4, "P"))))
            if ops:
                src = self._read_op(ops[0], il, 2)
                il.append(il.set_reg(4, "P",
                    il.mult(4, il.sign_extend(4, il.reg(2, "T")),
                                il.sign_extend(4, src))))
            return True

        # 32-bit multiply: dest = XT * loc32
        if n in ("IMPYL_ACC_XT_LOC32", "IMPYL_P_XT_LOC32",
                 "QMPYL_P_XT_LOC32"):
            dest = "ACC" if "ACC" in n else "P"
            if ops:
                il.append(il.set_reg(4, dest,
                    il.mult(4, il.reg(4, "XT"), self._read_op(ops[0], il, 4))))
            return True

        # 32-bit multiply-accumulate: ACC += P; P = XT * loc32
        if n in ("IMPYAL_P_XT_LOC32", "QMPYAL_P_XT_LOC32"):
            il.append(il.set_reg(4, "ACC", il.add(4, il.reg(4, "ACC"), il.reg(4, "P"))))
            if ops:
                il.append(il.set_reg(4, "P",
                    il.mult(4, il.reg(4, "XT"), self._read_op(ops[0], il, 4))))
            return True

        # 32-bit multiply-subtract: ACC -= P; P = XT * loc32
        if n in ("IMPYSL_P_XT_LOC32", "QMPYSL_P_XT_LOC32"):
            il.append(il.set_reg(4, "ACC", il.sub(4, il.reg(4, "ACC"), il.reg(4, "P"))))
            if ops:
                il.append(il.set_reg(4, "P",
                    il.mult(4, il.reg(4, "XT"), self._read_op(ops[0], il, 4))))
            return True

        # Square: P = T * T
        if n.startswith("SQR"):
            il.append(il.set_reg(4, "P",
                il.mult(4, il.sign_extend(4, il.reg(2, "T")),
                            il.sign_extend(4, il.reg(2, "T")))))
            return True

        # Remaining (unsigned 32-bit, MAC, etc.)
        il.append(il.nop())
        return True

    # ------------------------------------------------------------------ #
    # System operations (Phase 5)                                          #
    # ------------------------------------------------------------------ #

    def _sem_system(self, insn, addr, il):
        n = insn.yaml_name.upper()
        ops = insn.operands

        # TCLR — test and clear bit
        if n == "TCLR_LOC16_BIT":
            op0, op1 = self._op(ops, 0), self._op(ops, 1)
            if op0 and op1:
                bit_mask = il.not_expr(2, il.shift_left(2, self._c(il, 2, 1),
                                       self._c(il, 2, op1.value)))
                self._write_loc(op0, il, 2,
                    il.and_expr(2, self._read_op(op0, il, 2), bit_mask))
            return True

        # TSET — test and set bit
        if n == "TSET_LOC16_BIT":
            op0, op1 = self._op(ops, 0), self._op(ops, 1)
            if op0 and op1:
                bit_mask = il.shift_left(2, self._c(il, 2, 1),
                                         self._c(il, 2, op1.value))
                self._write_loc(op0, il, 2,
                    il.or_expr(2, self._read_op(op0, il, 2), bit_mask))
            return True

        # ROL/ROR ACC
        if n == "ROL_ACC":
            il.append(il.set_reg(4, "ACC",
                il.rotate_left(4, il.reg(4, "ACC"), self._c(il, 4, 1))))
            return True
        if n == "ROR_ACC":
            il.append(il.set_reg(4, "ACC",
                il.rotate_right(4, il.reg(4, "ACC"), self._c(il, 4, 1))))
            return True

        # ZAPA — zero ACC, P, and OVC
        if n == "ZAPA":
            il.append(il.set_reg(4, "ACC", self._c(il, 4, 0)))
            il.append(il.set_reg(4, "P", self._c(il, 4, 0)))
            return True

        # All others: nop (SETC, CLRC, EALLOW, EDIS, RPT, NOP, SAT, MAX,
        #   MIN, TBIT, ABS, SPM, NORM, FLIP, CSB, I/O, PREAD/PWRITE, MAC, etc.)
        il.append(il.nop())
        return True

    def _sem_trap(self, insn, addr, il):
        n = insn.yaml_name.upper()
        if "ESTOP" in n:
            il.append(il.breakpoint())
        else:
            il.append(il.system_call())
        return True

    # Explicit handler for SBF (condition in opcode bits [9:8], no cond4 operand)
    def _lift_sbf(self, insn, addr, il):
        if insn.branch_target is None:
            il.append(il.nop())
            return True
        try:
            from binaryninja import Architecture, LowLevelILLabel
            from binaryninja.enums import LowLevelILFlagCondition as FC
        except ImportError:
            il.append(il.nop())
            return True
        # SBF condition: bits [9:8] → 0=EQ, 1=NEQ, 2=TC, 3=NTC
        sbf_cond = (insn.opcode >> 8) & 0x3
        if sbf_cond == 0:
            cond_il = il.flag_condition(FC.LLFC_E)
        elif sbf_cond == 1:
            cond_il = il.flag_condition(FC.LLFC_NE)
        elif sbf_cond == 2:
            cond_il = il.flag("TC")
        elif sbf_cond == 3:
            cond_il = il.not_expr(0, il.flag("TC"))
        else:
            il.append(il.nop())
            return True
        arch = Architecture["tms320c28x"]
        t = il.get_label_for_address(arch, insn.branch_target)
        f = il.get_label_for_address(arch, addr + insn.size)
        if t is None:
            t = LowLevelILLabel()
        if f is None:
            f = LowLevelILLabel()
        il.append(il.if_expr(cond_il, t, f))
        return True

    # Explicit handlers for BAR (branch if ARn == / != ARm, no cond4 operand)
    def _lift_bar_off16_arn_arm_eq(self, insn, addr, il):
        return self._lift_bar(insn, addr, il, equal=True)

    def _lift_bar_off16_arn_arm_neq(self, insn, addr, il):
        return self._lift_bar(insn, addr, il, equal=False)

    def _lift_bar(self, insn, addr, il, equal):
        if insn.branch_target is None:
            il.append(il.nop())
            return True
        reg_ops = [op for op in insn.operands if op.type == OperandType.REGISTER]
        if len(reg_ops) < 2:
            il.append(il.nop())
            return True
        ar_n = f"AR{reg_ops[0].value}"
        ar_m = f"AR{reg_ops[1].value}"
        if equal:
            cond = il.compare_equal(2, il.reg(2, ar_n), il.reg(2, ar_m))
        else:
            cond = il.compare_not_equal(2, il.reg(2, ar_n), il.reg(2, ar_m))
        try:
            from binaryninja import Architecture, LowLevelILLabel
            arch = Architecture["tms320c28x"]
            t = il.get_label_for_address(arch, insn.branch_target)
            f = il.get_label_for_address(arch, addr + insn.size)
            if t is None:
                t = LowLevelILLabel()
            if f is None:
                f = LowLevelILLabel()
            il.append(il.if_expr(cond, t, f))
        except Exception:
            il.append(il.nop())
        return True

    # Explicit handler for BANZ
    def _lift_banz(self, insn, addr, il):
        ops = insn.operands
        n_op = next((op for op in ops if op.type == OperandType.REGISTER), None)
        if n_op is None or insn.branch_target is None:
            il.append(il.nop())
            return True
        if not (0 <= n_op.value <= 7):
            il.append(il.nop())
            return True
        ar = f"AR{n_op.value}"
        il.append(il.set_reg(2, ar, il.sub(2, il.reg(2, ar), self._c(il, 2, 1))))
        try:
            from binaryninja import Architecture
            arch = Architecture["tms320c28x"]
            t = il.get_label_for_address(arch, insn.branch_target)
            f = il.get_label_for_address(arch, addr + insn.size)
            if t is not None and f is not None:
                il.append(il.if_expr(
                    il.compare_not_equal(2, il.reg(2, ar), self._c(il, 2, 0)),
                    t, f))
            else:
                il.append(il.nop())
        except Exception:
            il.append(il.nop())
        return True

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _is_prologue_at(self, il, addr):
        """Check if addr starts with ADDB SP, #N (function prologue).

        Used to distinguish tail calls (target has prologue = real function)
        from intra-function jumps (target has no prologue = shared block).
        """
        try:
            view = il.source_function.view
            data = view.read(addr, 2)
            if data and len(data) >= 2:
                op16 = data[0] | (data[1] << 8)  # little-endian
                return (op16 & 0xFF80) == 0xFE00  # ADDB SP, #const7
        except Exception:
            pass
        return False

    def _dest_reg_from_name(self, n):
        for reg, sz in [("ACC",4), ("P",4), ("XT",4), ("T",2), ("TL",2),
                        ("PH",2), ("PL",2), ("DP",2), ("SP",2), ("IER",2),
                        ("IFR",2), ("DBGIER",2), ("ST0",2), ("ST1",2), ("RPC",4)]:
            if f"_{reg}_" in f"_{n}_" or n.endswith(f"_{reg}"):
                return (reg, sz)
        for i in range(8):
            if f"XAR{i}" in n:
                return (f"XAR{i}", 4)
            if f"_AR{i}_" in f"_{n}_" or n.endswith(f"_AR{i}"):
                return (f"AR{i}", 2)
        return None

    def _flag_condition(self, code, il):
        try:
            from binaryninja.enums import LowLevelILFlagCondition as FC
        except ImportError:
            return None
        mapping = {
            0x0: FC.LLFC_NE, 0x1: FC.LLFC_E, 0x2: FC.LLFC_SGT, 0x3: FC.LLFC_SGE,
            0x4: FC.LLFC_SLT, 0x5: FC.LLFC_SLE, 0x6: FC.LLFC_UGT, 0x7: FC.LLFC_UGE,
            0x8: FC.LLFC_ULT, 0x9: FC.LLFC_ULE, 0xA: FC.LLFC_NO, 0xB: FC.LLFC_O,
        }
        fc = mapping.get(code)
        if fc is not None:
            return il.flag_condition(fc)
        if code == 0xC:
            return il.not_expr(0, il.flag("TC"))
        if code == 0xD:
            return il.flag("TC")
        return None
