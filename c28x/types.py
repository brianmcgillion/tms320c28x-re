# SPDX-License-Identifier: MIT
"""Core types for the C28x decoder — no tool dependencies."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from c28x.operands import ResolvedOperand


class OperandType(Enum):
    """Types of instruction operands."""
    REGISTER = auto()      # Direct register reference
    IMMEDIATE = auto()     # Immediate constant
    LOC16 = auto()         # 16-bit addressed location
    LOC32 = auto()         # 32-bit addressed location
    CONDITION = auto()     # Branch condition code
    MEMORY = auto()        # Resolved memory address


class BranchType(Enum):
    """Control flow classification for CFG construction."""
    NONE = auto()
    UNCONDITIONAL = auto()
    CONDITIONAL_TRUE = auto()
    CONDITIONAL_FALSE = auto()
    CALL = auto()
    RETURN = auto()
    TRAP = auto()


@dataclass
class Operand:
    """A decoded instruction operand."""
    type: OperandType
    value: int = 0
    name: str = ""         # Register name or addressing mode text
    size: int = 2          # Size in bytes (2 = 16-bit word, 4 = 32-bit)
    signed: bool = False
    resolved: ResolvedOperand | None = None  # Populated for LOC16/LOC32


@dataclass
class DecodedInstruction:
    """Result of decoding a single instruction."""
    name: str                          # Mnemonic (e.g., "MOV", "ADD", "B")
    yaml_name: str = ""                # Original YAML name for lifter dispatch
    full_name: str = ""                # Human-readable description
    size: int = 2                      # Instruction size in bytes (2 or 4)
    operands: list[Operand] = field(default_factory=list)
    opcode: int = 0                    # Raw opcode value
    branch_type: BranchType = BranchType.NONE
    branch_target: int | None = None   # Resolved branch target address
    flags_written: list[str] = field(default_factory=list)
    semantics: dict = field(default_factory=dict)

    @property
    def is_branch(self) -> bool:
        return self.branch_type not in (BranchType.NONE,)

    @property
    def is_call(self) -> bool:
        return self.branch_type == BranchType.CALL

    @property
    def is_return(self) -> bool:
        return self.branch_type == BranchType.RETURN
