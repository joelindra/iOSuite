"""
Disassembly Context Helper
Formats machine instructions using Capstone engine or Frida parsed instructions.
"""

from typing import List, Dict, Any, Optional
import capstone


def disassemble_bytes(
    code_bytes: bytes,
    base_address: int,
    arch: str = "arm64",
    highlight_pc: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Disassemble raw bytes using Capstone engine.
    Returns list of instruction dictionaries.
    """
    if arch.lower() in ("arm64", "aarch64"):
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    elif arch.lower() in ("x64", "x86_64", "simulator"):
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

    instructions = []
    for insn in md.disasm(code_bytes, base_address):
        is_pc = (highlight_pc is not None and insn.address == highlight_pc)
        instructions.append({
            "address": f"0x{insn.address:016X}",
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "size": insn.size,
            "is_pc": is_pc,
        })
    return instructions


def format_instruction_lines(instructions: List[Dict[str, Any]]) -> List[str]:
    """Format instruction dictionaries into aligned strings for TUI rendering."""
    lines = []
    for ins in instructions:
        addr = ins.get("address", "")
        mnemonic = ins.get("mnemonic", "").ljust(8)
        op_str = ins.get("op_str", "")
        prefix = "-> " if ins.get("is_pc") else "   "
        lines.append(f"{prefix}{addr}  {mnemonic} {op_str}")
    return lines
