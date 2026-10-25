"""
Mach-O Address & Offset Resolver
Calculates static file offsets, handles segments and dyld_shared_cache awareness,
and generates disassembler jump commands for IDA Pro, Ghidra, Hopper, and LLDB.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


@dataclass
class MachOSegment:
    segname: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int


@dataclass
class ResolvedLocation:
    address: str
    module_name: str
    module_base: str
    file_offset: str
    aslr_slide: str
    ida_jump: str
    ghidra_jump: str
    r2_jump: str
    is_app: bool
    is_shared_cache: bool = False
    lldb_lookup: str = ""


def parse_addr(addr: int | str) -> int:
    """Safely parse hex string or int to integer address."""
    if isinstance(addr, int):
        return addr
    addr_str = str(addr).strip()
    if addr_str.lower().startswith("0x"):
        return int(addr_str, 16)
    try:
        return int(addr_str, 16)
    except ValueError:
        return int(addr_str)


def is_dyld_cache_path(module_name: str) -> bool:
    """Check if module path belongs to system dyld shared cache."""
    m = module_name.lower()
    return "/system/library/" in m or "/usr/lib/" in m or "dyld_shared_cache" in m


def calculate_offset(
    address: int | str,
    module_base: int | str,
    header_offset: int = 0,
    segments: Optional[List[MachOSegment]] = None,
) -> int:
    """
    Calculate the static Mach-O file/relative offset.
    Supports segment mapping when segments are provided.
    Offset = Address - ModuleBase + HeaderOffset
    """
    addr_int = parse_addr(address)
    base_int = parse_addr(module_base)
    if base_int <= 0:
        return addr_int

    # If segment boundary metadata is provided, map via LC_SEGMENT_64
    if segments:
        for seg in segments:
            seg_start = base_int + seg.vmaddr
            seg_end = seg_start + seg.vmsize
            if seg_start <= addr_int < seg_end:
                return (addr_int - seg_start) + seg.fileoff

    return max(0, addr_int - base_int + header_offset)


def generate_disassembler_commands(offset: int, module_name: str, impl_addr: Optional[int] = None) -> dict[str, str]:
    """Generate quick-copy jump commands for popular reverse engineering tools."""
    offset_hex = f"0x{offset:X}"
    mod_short = module_name.split("/")[-1].replace(".app", "").replace(".framework", "")
    addr_str = f"0x{impl_addr:X}" if impl_addr else offset_hex

    return {
        "ida": f"ida_kernwin.jumpto(get_imagebase() + {offset_hex})",
        "ghidra": f"toAddr({offset_hex})",
        "hopper": f"s {offset_hex}",
        "r2": f"s {offset_hex} # in {mod_short}",
        "lldb": f"image lookup -a {addr_str}",
        "offset_only": offset_hex,
    }


def resolve_location(
    address: int | str,
    module_name: str,
    module_base: int | str,
    is_app: bool = True,
    header_offset: int = 0,
    segments: Optional[List[MachOSegment]] = None,
) -> ResolvedLocation:
    """Build a comprehensive ResolvedLocation object."""
    addr_int = parse_addr(address)
    base_int = parse_addr(module_base)
    in_cache = is_dyld_cache_path(module_name)
    offset = calculate_offset(addr_int, base_int, header_offset, segments)
    cmds = generate_disassembler_commands(offset, module_name, addr_int)

    return ResolvedLocation(
        address=f"0x{addr_int:016X}",
        module_name=module_name or "Unknown",
        module_base=f"0x{base_int:016X}",
        file_offset=f"0x{offset:08X}",
        aslr_slide=f"0x{base_int:016X}",
        ida_jump=cmds["ida"],
        ghidra_jump=cmds["ghidra"],
        r2_jump=cmds["r2"],
        is_app=is_app,
        is_shared_cache=in_cache,
        lldb_lookup=cmds["lldb"],
    )
