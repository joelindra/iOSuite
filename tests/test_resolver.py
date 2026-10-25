"""
Unit tests for Mach-O address & offset resolver.
"""

from iosuite.core.resolver import (
    parse_addr,
    calculate_offset,
    generate_disassembler_commands,
    resolve_location,
)


def test_parse_addr():
    assert parse_addr(0x104800000) == 0x104800000
    assert parse_addr("0x104800000") == 0x104800000
    assert parse_addr("104800000") == 0x104800000


def test_calculate_offset():
    base = 0x104800000
    impl = 0x104A1B240
    offset = calculate_offset(impl, base)
    assert offset == 0x21B240


def test_generate_disassembler_commands():
    offset = 0x21B240
    cmds = generate_disassembler_commands(offset, "AcmeBank.app/AcmeBank")
    assert "ida_kernwin.jumpto(get_imagebase() + 0x21B240)" in cmds["ida"]
    assert "toAddr(0x21B240)" in cmds["ghidra"]
    assert "s 0x21B240" in cmds["r2"]


def test_resolve_location():
    loc = resolve_location(
        address="0x104A1B240",
        module_name="AcmeBank.app/AcmeBank",
        module_base="0x104800000",
        is_app=True,
    )
    assert loc.file_offset == "0x0021B240"
    assert loc.is_app is True
    assert "ida_kernwin" in loc.ida_jump
    assert "image lookup" in loc.lldb_lookup


def test_segment_mapping_and_dyld_cache():
    from iosuite.core.resolver import MachOSegment, is_dyld_cache_path

    # Verify dyld cache path detection
    assert is_dyld_cache_path("/System/Library/Frameworks/UIKit.framework/UIKit") is True
    assert is_dyld_cache_path("/private/var/containers/Bundle/Application/App.app/App") is False

    # Verify segment boundary calculation
    seg_text = MachOSegment(segname="__TEXT", vmaddr=0x0, vmsize=0x10000, fileoff=0x0, filesize=0x10000)
    seg_data = MachOSegment(segname="__DATA", vmaddr=0x10000, vmsize=0x4000, fileoff=0x10000, filesize=0x4000)

    base = 0x100000000
    addr_in_data = 0x100010500  # Offset inside __DATA: 0x500 + 0x10000 = 0x10500
    off = calculate_offset(addr_in_data, base, segments=[seg_text, seg_data])
    assert off == 0x10500

