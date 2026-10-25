"""
Unit tests for Swift demangler & ObjC signature parser.
"""

from iosuite.core.demangler import (
    is_swift_symbol,
    demangle_swift,
    parse_objc_selector,
    format_symbol_display,
)


def test_is_swift_symbol():
    assert is_swift_symbol("$s8AcmeBank22CheckoutViewControllerC11onPayTappedyyF") is True
    assert is_swift_symbol("_$s8AcmeBank22CheckoutViewControllerC11onPayTappedyyF") is True
    assert is_swift_symbol("-[CheckoutViewController onPayTapped:]") is False


def test_demangle_swift_heuristic():
    mangled = "$s8AcmeBank22CheckoutViewControllerC11onPayTappedyyF"
    demangled = demangle_swift(mangled)
    assert "AcmeBank" in demangled
    assert "CheckoutViewController" in demangled
    assert "onPayTapped" in demangled


def test_parse_objc_selector():
    name, colons = parse_objc_selector("sendAction:to:from:forEvent:")
    assert name == "sendAction:to:from:forEvent:"
    assert colons == 4

    name, colons = parse_objc_selector("viewDidLoad")
    assert colons == 0


def test_format_symbol_display():
    disp = format_symbol_display("", "CheckoutViewController", "onPayTapped:")
    assert disp == "- [CheckoutViewController onPayTapped:]"
