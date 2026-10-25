"""
Swift & Objective-C Symbol Demangler
Provides demangling for Swift 5+, legacy Swift, and Objective-C method signatures.
"""

import re
import shutil
import subprocess
from functools import lru_cache
from typing import Tuple


SWIFT_PREFIXES = ("$s", "_$s", "$S", "_$S", "_T")


def is_swift_symbol(symbol: str) -> bool:
    """Check if a symbol is a Swift mangled name."""
    if not symbol:
        return False
    return symbol.startswith(SWIFT_PREFIXES)


def _heuristic_swift_demangle(mangled: str) -> str:
    """
    Fallback demangler parsing standard Swift 5 length-prefixed identifier strings.
    E.g.: $s7AcmeApp22CheckoutViewControllerC11onPayTappedyyF
    """
    # Strip prefix
    s = mangled
    for prefix in SWIFT_PREFIXES:
        if s.startswith(prefix):
            s = s[len(prefix):]
            break

    # Extract tokens with leading digits: (\d+)([A-Za-z0-9_]+)
    tokens = []
    i = 0
    n = len(s)
    while i < n:
        # Skip non-digit separators/kind indicators (e.g. C, V, E, F)
        while i < n and not s[i].isdigit():
            i += 1
        if i >= n:
            break
        # Read full length number
        num_str = ""
        while i < n and s[i].isdigit():
            num_str += s[i]
            i += 1
        length = int(num_str)
        token = s[i:i + length]
        if token and len(token) == length:
            tokens.append(token)
            i += length
        else:
            break

    if len(tokens) >= 2:
        # e.g., Module.Class.function()
        return ".".join(tokens) + "()"
    elif len(tokens) == 1:
        return tokens[0]

    return mangled


@lru_cache(maxsize=4096)
def demangle_swift(symbol: str) -> str:
    """
    Demangle a Swift mangled name using swift-demangle if available,
    otherwise falling back to heuristic parsing.
    """
    if not is_swift_symbol(symbol):
        return symbol

    # Check if swift-demangle or xcrun is available
    tool = shutil.which("swift-demangle")
    if tool:
        try:
            res = subprocess.run(
                [tool, "--compact", symbol],
                capture_output=True,
                text=True,
                timeout=1,
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception:
            pass

    return _heuristic_swift_demangle(symbol)


def parse_objc_selector(selector_str: str) -> Tuple[str, str]:
    """
    Parse an Objective-C selector string.
    Returns (normalized_name, parameter_count).
    E.g.: "sendAction:to:from:forEvent:" -> ("sendAction:to:from:forEvent:", 4)
    """
    if not selector_str:
        return ("", 0)
    colons = selector_str.count(":")
    return (selector_str, colons)


def format_symbol_display(symbol: str, target_class: str = "", selector: str = "") -> str:
    """Format symbol for display in the TUI."""
    if symbol and is_swift_symbol(symbol):
        return demangle_swift(symbol)
    if target_class and selector:
        return f"- [{target_class} {selector}]"
    if symbol:
        return symbol
    return f"- [{target_class or 'Unknown'} {selector or 'action'}]"
