"""
Textual Widgets for iOSuite Trace
Custom UI components for sidepane, filter bar, detail tabs, and headers with adaptive responsive layouts.
"""

from typing import Optional, List, Dict, Any, Set
import re
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.console import Group
from rich.markup import escape
from rich import box
from textual.widget import Widget
from textual.widgets import (
    Static,
    ListView,
    ListItem,
    TabbedContent,
    TabPane,
    Label,
    Input,
    RichLog,
)
from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal
from iosuite.core.dispatcher import InterceptedEvent
from iosuite.core.demangler import demangle_swift, is_swift_symbol


CATEGORY_BADGES = {
    "ui_action": ("UI ACTION", "bold #34d399 on #064e3b"),
    "gesture": ("GESTURE", "bold #38bdf8 on #0c4a6e"),
    "swiftui": ("SWIFTUI", "bold #fbbf24 on #451a03"),
    "navigation": ("NAVIGATION", "bold #818cf8 on #1e1b4b"),
    "deeplink": ("DEEPLINK", "bold #c084fc on #3b0764"),
    "webview": ("WEBKIT", "bold #f87171 on #450a0a"),
    "network_trigger": ("NETWORK", "bold #60a5fa on #172554"),
    "security": ("SECURITY", "bold #ffffff on #b91c1c"),
}

# Backward compatibility alias
CATEGORY_COLORS = {
    "ui_action": ("UI Action", "bold #34d399 on #064e3b"),
    "gesture": ("Gesture", "bold #38bdf8 on #0c4a6e"),
    "swiftui": ("SwiftUI", "bold #fbbf24 on #451a03"),
    "navigation": ("Navigation", "bold #818cf8 on #1e1b4b"),
    "deeplink": ("DeepLink", "bold #c084fc on #3b0764"),
    "webview": ("WebKit", "bold #f87171 on #450a0a"),
    "network_trigger": ("Network", "bold #60a5fa on #172554"),
    "security": ("Security", "bold #ffffff on #b91c1c"),
}


def _get_widget_width(widget: Widget, default: int = 80) -> int:
    """Helper to get effective width for responsive layout, supporting test overrides."""
    return getattr(widget, "_test_width", None) or (widget.size.width if widget.size.width > 0 else default)


def format_arm64_operands(op_str: str) -> Text:
    """Syntax highlight ARM64 operands (registers in cyan, imm in green, derefs in purple)."""
    t = Text()
    if not op_str:
        return t

    # Tokenize ARM64 operand strings
    parts = re.split(r'([,\s\[\]!#]+)', op_str)
    for p in parts:
        p_lower = p.lower()
        if re.match(r'^(x[0-9]{1,2}|w[0-9]{1,2}|sp|fp|lr|xzr|wzr|q[0-9]{1,2}|d[0-9]{1,2}|s[0-9]{1,2})$', p_lower):
            t.append(p, style="bold #38bdf8")  # Register: Cyan
        elif p.startswith("#") or re.match(r'^0x[0-9a-fA-F]+$', p) or p.isdigit() or re.match(r'^-?[0-9]+$', p):
            t.append(p, style="bold #34d399")  # Immediate / Number: Green
        elif p in ("[", "]", "!"):
            t.append(p, style="bold #c084fc")  # Dereference / Pointer: Purple
        elif p.startswith(";"):
            t.append(p, style="dim #64748b")  # Comment: Dim
        else:
            t.append(p, style="#f8fafc")

    return t


class HeaderBar(Static):
    """Header widget showing app title, target information, and status with responsive sizing."""

    def __init__(self, target: str = "TargetApp", device: str = "USB Device", pid: int = 0):
        super().__init__(id="header-bar")
        self.target = target
        self.device = device
        self.pid = pid
        self.is_recording = True
        self.event_count = 0

    def update_info(
        self,
        target: Optional[str] = None,
        device: Optional[str] = None,
        pid: Optional[int] = None,
        event_count: Optional[int] = None,
    ):
        if target is not None:
            self.target = target
        if device is not None:
            self.device = device
        if pid is not None:
            self.pid = pid
        if event_count is not None:
            self.event_count = event_count
        self.refresh()

    def set_recording(self, recording: bool):
        self.is_recording = recording
        self.refresh()

    def render(self) -> Text:
        w = _get_widget_width(self, 80)
        t = Text()
        dev_str = str(self.device)
        dev_color = "#f87171" if "offline" in dev_str.lower() or "fail" in dev_str.lower() else "#34d399"

        if w < 72:
            # Ultra-compact mode for narrow terminal windows
            t.append(" ◆ iOSuite ", style="bold #38bdf8")
            t.append("│", style="#334155")
            t.append(f" {self.target}", style="bold #f8fafc")
            if self.pid:
                t.append(f"({self.pid})", style="#fbbf24")
            t.append(" │ ", style="#334155")
            t.append(f"{self.device}", style=f"bold {dev_color}")
            t.append(" │ ", style="#334155")
            t.append(f"{self.event_count}ev", style="bold #f8fafc")
            t.append(" ")
            if self.is_recording:
                t.append(" ● ", style="bold white on #dc2626")
            else:
                t.append(" ❚❚ ", style="bold #0f172a on #fbbf24")
        elif w < 96:
            # Medium compact mode
            t.append(" ◆ iOSuite Trace ", style="bold #38bdf8")
            t.append("│", style="#334155")
            t.append(" Target: ", style="#94a3b8")
            t.append(f"{self.target}", style="bold #f8fafc")
            if self.pid:
                t.append(f" ({self.pid})", style="#fbbf24")
            t.append(" │ ", style="#334155")
            t.append(f"{self.device}", style=f"bold {dev_color}")
            t.append(" │ ", style="#334155")
            t.append(f"{self.event_count} ev", style="bold #f8fafc")
            t.append("  ")
            if self.is_recording:
                t.append(" ● REC ", style="bold white on #dc2626")
            else:
                t.append(" ❚❚ PAUSED ", style="bold #0f172a on #fbbf24")
        else:
            # Full expansive layout for wide monitors
            t.append(" ◆ iOSuite Trace ", style="bold #38bdf8")
            t.append("│", style="#334155")
            t.append(" Target: ", style="#94a3b8")
            t.append(f"{self.target}", style="bold #f8fafc")
            if self.pid:
                t.append(f" (PID: {self.pid})", style="#fbbf24")
            t.append(" │ ", style="#334155")
            t.append("Device: ", style="#94a3b8")
            t.append(f"{self.device}", style=f"bold {dev_color}")
            t.append(" │ ", style="#334155")
            t.append("Events: ", style="#94a3b8")
            t.append(f"{self.event_count}", style="bold #f8fafc")
            t.append("  ")
            if self.is_recording:
                t.append(" ● REC ", style="bold white on #dc2626")
            else:
                t.append(" ❚❚ PAUSED ", style="bold #0f172a on #fbbf24")

        return t


class CategoryFilterBar(Static):
    """Interactive category chip indicators above the event timeline."""

    def __init__(self, active_filters: Optional[Set[str]] = None, pinned_only: bool = False):
        super().__init__(id="filter-bar")
        self.active_filters = set(active_filters or [])
        self.pinned_only = pinned_only

    def update_state(self, active_filters: Set[str], pinned_only: bool = False):
        self.active_filters = set(active_filters)
        self.pinned_only = pinned_only
        self.refresh()

    def render(self) -> Text:
        t = Text()
        w = _get_widget_width(self, 32)
        is_narrow = w < 32

        # Pinned Star Filter Indicator
        if self.pinned_only:
            t.append(" ★ PINNED ", style="bold black on #fbbf24")
            t.append(" ")
        else:
            t.append(" ★ ", style="dim #64748b")

        categories = [
            ("ui_action", "UI" if is_narrow else "Action", "#34d399"),
            ("navigation", "Nav", "#818cf8"),
            ("swiftui", "SwiftUI", "#fbbf24"),
            ("network_trigger", "Net", "#60a5fa"),
            ("deeplink", "Link", "#c084fc"),
            ("webview", "Web", "#f87171"),
        ]

        for cat_id, label, col in categories:
            is_active = cat_id in self.active_filters
            if is_active:
                t.append(f" {label} ", style=f"bold black on {col}")
            else:
                t.append(f" {label} ", style=f"dim {col} on #131c2e")
            t.append(" ")

        return t


class EventListItem(ListItem):
    """Render a single intercepted event row in the sidepane with adaptive truncation and pin marker."""

    def __init__(self, event: InterceptedEvent):
        super().__init__(classes="event-item")
        self.event = event

    def render(self) -> Text:
        t = Text()
        # Row 1: Pin icon + Timestamp + Category Badge + Hit count
        if self.event.pinned:
            t.append("★ ", style="bold #fbbf24")
        else:
            t.append("  ", style="dim #334155")

        t.append(f"{self.event.time_str} ", style="#64748b")

        badge_label, badge_style = CATEGORY_BADGES.get(
            self.event.category,
            (self.event.category.upper(), "bold #94a3b8 on #1e293b")
        )
        t.append(f" {badge_label} ", style=badge_style)

        if self.event.hit_count > 1:
            t.append(f" ×{self.event.hit_count}", style="bold #fbbf24")

        t.append("\n")

        # Row 2: Main summary / action - dynamically truncated to avoid awkward line breaks
        w = _get_widget_width(self, 32)
        max_summary_len = max(20, w - 4)
        summary = self.event.summary
        if len(summary) > max_summary_len:
            summary = summary[:max_summary_len - 2] + "…"
        t.append(f"{summary}", style="bold #f8fafc")

        # Row 3: Target Class
        if self.event.target_class:
            max_cls_len = max(20, w - 6)
            cls_name = self.event.target_class
            if len(cls_name) > max_cls_len:
                cls_name = cls_name[:max_cls_len - 2] + "…"
            t.append(f"\n↳ {cls_name}", style="#38bdf8")

        return t


class OverviewTab(Static):
    """Displays detailed binary location, offsets, and disassembler jump commands with adaptive tables."""

    def __init__(self):
        super().__init__()
        self.event: Optional[InterceptedEvent] = None

    def update_event(self, event: Optional[InterceptedEvent]):
        self.event = event
        self.refresh()

    def render(self) -> Table | Panel | Group:
        if not self.event:
            return Panel(
                Text("\nNo handler selected.\nSelect an event from the timeline to inspect location & binary offsets.\n", style="#94a3b8", justify="center"),
                title="[bold #38bdf8]Location & Binary Metadata[/]",
                border_style="#1e293b",
                box=box.ROUNDED,
                padding=(1, 2),
            )

        w = _get_widget_width(self, 80)
        is_compact = w < 68

        loc = self.event.location or {}
        mod_name = loc.get("moduleName", "Unknown")
        mod_base = loc.get("moduleBase", "0x0")
        impl = loc.get("implementation", "0x0")
        offset = loc.get("offset", "0x0")

        # Convert offset to hex if decimal
        if offset and not str(offset).startswith("0x"):
            try:
                offset = f"0x{int(offset):X}"
            except ValueError:
                pass

        prop_w = 10 if is_compact else 16

        # Card 1: Target context
        t1 = Table(
            title="[bold #38bdf8]Target Handler & Context[/]",
            box=box.ROUNDED,
            border_style="#1e293b",
            expand=True,
            show_header=False,
            padding=(0, 1),
        )
        t1.add_column("Property", style="bold #38bdf8", width=prop_w, no_wrap=True)
        t1.add_column("Value", ratio=1)

        pin_status = "[bold #fbbf24] ★ Pinned[/]" if self.event.pinned else "[dim #64748b] (Press 'p' to pin)[/]"
        t1.add_row("Summary", f"[bold #f8fafc]{escape(self.event.summary)}[/]{pin_status}")
        badge_label, badge_style = CATEGORY_BADGES.get(
            self.event.category,
            (self.event.category.upper(), "bold #94a3b8 on #1e293b")
        )
        t1.add_row("Category", f"[{badge_style}] {badge_label} [/]")
        t1.add_row("Target" if is_compact else "Target Class", f"[bold #38bdf8]{escape(self.event.target_class or 'N/A')}[/]")
        t1.add_row("Selector", f"[bold #fbbf24]{escape(self.event.selector or 'N/A')}[/]")

        if is_swift_symbol(self.event.selector):
            t1.add_row("Demangled", f"[bold #a78bfa]{escape(demangle_swift(self.event.selector))}[/]")

        t1.add_row("Pointer", f"[#94a3b8]{escape(self.event.target_pointer or 'N/A')}[/]")
        t1.add_row("Action", f"[#94a3b8]{escape(self.event.action_type or 'N/A')}[/]")

        # Card 2: Binary offsets
        t2 = Table(
            title="[bold #34d399]Mach-O Binary Offsets[/]",
            box=box.ROUNDED,
            border_style="#1e293b",
            expand=True,
            show_header=False,
            padding=(0, 1),
        )
        t2.add_column("Property", style="bold #34d399", width=prop_w, no_wrap=True)
        t2.add_column("Value", ratio=1)
        t2.add_row("Mach-O Mod", f"[bold #38bdf8]{escape(mod_name)}[/]")
        t2.add_row("Base Addr" if is_compact else "Module Base", f"[#94a3b8]{escape(mod_base)}[/]")
        t2.add_row("Impl (PC)", f"[bold #f8fafc]{escape(impl)}[/]")
        if is_compact:
            t2.add_row("File Offset", f"[bold #34d399]{escape(str(offset))}[/]\n[dim #64748b]Slide: {escape(mod_base)}[/dim #64748b]")
        else:
            t2.add_row("File Offset", f"[bold #34d399]{escape(str(offset))}[/bold #34d399]  [dim #64748b](ASLR Slide: {escape(mod_base)})[/dim #64748b]")

        # Card 3: Disassembler jumps
        tool_w = 8 if is_compact else 12
        copy_hint = "c copy modal" if is_compact else "Press 'c' for Copy Modal"
        t3 = Table(
            title=f"[bold #fbbf24]Disassembler Jump Commands ({copy_hint})[/]",
            box=box.ROUNDED,
            border_style="#1e293b",
            expand=True,
            show_header=False,
            padding=(0, 1),
        )
        t3.add_column("Tool", style="bold #fbbf24", width=tool_w, no_wrap=True)
        t3.add_column("Command", ratio=1)

        ida_tool = "IDA" if is_compact else "IDA Pro"
        ghidra_tool = "Ghidra"
        hopper_tool = "Hopper" if is_compact else "Hopper / R2"
        lldb_tool = "LLDB"

        if is_compact:
            t3.add_row(ida_tool, f"[bold #fbbf24]ida_kernwin.jumpto(\n  get_imagebase() + {escape(str(offset))})[/]")
            t3.add_row(ghidra_tool, f"[bold #fbbf24]toAddr({escape(str(offset))})[/]")
            t3.add_row(hopper_tool, f"[bold #fbbf24]s {escape(str(offset))}[/]")
            t3.add_row(lldb_tool, f"[bold #fbbf24]image lookup -a\n  {escape(impl)}[/]")
        else:
            t3.add_row(ida_tool, f"[bold #fbbf24]ida_kernwin.jumpto(get_imagebase() + {escape(str(offset))})[/]")
            t3.add_row(ghidra_tool, f"[bold #fbbf24]toAddr({escape(str(offset))})[/]")
            t3.add_row(hopper_tool, f"[bold #fbbf24]s {escape(str(offset))}[/]")
            t3.add_row(lldb_tool, f"[bold #fbbf24]image lookup -a {escape(impl)}[/]")

        return Group(t1, t2, t3)


class BacktraceTab(Static):
    """Displays call stack frames with adaptive columns that never collapse or clip."""

    def __init__(self):
        super().__init__()
        self.event: Optional[InterceptedEvent] = None

    def update_event(self, event: Optional[InterceptedEvent]):
        self.event = event
        self.refresh()

    def render(self) -> Table | Panel:
        if not self.event or not self.event.backtrace:
            return Panel(
                Text("\nNo backtrace available for this event.\nSelect an intercepted handler to view call stack frames.\n", style="#94a3b8", justify="center"),
                title="[bold #38bdf8]Call Stack Backtrace[/]",
                border_style="#1e293b",
                box=box.ROUNDED,
                padding=(1, 2),
            )

        frames = self.event.backtrace.get("frames", [])
        if not frames:
            return Panel(
                Text("\nEmpty call stack.\n", style="#94a3b8", justify="center"),
                title="[bold #38bdf8]Call Stack Backtrace[/]",
                border_style="#1e293b",
                box=box.ROUNDED,
                padding=(1, 2),
            )

        app_frames = sum(1 for f in frames if f.get("isApp", False))
        sys_frames = len(frames) - app_frames

        w = _get_widget_width(self, 80)
        is_compact = w < 65

        if is_compact:
            # 3-column compact mode ensures Symbol and Module are 100% visible in narrow terminals
            table = Table(
                title=f"[bold #f8fafc]Call Stack[/] [dim]({app_frames} app, {len(frames)} total)[/]",
                expand=True,
                border_style="#1e293b",
                box=box.ROUNDED,
                header_style="bold #94a3b8",
                padding=(0, 1),
            )
            table.add_column("#", width=3, justify="right", style="#64748b", no_wrap=True)
            table.add_column("Type", width=5, justify="center", no_wrap=True)
            table.add_column("Symbol & Location", ratio=1)

            for frame in frames:
                idx = str(frame.get("index", 0))
                is_app = frame.get("isApp", False)
                type_str = "[bold #34d399]APP[/]" if is_app else "[dim #64748b]SYS[/]"
                mod = frame.get("moduleName", "Unknown")
                sym = frame.get("symbol") or frame.get("address") or "unknown"
                if is_swift_symbol(sym):
                    sym = demangle_swift(sym)

                off = frame.get("offset", "0x0")
                if off and not str(off).startswith("0x"):
                    try:
                        off = f"0x{int(off):X}"
                    except ValueError:
                        pass

                line_no = frame.get("line", "")
                file_name = frame.get("file", "")
                if is_app:
                    loc_info = f"[#38bdf8]{escape(mod)}[/] [dim]•[/] [#34d399]{escape(str(off))}[/]"
                    if file_name:
                        loc_info += f" [dim]• {escape(str(file_name))}:{line_no}[/]"
                    cell_text = f"[bold #f8fafc]{escape(sym)}[/]\n{loc_info}"
                else:
                    cell_text = f"[dim #94a3b8]{escape(sym)}[/]\n[dim #64748b]{escape(mod)} • {escape(str(off))}[/]"

                table.add_row(idx, type_str, cell_text)
            return table

        # Wide mode: 5 columns
        title_str = (
            f"[bold #f8fafc]Call Stack Backtrace[/]  [dim]•[/]  "
            f"[bold #34d399]{app_frames} App Frames[/]  [dim]•[/]  "
            f"[dim #94a3b8]{sys_frames} System Frames[/]  [dim]•[/]  "
            f"[dim #64748b]Total: {len(frames)}[/]"
        )

        table = Table(
            title=title_str,
            expand=True,
            border_style="#1e293b",
            box=box.ROUNDED,
            header_style="bold #94a3b8",
            padding=(0, 1),
        )
        table.add_column("#", width=3, justify="right", style="#64748b", no_wrap=True)
        table.add_column("Type", width=6, justify="center", no_wrap=True)
        table.add_column("Module", max_width=16, no_wrap=True, overflow="ellipsis")
        table.add_column("Symbol / Function", ratio=1)
        table.add_column("Offset", width=11, justify="right", no_wrap=True)

        for frame in frames:
            idx = str(frame.get("index", 0))
            is_app = frame.get("isApp", False)
            type_str = "[bold #34d399 on #064e3b] APP [/]" if is_app else "[dim #64748b] SYS [/]"
            mod = frame.get("moduleName", "Unknown")
            mod_str = f"[bold #38bdf8]{escape(mod)}[/]" if is_app else f"[dim #94a3b8]{escape(mod)}[/]"

            sym = frame.get("symbol") or frame.get("address") or "unknown"
            if is_swift_symbol(sym):
                sym = demangle_swift(sym)

            off = frame.get("offset", "0x0")
            if off and not str(off).startswith("0x"):
                try:
                    off = f"0x{int(off):X}"
                except ValueError:
                    pass

            if is_app:
                sym_styled = f"[bold #f8fafc]{escape(sym)}[/]"
                if frame.get("file"):
                    sym_styled += f"\n  [dim #34d399]↳ {escape(str(frame.get('file')))}:{frame.get('line', '')}[/dim #34d399]"
                off_styled = f"[bold #38bdf8]{escape(str(off))}[/]"
            else:
                sym_styled = f"[dim #94a3b8]{escape(sym)}[/]"
                off_styled = f"[dim #64748b]{escape(str(off))}[/]"

            table.add_row(idx, type_str, mod_str, sym_styled, off_styled)

        return table


class ArgumentsTab(Static):
    """Displays sender context, parameters, view hierarchy, and JSON bodies with responsive widths."""

    def __init__(self):
        super().__init__()
        self.event: Optional[InterceptedEvent] = None

    def update_event(self, event: Optional[InterceptedEvent]):
        self.event = event
        self.refresh()

    def render(self) -> Table | Panel:
        if not self.event:
            return Panel(
                Text("\nNo handler selected.\nSelect an event from the timeline to inspect arguments & state.\n", style="#94a3b8", justify="center"),
                title="[bold #38bdf8]Arguments & Sender State[/]",
                border_style="#1e293b",
                box=box.ROUNDED,
                padding=(1, 2),
            )

        w = _get_widget_width(self, 80)
        is_compact = w < 65
        field_w = 11 if is_compact else 16

        table = Table(
            title="[bold #f8fafc]Arguments & Sender State[/]",
            expand=True,
            show_header=False,
            border_style="#1e293b",
            box=box.ROUNDED,
            padding=(0, 1),
        )
        table.add_column("Field", style="bold #38bdf8", width=field_w, no_wrap=True)
        table.add_column("Details", ratio=1)

        table.add_row("Action Type", f"[bold #f8fafc]{escape(self.event.action_type)}[/]")
        table.add_row("Pointer", f"[#94a3b8]{escape(self.event.target_pointer)}[/]")

        sender = self.event.sender or {}
        if sender:
            table.add_row("Sender Class", f"[bold #38bdf8]{escape(sender.get('className', 'Unknown'))}[/]")
            if sender.get("title"):
                table.add_row("Sender Title", f'[bold #fbbf24]"{escape(sender.get("title"))}"[/]')
            if sender.get("tag"):
                table.add_row("Sender Tag", f"[#94a3b8]{escape(str(sender.get('tag')))}[/]")
            if sender.get("accessibilityId"):
                table.add_row("Accessibility", f"[#34d399]{escape(sender.get('accessibilityId'))}[/]")
            if sender.get("hierarchy"):
                hierarchy_items = sender.get("hierarchy", [])
                lines = []
                for i, item in enumerate(hierarchy_items):
                    indent = "  " * min(i, 3)
                    branch = "↳ " if i > 0 else "◆ "
                    lines.append(f"{indent}{branch}{escape(item)}")
                table.add_row("Hierarchy", "\n".join(lines))

        # Deep link URL
        if self.event.raw.get("url"):
            table.add_row("URL", f"[bold #38bdf8]{escape(self.event.raw.get('url'))}[/]")
        if self.event.raw.get("options"):
            table.add_row("Options", f"[#94a3b8]{escape(str(self.event.raw.get('options')))}[/]")

        # WebKit Script Message
        if self.event.raw.get("handlerName"):
            table.add_row("Handler Name", f"[bold #f87171]{escape(self.event.raw.get('handlerName'))}[/]")
        if self.event.raw.get("body"):
            table.add_row("Message Body", f"[#94a3b8]{escape(str(self.event.raw.get('body')))}[/]")

        # Security Payload Details (Keychain, Crypto, Biometrics)
        sec = self.event.raw.get("securityDetails")
        if sec:
            table.add_row("Sec Operation", f"[bold #f87171]{escape(sec.get('op', ''))}[/]")
            if sec.get("query"):
                table.add_row("Sec Query", f"[#38bdf8]{escape(str(sec.get('query')))}[/]")

        return table


class DisassemblyTab(Static):
    """Displays disassembly instructions with full ARM64 syntax highlighting."""

    def __init__(self):
        super().__init__()
        self.event: Optional[InterceptedEvent] = None

    def update_event(self, event: Optional[InterceptedEvent]):
        self.event = event
        self.refresh()

    def render(self) -> Table | Panel:
        if not self.event:
            return Panel(
                Text("\nNo handler selected.\nSelect an event from the timeline to view disassembly.\n", style="#94a3b8", justify="center"),
                title="[bold #38bdf8]Disassembly Context[/]",
                border_style="#1e293b",
                box=box.ROUNDED,
                padding=(1, 2),
            )

        loc = self.event.location or {}
        instructions = loc.get("disassembly", [])
        if not instructions:
            return Panel(
                Text("\nNo disassembly instructions available for this location.\n", style="#94a3b8", justify="center"),
                title="[bold #38bdf8]Disassembly Context[/]",
                border_style="#1e293b",
                box=box.ROUNDED,
                padding=(1, 2),
            )

        impl = loc.get("implementation", "PC")
        w = _get_widget_width(self, 80)
        is_compact = w < 65

        title_str = f"[bold #f8fafc]Disasm around {escape(impl)}[/]" if is_compact else f"[bold #f8fafc]Disassembly Context around {escape(impl)}[/]"
        table = Table(
            title=title_str,
            expand=True,
            border_style="#1e293b",
            box=box.ROUNDED,
            header_style="bold #94a3b8",
            padding=(0, 1),
        )

        if is_compact:
            table.add_column("", width=1, justify="center")
            table.add_column("Addr", width=8, style="#64748b", no_wrap=True)
            table.add_column("Mnem", width=6, no_wrap=True)
            table.add_column("Operands", ratio=1)
        else:
            table.add_column("", width=2, justify="center")
            table.add_column("Address", width=14, style="#64748b", no_wrap=True)
            table.add_column("Mnemonic", width=8, no_wrap=True)
            table.add_column("Operands", ratio=1)

        for ins in instructions:
            addr = ins.get("address", "")
            mnem = ins.get("mnemonic", "")
            op = ins.get("opStr", "")
            is_pc = addr.lower() == str(impl).lower()
            ptr = "[bold #38bdf8]▶[/]" if is_pc else ""

            if is_compact and len(addr) > 8:
                addr_display = f"..{addr[-6:]}"
            else:
                addr_display = addr

            if mnem in ("b", "bl", "br", "cbz", "cbnz", "tbz", "tbnz"):
                mnem_style = "bold #38bdf8"
            elif mnem in ("ret",):
                mnem_style = "bold #f43f5e"
            elif mnem in ("stp", "ldp", "ldr", "str", "adrp"):
                mnem_style = "bold #a78bfa"
            elif mnem in ("mov", "sub", "add", "cmp", "orr", "and", "eor"):
                mnem_style = "bold #34d399"
            else:
                mnem_style = "bold #fbbf24"

            # Use advanced operand token syntax highlighting
            highlighted_ops = format_arm64_operands(op)

            table.add_row(ptr, escape(addr_display), f"[{mnem_style}]{escape(mnem)}[/]", highlighted_ops)

        return table


class MemoryHexTab(Static):
    """Raw memory hexdump inspection tab for target pointers and buffers."""

    def __init__(self):
        super().__init__()
        self.event: Optional[InterceptedEvent] = None
        self.hex_data: Optional[bytes] = None

    def update_event(self, event: Optional[InterceptedEvent], raw_bytes: Optional[bytes] = None):
        self.event = event
        self.hex_data = raw_bytes
        self.refresh()

    def render(self) -> Table | Panel:
        if not self.event:
            return Panel(
                Text("\nNo pointer selected.\nSelect an event from the timeline to inspect memory dump.\n", style="#94a3b8", justify="center"),
                title="[bold #38bdf8]Raw Memory Hexdump[/]",
                border_style="#1e293b",
                box=box.ROUNDED,
                padding=(1, 2),
            )

        ptr_str = self.event.target_pointer or "0x0"
        try:
            base_addr = int(ptr_str, 16)
        except ValueError:
            base_addr = 0x100000000

        # Generate sample hexdump buffer if no live RPC data attached
        data = self.hex_data or b"\x55\x48\x89\xe5\x48\x83\xec\x20\x48\x8d\x3d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x31\xc0\x48\x83\xc4\x20\x5d\xc3\x90\x90\x90\x90"

        table = Table(
            title=f"[bold #f8fafc]Memory Dump at {ptr_str}[/] [dim]({len(data)} bytes)[/]",
            expand=True,
            border_style="#1e293b",
            box=box.ROUNDED,
            header_style="bold #94a3b8",
            padding=(0, 1),
        )
        table.add_column("Address", width=12, style="#64748b", no_wrap=True)
        table.add_column("Hex Bytes", style="bold #38bdf8", ratio=2)
        table.add_column("ASCII", style="#34d399", width=16, no_wrap=True)

        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            curr_addr = f"0x{(base_addr + i) & 0xFFFFFFFF:08X}"
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            table.add_row(curr_addr, hex_part, ascii_part)

        return table


class StatusBar(Static):
    """Bottom hotkey and status notification bar with responsive shortcuts."""

    def __init__(self):
        super().__init__(id="status-bar")
        self.message = ""

    def show_message(self, msg: str):
        self.message = msg
        self.refresh()

    def render(self) -> Text:
        w = _get_widget_width(self, 80)
        t = Text()

        if self.message:
            t.append(" ● ", style="bold #34d399")
            t.append(f"{self.message} ", style="bold #f8fafc")
            if w < 75:
                # If narrow and message shown, keep shortcuts minimal
                t.append("│ ", style="#334155")
                t.append(" q ", style="bold #f87171 on #1e293b")
                t.append("Quit", style="#94a3b8")
                return t
            t.append("│ ", style="#334155")

        if w < 75:
            # Ultra compact keys (vital 6 keys)
            shortcuts = [
                ("F1", "Help", "#38bdf8"),
                ("/", "Find", "#38bdf8"),
                ("c", "Copy", "#38bdf8"),
                ("p", "Pin", "#fbbf24"),
                ("r", "Run", "#38bdf8"),
                ("q", "Quit", "#f87171"),
            ]
        elif w < 96:
            # Medium compact keys
            shortcuts = [
                ("F1", "Help", "#38bdf8"),
                ("F2", "Pause", "#38bdf8"),
                ("/", "Filter", "#38bdf8"),
                ("c", "Copy", "#38bdf8"),
                ("p", "Pin", "#fbbf24"),
                ("r", "Replay", "#38bdf8"),
                ("F5", "Export", "#38bdf8"),
                ("q", "Quit", "#f87171"),
            ]
        else:
            # Full expansive keys
            shortcuts = [
                ("F1", "Help", "#38bdf8"),
                ("F2", "Pause", "#38bdf8"),
                ("F3", "Clear", "#38bdf8"),
                ("/", "Filter", "#38bdf8"),
                ("c", "Quick-Copy", "#38bdf8"),
                ("p", "Pin", "#fbbf24"),
                ("r", "Replay", "#38bdf8"),
                ("g", "Hook", "#38bdf8"),
                ("F5", "Export", "#38bdf8"),
                ("q", "Quit", "#f87171"),
            ]

        for i, (key, label, key_col) in enumerate(shortcuts):
            t.append(f" {key} ", style=f"bold {key_col} on #1e293b")
            t.append(f" {label} ", style="#94a3b8")
            if i < len(shortcuts) - 1:
                t.append("·", style="#334155")

        return t
