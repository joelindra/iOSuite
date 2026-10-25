"""
Modal Screens and Dialogs for iOSuite Trace
Includes HelpModal, MessageModal, CopyJumpModal, and TamperReplayModal.
"""

from typing import Optional, Dict, Any
from textual.screen import ModalScreen
from textual.app import ComposeResult
from textual.widgets import Static, Button, Input, Label
from textual.containers import Vertical, Horizontal
from rich.text import Text
from rich.table import Table
from rich import box
import pyperclip


class HelpModal(ModalScreen):
    """Modal displaying keybindings and usage help."""

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog-box"):
            table = Table(
                title="[bold #38bdf8]◆ iOSuite-Trace Keyboard Shortcuts[/]",
                box=box.ROUNDED,
                border_style="#334155",
                expand=True,
                header_style="bold #94a3b8",
            )
            table.add_column("Key", style="bold #38bdf8", width=10, no_wrap=True)
            table.add_column("Action", style="#f8fafc", ratio=1)

            table.add_row("↑ / ↓, j/k", "Navigate through intercepted handlers")
            table.add_row("1..6", "Switch detail tabs (Location, Stack, Args, Disasm, Logs, Mem)")
            table.add_row("/", "Focus live search / filter query (supports /regex/)")
            table.add_row("Esc", "Clear search query / unfocus / close modal")
            table.add_row("c", "Quick-Copy Modal (IDA, Ghidra, Offset, JSON to clipboard)")
            table.add_row("p", "Toggle Star / Pin on selected event")
            table.add_row("Alt+P", "Toggle filter: Show only Pinned (starred) events")
            table.add_row("r", "Replay handler with original parameters")
            table.add_row("Shift+R", "Mutate arguments & Replay (Tamper Replay)")
            table.add_row("F2", "Pause / resume real-time interception")
            table.add_row("F3", "Clear event history")
            table.add_row("g", "Generate standalone Frida hook script")
            table.add_row("F5", "Export session to Markdown & JSON")
            table.add_row("q", "Quit session and detach cleanly")

            yield Static(table)
            yield Button("Close (Esc)", variant="primary", id="btn-close-help")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()

    def key_escape(self) -> None:
        self.dismiss()


class MessageModal(ModalScreen):
    """Modal displaying a message or export confirmation."""

    def __init__(self, title: str, message: str):
        super().__init__()
        self.title_str = title
        self.message_str = message

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog-box"):
            yield Static(f"[bold #38bdf8]◆ {self.title_str}[/bold #38bdf8]\n\n[#e2e8f0]{self.message_str}[/]\n")
            yield Button("OK (Enter / Esc)", variant="success", id="btn-ok")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()

    def key_escape(self) -> None:
        self.dismiss()

    def key_enter(self) -> None:
        self.dismiss()


class CopyJumpModal(ModalScreen):
    """Quick-copy dialog allowing analyst to copy disassembler jump strings directly to OS clipboard."""

    def __init__(self, location: Dict[str, Any], event_summary: str, selector: str):
        super().__init__()
        self.location = location
        self.event_summary = event_summary
        self.selector = selector

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog-box"):
            yield Static(f"[bold #38bdf8]◆ Quick-Copy to OS Clipboard[/bold #38bdf8]\n[#94a3b8]{self.event_summary}[/]\n")

            offset = self.location.get("offset", "0x0")
            if offset and not str(offset).startswith("0x"):
                try:
                    offset = f"0x{int(offset):X}"
                except ValueError:
                    pass
            impl = self.location.get("implementation", "0x0")

            yield Button(f"1 · IDA Pro Jumpto: ida_kernwin.jumpto(get_imagebase()+{offset})", variant="default", id="copy-ida")
            yield Button(f"2 · Ghidra toAddr: toAddr({offset})", variant="default", id="copy-ghidra")
            yield Button(f"3 · Raw Mach-O Offset: {offset}", variant="default", id="copy-offset")
            yield Button(f"4 · Target Selector: {self.selector}", variant="default", id="copy-sel")
            yield Button(f"5 · LLDB Lookup: image lookup -a {impl}", variant="default", id="copy-lldb")
            yield Button("Cancel (Esc)", variant="error", id="copy-cancel")

    def _copy(self, text: str, desc: str) -> None:
        try:
            pyperclip.copy(text)
        except Exception:
            pass
        self.dismiss((text, desc))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        offset = self.location.get("offset", "0x0")
        if offset and not str(offset).startswith("0x"):
            try:
                offset = f"0x{int(offset):X}"
            except ValueError:
                pass
        impl = self.location.get("implementation", "0x0")

        btn_id = event.button.id
        if btn_id == "copy-ida":
            self._copy(f"ida_kernwin.jumpto(get_imagebase() + {offset})", "IDA Pro Jumpto command")
        elif btn_id == "copy-ghidra":
            self._copy(f"toAddr({offset})", "Ghidra address")
        elif btn_id == "copy-offset":
            self._copy(str(offset), "Mach-O offset")
        elif btn_id == "copy-sel":
            self._copy(str(self.selector), "Selector name")
        elif btn_id == "copy-lldb":
            self._copy(f"image lookup -a {impl}", "LLDB lookup command")
        else:
            self.dismiss(None)

    def key_1(self) -> None:
        self.query_one("#copy-ida", Button).press()

    def key_2(self) -> None:
        self.query_one("#copy-ghidra", Button).press()

    def key_3(self) -> None:
        self.query_one("#copy-offset", Button).press()

    def key_4(self) -> None:
        self.query_one("#copy-sel", Button).press()

    def key_5(self) -> None:
        self.query_one("#copy-lldb", Button).press()

    def key_escape(self) -> None:
        self.dismiss(None)


class TamperReplayModal(ModalScreen):
    """Interactive argument mutation dialog before handler replay."""

    def __init__(self, target_class: str, selector: str, default_arg: str = ""):
        super().__init__()
        self.target_class = target_class
        self.selector = selector
        self.default_arg = default_arg

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog-box"):
            yield Static(f"[bold #fbbf24]◆ Parameter Tampering & Replay[/bold #fbbf24]\n[#94a3b8]{self.target_class} -> {self.selector}[/]\n")
            yield Label("Mutated Argument Value (String, Integer, or JSON):", classes="field-label")
            yield Input(value=str(self.default_arg), id="tamper-input", placeholder="Enter modified parameter value...")
            with Horizontal(classes="modal-buttons"):
                yield Button("Invoke Replay", variant="primary", id="btn-invoke-tamper")
                yield Button("Cancel (Esc)", variant="default", id="btn-cancel-tamper")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-invoke-tamper":
            val = self.query_one("#tamper-input", Input).value
            self.dismiss(val)
        else:
            self.dismiss(None)

    def key_enter(self) -> None:
        self.query_one("#btn-invoke-tamper", Button).press()

    def key_escape(self) -> None:
        self.dismiss(None)
