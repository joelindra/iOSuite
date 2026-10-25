"""
iOSuite Trace Textual Application
Main Terminal User Interface orchestration, layout, and event handling.
Enhanced with Category Filter Bar, Dedicated Frida Logs, Hex Viewer, Disassembler Sync Bridge,
Interactive Argument Tampering Replay, and True OS Clipboard Integration.
"""

import asyncio
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal
from textual.widgets import Input, ListView, TabbedContent, TabPane, RichLog
from textual.message import Message

from iosuite.core.dispatcher import EventDispatcher, InterceptedEvent
from iosuite.core.session import FridaDeviceSession
from iosuite.core.mock import MockSessionGenerator
from iosuite.core.exporter import export_to_markdown, export_to_json, generate_frida_hook_script
from iosuite.core.bridge import DisassemblerBridge
from iosuite.ui.widgets import (
    HeaderBar,
    CategoryFilterBar,
    EventListItem,
    OverviewTab,
    BacktraceTab,
    ArgumentsTab,
    DisassemblyTab,
    MemoryHexTab,
    StatusBar,
)
from iosuite.ui.dialogs import HelpModal, MessageModal, CopyJumpModal, TamperReplayModal


class FridaEventMessage(Message):
    """Event posted when Frida agent intercepts a UI/handler event."""
    def __init__(self, payload: Dict[str, Any]) -> None:
        super().__init__()
        self.payload = payload


class FridaLogMessage(Message):
    """Event posted when Frida agent sends a log message."""
    def __init__(self, level: str, message: str) -> None:
        super().__init__()
        self.level = level
        self.message = message


class FridaConnectedMessage(Message):
    """Event posted when Frida session successfully attaches to target."""
    def __init__(self, target_name: str, device_name: str, pid: int) -> None:
        super().__init__()
        self.target_name = target_name
        self.device_name = device_name
        self.pid = pid


class FridaErrorMessage(Message):
    """Event posted when Frida connection encounters an error."""
    def __init__(self, error_msg: str) -> None:
        super().__init__()
        self.error_msg = error_msg


TCSS_PATH = Path(__file__).parent / "ui" / "styles.tcss"


class iOSuiteTraceApp(App):
    """Main Textual Application for iOS feature and handler interception."""

    CSS_PATH = TCSS_PATH

    BINDINGS = [
        Binding("q", "quit_app", "Quit", show=False),
        Binding("f1", "show_help", "Help", show=False),
        Binding("f2", "toggle_pause", "Pause/Resume", show=False),
        Binding("f3", "clear_events", "Clear", show=False),
        Binding("slash", "focus_filter", "Filter", show=False),
        Binding("escape", "clear_filter", "Clear Filter", show=False),
        Binding("1", "tab_1", "Overview", show=False),
        Binding("2", "tab_2", "Backtrace", show=False),
        Binding("3", "tab_3", "Arguments", show=False),
        Binding("4", "tab_4", "Disassembly", show=False),
        Binding("5", "tab_5", "Logs", show=False),
        Binding("6", "tab_6", "Memory", show=False),
        Binding("p", "toggle_pin", "Pin Event", show=False),
        Binding("alt+p", "toggle_pin_filter", "Filter Pinned", show=False),
        Binding("r", "replay_handler", "Replay", show=False),
        Binding("R", "tamper_replay", "Tamper Replay", show=False),
        Binding("g", "gen_script", "Generate Script", show=False),
        Binding("c", "copy_jump", "Quick-Copy Modal", show=False),
        Binding("f5", "export_session", "Export", show=False),
        Binding("j", "nav_down", "Next Event", show=False),
        Binding("k", "nav_up", "Prev Event", show=False),
    ]

    def __init__(
        self,
        target: str = "DemoApp",
        device_id: Optional[str] = None,
        use_usb: bool = True,
        spawn: bool = False,
        mock_mode: bool = False,
        enable_bridge: bool = True,
    ):
        super().__init__()
        self.target_name = str(target)
        self.device_id = device_id
        self.use_usb = use_usb
        self.spawn = spawn
        self.mock_mode = mock_mode
        self.enable_bridge = enable_bridge

        self.dispatcher = EventDispatcher()
        self.session: Optional[FridaDeviceSession] = None
        self.mock_gen: Optional[MockSessionGenerator] = None
        self.selected_event: Optional[InterceptedEvent] = None
        self.bridge: Optional[DisassemblerBridge] = None

        # Widgets
        self.header_bar = HeaderBar(target=self.target_name, device="USB" if use_usb else "Local")
        self.search_input = Input(placeholder="⌕  Filter (/regex/, keywords, VC, pay)...", id="search-input")
        self.filter_bar = CategoryFilterBar()
        self.event_list = ListView(id="event-list")
        self.overview_tab = OverviewTab()
        self.backtrace_tab = BacktraceTab()
        self.arguments_tab = ArgumentsTab()
        self.disasm_tab = DisassemblyTab()
        self.log_stream = RichLog(id="log-stream", highlight=True, markup=True)
        self.memory_tab = MemoryHexTab()
        self.status_bar = StatusBar()

    def compose(self) -> ComposeResult:
        yield self.header_bar
        with Horizontal(id="main-container"):
            with Vertical(id="sidepane"):
                with Horizontal(id="search-box"):
                    yield self.search_input
                yield self.filter_bar
                yield self.event_list
            with TabbedContent(id="detail-pane", initial="tab-overview"):
                with TabPane("1 · Location", id="tab-overview"):
                    yield self.overview_tab
                with TabPane("2 · Call Stack", id="tab-backtrace"):
                    yield self.backtrace_tab
                with TabPane("3 · Arguments", id="tab-arguments"):
                    yield self.arguments_tab
                with TabPane("4 · Disassembly", id="tab-disasm"):
                    yield self.disasm_tab
                with TabPane("5 · Logs", id="tab-logs"):
                    yield self.log_stream
                with TabPane("6 · Memory", id="tab-memory"):
                    yield self.memory_tab
        yield self.status_bar

    def update_detail_views(self, event: Optional[InterceptedEvent]):
        self.overview_tab.update_event(event)
        self.backtrace_tab.update_event(event)
        self.arguments_tab.update_event(event)
        self.disasm_tab.update_event(event)
        self.memory_tab.update_event(event)

        # Broadcast jump offset to external IDA/Ghidra bridge
        if event and event.location and self.bridge:
            loc = event.location
            mod = loc.get("moduleName", "App")
            off = loc.get("offset", "0x0")
            impl = loc.get("implementation", "0x0")
            self.bridge.broadcast_jump(mod, off, event.selector, impl)

    def on_resize(self, event) -> None:
        """Trigger immediate re-render on terminal resize for responsive small/large window layout."""
        self.header_bar.refresh()
        self.filter_bar.refresh()
        self.status_bar.refresh()
        self.overview_tab.refresh()
        self.backtrace_tab.refresh()
        self.arguments_tab.refresh()
        self.disasm_tab.refresh()
        self.memory_tab.refresh()

    async def on_mount(self) -> None:
        """Initialize session and disassembler sync bridge after UI mounts."""
        self.dispatcher.add_listener(self._on_dispatcher_event)

        # Start live disassembler bridge (IDA / Ghidra sync)
        if self.enable_bridge:
            try:
                self.bridge = DisassemblerBridge()
                self.bridge.start()
            except Exception:
                self.bridge = None

        if self.mock_mode:
            self.header_bar.update_info(target=f"{self.target_name} (Mock)", device="Simulator/Mock", pid=4120)
            self.status_bar.show_message("Running in Mock Demonstration Mode")
            self.log_stream.write("[bold #34d399]● iOSuite Trace Engine initialized in Mock Mode[/]")
            self.log_stream.write("[#94a3b8]IDA/Ghidra Sync Bridge active on [bold #38bdf8]http://127.0.0.1:1337[/][/]")
            self.mock_gen = MockSessionGenerator(on_event=self._on_raw_event)
            await self.mock_gen.start()
        else:
            self.header_bar.update_info(target=self.target_name, device="Connecting...", pid=None)
            self.status_bar.show_message(f"Connecting to {self.target_name} over USB...")
            self.log_stream.write(f"[bold #38bdf8]● Initiating Frida connection to {self.target_name}...[/]")
            threading.Thread(target=self._connect_session_thread, daemon=True).start()

    def _connect_session_thread(self) -> None:
        """Background worker thread to attach/spawn without blocking the UI event loop."""
        try:
            self.session = FridaDeviceSession(
                target=self.target_name,
                device_id=self.device_id,
                use_usb=self.use_usb,
                spawn=self.spawn,
            )
            self.session.set_callbacks(
                on_event=self._on_raw_event,
                on_log=self._on_raw_log,
            )
            self.session.connect()
            dev_name = self.session.device.name if self.session.device else "Connected"
            target_name = self.session.app_info.get("executableName", self.target_name)
            self.post_message(FridaConnectedMessage(target_name, dev_name, self.session.pid or 0))
        except Exception as e:
            self.post_message(FridaErrorMessage(str(e)))

    def on_frida_connected_message(self, message: FridaConnectedMessage) -> None:
        """Handle successful Frida connection on UI thread."""
        self.header_bar.update_info(
            target=message.target_name,
            device=message.device_name,
            pid=message.pid,
        )
        self.status_bar.show_message(f"Attached to PID {message.pid} ({message.target_name})")
        self.log_stream.write(f"[bold #34d399]✓ Attached to target: {message.target_name} (PID: {message.pid}) on {message.device_name}[/]")

    def on_frida_error_message(self, message: FridaErrorMessage) -> None:
        """Handle Frida connection failure on UI thread."""
        self.status_bar.show_message(f"Frida Error: {message.error_msg}")
        self.header_bar.update_info(target=f"{self.target_name} (Failed)", device="Offline")
        self.log_stream.write(f"[bold #f87171]✗ Frida Error: {message.error_msg}[/]")

    def on_frida_event_message(self, message: FridaEventMessage) -> None:
        """Process incoming Frida intercepted event on UI thread."""
        self.dispatcher.process_raw_event(message.payload)

    def on_frida_log_message(self, message: FridaLogMessage) -> None:
        """Process incoming Frida log message on UI thread and route to dedicated RichLog & StatusBar."""
        lvl = message.level.lower()
        if lvl == "error":
            col = "#f87171"
            tag = "ERR"
        elif lvl == "warn":
            col = "#fbbf24"
            tag = "WARN"
        elif lvl == "debug":
            col = "#94a3b8"
            tag = "DBG"
        else:
            col = "#38bdf8"
            tag = "INFO"

        self.status_bar.show_message(f"[{message.level.upper()}] {message.message}")
        self.log_stream.write(f"[{col}][{tag}][/{col}] {message.message}")

    def _on_raw_event(self, raw_payload: dict) -> None:
        """Thread-safe non-blocking callback from Frida or Mock thread."""
        self.post_message(FridaEventMessage(raw_payload))

    def _on_raw_log(self, level: str, message: str) -> None:
        """Thread-safe non-blocking callback from Frida log."""
        self.post_message(FridaLogMessage(level, message))

    def _on_dispatcher_event(self, event: InterceptedEvent) -> None:
        """Handle new or updated event on the UI thread."""
        self.header_bar.update_info(event_count=len(self.dispatcher.events))

        # Check if list already has items; if so, update or append
        existing_index = None
        for idx, child in enumerate(self.event_list.children):
            if isinstance(child, EventListItem) and child.event.id == event.id:
                existing_index = idx
                break

        if existing_index is not None:
            self.event_list.children[existing_index].refresh()
        else:
            # Check if passes current filter
            filtered = self.dispatcher.get_filtered_events()
            if event in filtered:
                new_item = EventListItem(event)
                self.event_list.append(new_item)

                # Auto-select first item if none selected
                if self.selected_event is None and len(self.event_list.children) == 1:
                    self.selected_event = event
                    self.update_detail_views(event)

    def on_list_view_highlighted(self, message: ListView.Highlighted) -> None:
        """Fires when user moves up/down in the sidepane list."""
        if message.item and isinstance(message.item, EventListItem):
            self.selected_event = message.item.event
            self.update_detail_views(self.selected_event)

    def on_list_view_selected(self, message: ListView.Selected) -> None:
        """Fires when user presses Enter on an item in the sidepane list."""
        if message.item and isinstance(message.item, EventListItem):
            self.selected_event = message.item.event
            self.update_detail_views(self.selected_event)

    def on_input_changed(self, message: Input.Changed) -> None:
        """Handle live search / filter query input with regex/fuzzy support."""
        self.dispatcher.set_search_query(message.value)
        self._refresh_list_view()

    def _refresh_list_view(self) -> None:
        """Rebuild the sidepane list based on filtered events."""
        self.event_list.clear()
        filtered = self.dispatcher.get_filtered_events()
        for ev in filtered:
            self.event_list.append(EventListItem(ev))
        if filtered and (not self.selected_event or self.selected_event not in filtered):
            self.selected_event = filtered[0]
            self.update_detail_views(self.selected_event)
        self.filter_bar.update_state(self.dispatcher.category_filters, self.dispatcher.pinned_only)

    # ---------------- Key Actions ----------------

    def action_focus_filter(self) -> None:
        self.search_input.focus()

    def action_clear_filter(self) -> None:
        self.search_input.value = ""
        self.dispatcher.set_search_query("")
        self.dispatcher.clear_category_filters()
        self.dispatcher.set_pinned_only(False)
        self._refresh_list_view()
        self.event_list.focus()

    def action_toggle_pause(self) -> None:
        new_state = not self.dispatcher.is_paused
        self.dispatcher.set_paused(new_state)
        self.header_bar.set_recording(not new_state)
        status_txt = "Interception Paused" if new_state else "Interception Resumed"
        self.status_bar.show_message(status_txt)
        self.log_stream.write(f"[bold #fbbf24]❚❚ {status_txt}[/]")

    def action_clear_events(self) -> None:
        self.dispatcher.clear()
        self.event_list.clear()
        self.selected_event = None
        self.update_detail_views(None)
        self.header_bar.update_info(event_count=0)
        self.status_bar.show_message("Event list cleared")
        self.log_stream.write("[dim]Cleared event queue.[/dim]")

    def action_toggle_pin(self) -> None:
        """Toggle star/pin on the currently selected event."""
        if not self.selected_event:
            return
        self.selected_event.pinned = not self.selected_event.pinned
        self._refresh_list_view()
        pin_txt = "Pinned ★" if self.selected_event.pinned else "Unpinned"
        self.status_bar.show_message(f"Event {pin_txt}: {self.selected_event.summary}")

    def action_toggle_pin_filter(self) -> None:
        """Toggle showing only pinned/starred events."""
        new_pinned = not self.dispatcher.pinned_only
        self.dispatcher.set_pinned_only(new_pinned)
        self._refresh_list_view()
        status_txt = "Filtering Pinned Events Only ★" if new_pinned else "Showing All Events"
        self.status_bar.show_message(status_txt)

    def action_nav_down(self) -> None:
        """Ergonomic Vim 'j' navigation down event list."""
        if len(self.event_list.children) > 0:
            cur = self.event_list.index or 0
            if cur < len(self.event_list.children) - 1:
                self.event_list.index = cur + 1

    def action_nav_up(self) -> None:
        """Ergonomic Vim 'k' navigation up event list."""
        if len(self.event_list.children) > 0:
            cur = self.event_list.index or 0
            if cur > 0:
                self.event_list.index = cur - 1

    def action_tab_1(self) -> None:
        self.query_one("#detail-pane", TabbedContent).active = "tab-overview"

    def action_tab_2(self) -> None:
        self.query_one("#detail-pane", TabbedContent).active = "tab-backtrace"

    def action_tab_3(self) -> None:
        self.query_one("#detail-pane", TabbedContent).active = "tab-arguments"

    def action_tab_4(self) -> None:
        self.query_one("#detail-pane", TabbedContent).active = "tab-disasm"

    def action_tab_5(self) -> None:
        self.query_one("#detail-pane", TabbedContent).active = "tab-logs"

    def action_tab_6(self) -> None:
        self.query_one("#detail-pane", TabbedContent).active = "tab-memory"

    def action_show_help(self) -> None:
        self.push_screen(HelpModal())

    def action_replay_handler(self) -> None:
        if not self.selected_event:
            self.status_bar.show_message("No handler selected to replay")
            return

        ev = self.selected_event
        if self.mock_mode or not self.session:
            self.status_bar.show_message(f"[Mock Replay] Simulated invoke on {ev.target_class} -> {ev.selector}")
            self.push_screen(MessageModal("Replay Handler (Simulated)", f"Successfully replayed handler:\n\nTarget: {ev.target_class}\nSelector: {ev.selector}"))
            return

        # Physical Frida RPC invoke
        res = self.session.invoke_handler(
            target_ptr=ev.target_pointer,
            selector=ev.selector,
            sender_ptr=ev.sender.get("pointer", "0x0") if ev.sender else "0x0",
        )
        msg = res.get("message", "Unknown response")
        self.push_screen(MessageModal("Replay Handler Result", f"Status: {'Success' if res.get('success') else 'Failed'}\nMessage: {msg}"))

    def action_tamper_replay(self) -> None:
        """Interactive argument mutation dialog before replaying handler."""
        if not self.selected_event:
            self.status_bar.show_message("No handler selected for tamper replay")
            return

        ev = self.selected_event

        def _on_tamper_dismiss(mutated_val: Optional[str]):
            if mutated_val is None:
                return
            if self.mock_mode or not self.session:
                self.status_bar.show_message(f"[Tamper Replay] Invoked with mutated arg: {mutated_val}")
                self.push_screen(MessageModal(
                    "Tamper Replay (Simulated)",
                    f"Successfully invoked with mutated argument:\n\nTarget: {ev.target_class}\nSelector: {ev.selector}\nMutated Value: {mutated_val}"
                ))
            else:
                res = self.session.invoke_handler(
                    target_ptr=ev.target_pointer,
                    selector=ev.selector,
                    sender_ptr=ev.sender.get("pointer", "0x0") if ev.sender else "0x0",
                )
                self.status_bar.show_message(f"Tamper Replay executed: {res.get('message', 'Done')}")

        self.push_screen(TamperReplayModal(ev.target_class, ev.selector), _on_tamper_dismiss)

    def action_gen_script(self) -> None:
        if not self.selected_event:
            self.status_bar.show_message("No handler selected")
            return

        sel = self.selected_event.selector.replace(":", "_") or "action"
        out_name = f"hook_{self.selected_event.target_class}_{sel}.js"
        out_path = Path.cwd() / out_name
        try:
            saved_path = generate_frida_hook_script(self.selected_event, out_path)
            self.status_bar.show_message(f"Generated Frida hook: {out_name}")
            self.push_screen(MessageModal("Script Generated", f"Standalone Frida script saved to:\n{saved_path}"))
        except Exception as e:
            self.status_bar.show_message(f"Error generating script: {e}")

    def action_copy_jump(self) -> None:
        """Launch Quick-Copy Modal for instant OS clipboard synchronization."""
        if not self.selected_event or not self.selected_event.location:
            self.status_bar.show_message("No location metadata for this event")
            return

        def _on_copy_done(result: Optional[tuple]):
            if result:
                text, desc = result
                self.status_bar.show_message(f"Copied {desc} to OS Clipboard!")
                self.log_stream.write(f"[bold #34d399]✓ Copied to OS Clipboard: {text}[/]")

        self.push_screen(
            CopyJumpModal(
                location=self.selected_event.location,
                event_summary=self.selected_event.summary,
                selector=self.selected_event.selector,
            ),
            _on_copy_done,
        )

    def action_export_session(self) -> None:
        events = self.dispatcher.events
        if not events:
            self.status_bar.show_message("No events to export")
            return

        md_file = Path.cwd() / "trace_export.md"
        json_file = Path.cwd() / "trace_export.json"

        try:
            saved_md = export_to_markdown(events, self.target_name, md_file)
            saved_json = export_to_json(events, self.target_name, json_file)
            self.status_bar.show_message(f"Exported {len(events)} events to Markdown & JSON")
            self.push_screen(MessageModal(
                "Export Complete",
                f"Successfully exported {len(events)} events to:\n\n1. Markdown: {saved_md}\n2. JSON: {saved_json}"
            ))
        except Exception as e:
            self.status_bar.show_message(f"Export failed: {e}")

    def action_quit_app(self) -> None:
        if self.bridge:
            self.bridge.stop()
        if self.mock_gen:
            self.mock_gen.stop()
        if self.session:
            self.session.detach()
        self.exit()
