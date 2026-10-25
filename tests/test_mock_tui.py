"""
Async integration tests for Textual TUI using Textual's run_test().
"""

import pytest
from textual.widgets import TabbedContent
from iosuite.app import iOSuiteTraceApp


@pytest.mark.anyio
async def test_app_mount_and_widgets():
    app = iOSuiteTraceApp(target="TestApp", mock_mode=True)
    async with app.run_test() as pilot:
        # Check that main container and widgets are mounted
        assert app.header_bar is not None
        assert app.event_list is not None
        assert app.overview_tab is not None
        assert app.status_bar is not None

        # Give it a tiny pause to allow initial mock events to populate
        await pilot.pause(0.2)

        # Ensure events were processed
        assert len(app.dispatcher.events) >= 1
        assert len(app.event_list.children) >= 1

        # Check detail tab update
        assert app.selected_event is not None
        assert app.overview_tab.event is not None

        detail_tabs = app.query_one("#detail-pane", TabbedContent)

        # Test tab switching actions
        app.action_tab_2()
        await pilot.pause(0.05)
        assert detail_tabs.active == "tab-backtrace"

        app.action_tab_3()
        await pilot.pause(0.05)
        assert detail_tabs.active == "tab-arguments"

        app.action_tab_4()
        await pilot.pause(0.05)
        assert detail_tabs.active == "tab-disasm"

        app.action_tab_1()
        await pilot.pause(0.05)
        assert detail_tabs.active == "tab-overview"


@pytest.mark.anyio
async def test_frida_message_handling():
    from iosuite.app import FridaConnectedMessage, FridaEventMessage, FridaLogMessage

    app = iOSuiteTraceApp(target="TestApp", mock_mode=True)
    async with app.run_test() as pilot:
        # Test simulated connection message
        app.post_message(FridaConnectedMessage("TestApp", "iPhone USB", 12345))
        await pilot.pause(0.05)
        assert app.header_bar.pid == 12345
        assert "12345" in str(app.status_bar.render())

        # Test simulated intercepted event
        app.post_message(FridaEventMessage({
            "id": "test_ev_1",
            "category": "ui_action",
            "actionType": "sendAction",
            "summary": "UIButton -> onLoginTapped:",
            "targetClass": "LoginViewController",
            "selector": "onLoginTapped:",
            "location": {"offset": "0x1234", "moduleName": "TestApp"},
        }))
        await pilot.pause(0.05)
        assert any(e.id == "test_ev_1" for e in app.dispatcher.events)

        # Test log message
        app.post_message(FridaLogMessage("info", "Hook installed successfully"))
        await pilot.pause(0.05)
        assert "Hook installed successfully" in str(app.status_bar.render())

        # Test error message
        from iosuite.app import FridaErrorMessage
        app.post_message(FridaErrorMessage("Process terminated unexpectedly"))
        await pilot.pause(0.05)
        assert "Process terminated unexpectedly" in str(app.status_bar.render())
        assert "Offline" in str(app.header_bar.render())


@pytest.mark.anyio
async def test_small_window_responsiveness():
    """Verify that app runs cleanly and all tabs adapt in small terminal sizes."""
    from rich.console import Console

    app = iOSuiteTraceApp(target="SmallTestApp", mock_mode=True)
    async with app.run_test(size=(65, 20)) as pilot:
        await pilot.pause(0.2)
        assert len(app.dispatcher.events) >= 1

        # Header bar adapts to compact mode
        h_str = str(app.header_bar.render())
        assert "SmallTestApp" in h_str
        assert "ev" in h_str

        # Status bar adapts to compact mode
        s_str = str(app.status_bar.render())
        assert "Running in Mock Demonstration Mode" in s_str
        assert "Quit" in s_str

        c = Console(width=40)

        # Tab 1: Overview
        app.action_tab_1()
        await pilot.pause(0.05)
        with c.capture() as cap:
            c.print(app.overview_tab.render())
        captured_overview = cap.get()
        assert "Target" in captured_overview
        assert "Mach-O" in captured_overview
        assert "Disassembler" in captured_overview

        # Tab 2: Call Stack (compact 3-column mode)
        app.action_tab_2()
        await pilot.pause(0.05)
        with c.capture() as cap:
            c.print(app.backtrace_tab.render())
        captured_bt = cap.get()
        assert "Call Stack" in captured_bt
        assert "APP" in captured_bt or "SYS" in captured_bt

        # Tab 3: Arguments
        app.action_tab_3()
        await pilot.pause(0.05)
        with c.capture() as cap:
            c.print(app.arguments_tab.render())
        captured_args = cap.get()
        assert "Arguments" in captured_args

        # Tab 4: Disassembly
        app.action_tab_4()
        await pilot.pause(0.05)
        with c.capture() as cap:
            c.print(app.disasm_tab.render())
        captured_disasm = cap.get()
        assert "Disasm" in captured_disasm


def test_widget_compact_vs_wide_render():
    """Unit test for widgets rendering under different width constraints."""
    from rich.console import Console
    from iosuite.core.mock import MOCK_EVENTS_POOL
    from iosuite.core.dispatcher import InterceptedEvent
    from iosuite.ui.widgets import (
        HeaderBar,
        EventListItem,
        OverviewTab,
        BacktraceTab,
        DisassemblyTab,
        StatusBar,
    )

    ev = InterceptedEvent(
        id="test_ev",
        timestamp="2026-10-23T10:00:00",
        category="ui_action",
        action_type="sendAction",
        summary="UIButton -> onPayButtonTapped:VeryLongSummaryTextThatShouldBeTruncatedNeatly",
        target_class="AcmeBank.CheckoutViewControllerLongClassName",
        selector="onPayButtonTapped:",
        location=MOCK_EVENTS_POOL[0]["location"],
        backtrace=MOCK_EVENTS_POOL[0]["backtrace"],
    )

    # 1. HeaderBar
    hb = HeaderBar(target="TestApp", device="USB", pid=1234)
    hb._test_width = 60
    compact_hb = str(hb.render())
    assert "TestApp" in compact_hb
    assert "1234" in compact_hb

    hb._test_width = 120
    wide_hb = str(hb.render())
    assert "Target:" in wide_hb
    assert "PID: 1234" in wide_hb

    # 2. EventListItem truncation
    item = EventListItem(ev)
    item._test_width = 28
    rendered_item = str(item.render())
    assert "UI ACTION" in rendered_item
    assert "…" in rendered_item  # Properly truncated

    # 3. OverviewTab
    ot = OverviewTab()
    ot.update_event(ev)
    ot._test_width = 42
    c42 = Console(width=42)
    with c42.capture() as cap:
        c42.print(ot.render())
    ot_text = cap.get()
    assert "Target" in ot_text
    assert "Mach-O" in ot_text
    assert "ida_kernwin.jumpto" in ot_text

    # 4. BacktraceTab
    bt = BacktraceTab()
    bt.update_event(ev)
    bt._test_width = 42
    with c42.capture() as cap:
        c42.print(bt.render())
    bt_text = cap.get()
    assert "Call Stack" in bt_text
    assert "APP" in bt_text

    # 5. DisassemblyTab
    dt = DisassemblyTab()
    dt.update_event(ev)
    dt._test_width = 42
    with c42.capture() as cap:
        c42.print(dt.render())
    dt_text = cap.get()
    assert "Disasm" in dt_text
    assert "Operands" in dt_text

    # 6. StatusBar
    sb = StatusBar()
    sb._test_width = 60
    sb.show_message("Connected successfully")
    assert "Connected successfully" in str(sb.render())
    assert "Quit" in str(sb.render())

