"""
Mock Event Generator for iOSuite Trace
Provides realistic simulated iOS events for testing, development, and offline demonstrations.
"""

import asyncio
import random
from datetime import datetime
from typing import Dict, Any, Callable


MOCK_EVENTS_POOL = [
    {
        "category": "ui_action",
        "actionType": "sendAction",
        "targetClass": "AcmeBank.CheckoutViewController",
        "selector": "onPayButtonTapped:",
        "targetPointer": "0x1084f2100",
        "summary": "UIButton -> onPayButtonTapped:",
        "sender": {
            "className": "UIButton",
            "title": "Bayar Sekarang (Rp 250.000)",
            "tag": 101,
            "accessibilityId": "btn_pay_checkout",
            "hierarchy": [
                "UIWindow",
                "UITabBarController",
                "UINavigationController",
                "AcmeBank.CheckoutViewController",
                "UIView (ContentView)",
                "UIButton [id=\"btn_pay_checkout\"]",
            ],
        },
        "location": {
            "implementation": "0x104A1B240",
            "moduleName": "AcmeBank.app/AcmeBank",
            "moduleBase": "0x104800000",
            "offset": "0x21B240",
            "isApp": True,
            "disassembly": [
                {"address": "0x104A1B240", "mnemonic": "stp", "opStr": "x29, x30, [sp, #-0x20]!", "size": 4},
                {"address": "0x104A1B244", "mnemonic": "mov", "opStr": "x29, sp", "size": 4},
                {"address": "0x104A1B248", "mnemonic": "sub", "opStr": "sp, sp, #0x40", "size": 4},
                {"address": "0x104A1B24C", "mnemonic": "adrp", "opStr": "x8, 0x104b20000", "size": 4},
                {"address": "0x104A1B250", "mnemonic": "ldr", "opStr": "x0, [x8, #0x120]", "size": 4},
                {"address": "0x104A1B254", "mnemonic": "bl", "opStr": "0x1049c0110 ; -[PaymentService execute]", "size": 4},
                {"address": "0x104A1B258", "mnemonic": "mov", "opStr": "sp, x29", "size": 4},
                {"address": "0x104A1B25C", "mnemonic": "ldp", "opStr": "x29, x30, [sp], #0x20", "size": 4},
                {"address": "0x104A1B260", "mnemonic": "ret", "opStr": "", "size": 4},
            ],
        },
        "backtrace": {
            "hasAppFrame": True,
            "frames": [
                {
                    "index": 0,
                    "address": "0x104A1B240",
                    "moduleName": "AcmeBank",
                    "moduleBase": "0x104800000",
                    "offset": "0x21B240",
                    "symbol": "$s8AcmeBank22CheckoutViewControllerC16onPayButtonTappedyyF",
                    "file": "CheckoutViewController.swift",
                    "line": 142,
                    "isApp": True,
                },
                {
                    "index": 1,
                    "address": "0x184291880",
                    "moduleName": "UIKitCore",
                    "moduleBase": "0x184000000",
                    "offset": "0x291880",
                    "symbol": "-[UIApplication sendAction:to:from:forEvent:]",
                    "file": "",
                    "line": 0,
                    "isApp": False,
                },
                {
                    "index": 2,
                    "address": "0x18428f520",
                    "moduleName": "UIKitCore",
                    "moduleBase": "0x184000000",
                    "offset": "0x28F520",
                    "symbol": "-[UIControl sendAction:to:forEvent:]",
                    "file": "",
                    "line": 0,
                    "isApp": False,
                },
            ],
        },
    },
    {
        "category": "navigation",
        "actionType": "pushViewController",
        "targetClass": "AcmeBank.PaymentConfirmationViewController",
        "summary": "Push Nav -> PaymentConfirmationViewController",
        "location": {
            "implementation": "0x104A3C100",
            "moduleName": "AcmeBank.app/AcmeBank",
            "moduleBase": "0x104800000",
            "offset": "0x23C100",
            "isApp": True,
            "disassembly": [
                {"address": "0x104A3C100", "mnemonic": "stp", "opStr": "x20, x19, [sp, #-0x20]!", "size": 4},
                {"address": "0x104A3C104", "mnemonic": "stp", "opStr": "x29, x30, [sp, #0x10]", "size": 4},
                {"address": "0x104A3C108", "mnemonic": "bl", "opStr": "0x104a3d500 ; -[UIViewController viewDidLoad]", "size": 4},
            ],
        },
        "backtrace": {
            "hasAppFrame": True,
            "frames": [
                {
                    "index": 0,
                    "address": "0x104A3C100",
                    "moduleName": "AcmeBank",
                    "moduleBase": "0x104800000",
                    "offset": "0x23C100",
                    "symbol": "$s8AcmeBank31PaymentConfirmationVC11viewDidLoadyyF",
                    "file": "PaymentConfirmationViewController.swift",
                    "line": 34,
                    "isApp": True,
                },
                {
                    "index": 1,
                    "address": "0x184410290",
                    "moduleName": "UIKitCore",
                    "moduleBase": "0x184000000",
                    "offset": "0x410290",
                    "symbol": "-[UINavigationController pushViewController:animated:]",
                    "file": "",
                    "line": 0,
                    "isApp": False,
                },
            ],
        },
    },
    {
        "category": "swiftui",
        "actionType": "swiftuiHit",
        "targetClass": "AcmeBank.CustomQuickTransferCardView",
        "summary": "SwiftUI Touch on QuickTransferCardView",
        "location": {
            "implementation": "0x104AF0180",
            "moduleName": "AcmeBank.app/AcmeBank",
            "moduleBase": "0x104800000",
            "offset": "0x2F0180",
            "isApp": True,
            "disassembly": [
                {"address": "0x104AF0180", "mnemonic": "pacibsp", "opStr": "", "size": 4},
                {"address": "0x104AF0184", "mnemonic": "stp", "opStr": "x29, x30, [sp, #-0x10]!", "size": 4},
                {"address": "0x104AF0188", "mnemonic": "bl", "opStr": "0x104af0890 ; ClosureAction.invoke()", "size": 4},
            ],
        },
        "backtrace": {
            "hasAppFrame": True,
            "frames": [
                {
                    "index": 0,
                    "address": "0x104AF0180",
                    "moduleName": "AcmeBank",
                    "moduleBase": "0x104800000",
                    "offset": "0x2F0180",
                    "symbol": "$s8AcmeBank25QuickTransferCardViewV10bodyClosureyyF",
                    "file": "QuickTransferCardView.swift",
                    "line": 78,
                    "isApp": True,
                },
            ],
        },
    },
    {
        "category": "deeplink",
        "actionType": "openURL",
        "targetClass": "AcmeBank.AppDelegate",
        "url": "acme://promo/transfer?ref=MERDEKA50&amount=100000",
        "summary": "Open URL: acme://promo/transfer?ref=MERDEKA50",
        "location": {
            "implementation": "0x1048C0A20",
            "moduleName": "AcmeBank.app/AcmeBank",
            "moduleBase": "0x104800000",
            "offset": "0xC0A20",
            "isApp": True,
            "disassembly": [
                {"address": "0x1048C0A20", "mnemonic": "sub", "opStr": "sp, sp, #0x30", "size": 4},
                {"address": "0x1048C0A24", "mnemonic": "stp", "opStr": "x29, x30, [sp, #0x20]", "size": 4},
            ],
        },
        "backtrace": {
            "hasAppFrame": True,
            "frames": [
                {
                    "index": 0,
                    "address": "0x1048C0A20",
                    "moduleName": "AcmeBank",
                    "moduleBase": "0x104800000",
                    "offset": "0xC0A20",
                    "symbol": "$s8AcmeBank11AppDelegateC11application_7openURL7optionsSbSo13UIApplicationC_10Foundation0H0VSDySo0n6MethodE3KeyaypGtF",
                    "file": "AppDelegate.swift",
                    "line": 52,
                    "isApp": True,
                },
            ],
        },
    },
    {
        "category": "webview",
        "actionType": "scriptMessage",
        "targetClass": "AcmeBank.InAppBrowserViewController",
        "summary": 'WebKit Bridge: "getSecureToken"',
        "body": '{"action": "request_session_token", "merchantId": "ID_MCH_88291"}',
        "location": {
            "implementation": "0x104950400",
            "moduleName": "AcmeBank.app/AcmeBank",
            "moduleBase": "0x104800000",
            "offset": "0x150400",
            "isApp": True,
            "disassembly": [
                {"address": "0x104950400", "mnemonic": "stp", "opStr": "x29, x30, [sp, #-0x10]!", "size": 4},
            ],
        },
        "backtrace": {
            "hasAppFrame": True,
            "frames": [
                {
                    "index": 0,
                    "address": "0x104950400",
                    "moduleName": "AcmeBank",
                    "moduleBase": "0x104800000",
                    "offset": "0x150400",
                    "symbol": "-[InAppBrowserViewController userContentController:didReceiveScriptMessage:]",
                    "file": "InAppBrowserViewController.m",
                    "line": 89,
                    "isApp": True,
                },
            ],
        },
    },
    {
        "category": "network_trigger",
        "actionType": "dataTask",
        "url": "https://api.acmebank.co.id/v2/transactions/checkout",
        "method": "POST",
        "summary": "POST https://api.acmebank.co.id/v2/transactions/checkout",
        "location": {
            "implementation": "0x104A1B300",
            "moduleName": "AcmeBank.app/AcmeBank",
            "moduleBase": "0x104800000",
            "offset": "0x21B300",
            "isApp": True,
            "disassembly": [],
        },
        "backtrace": {
            "hasAppFrame": True,
            "frames": [
                {
                    "index": 0,
                    "address": "0x104A1B300",
                    "moduleName": "AcmeBank",
                    "moduleBase": "0x104800000",
                    "offset": "0x21B300",
                    "symbol": "$s8AcmeBank14NetworkServiceC11postRequest4path4bodyyySS_SDySSypGtF",
                    "file": "NetworkService.swift",
                    "line": 105,
                    "isApp": True,
                },
            ],
        },
    },
]


class MockSessionGenerator:
    """Simulates a live Frida session on an iOS app."""

    def __init__(self, on_event: Callable[[Dict[str, Any]], None], interval_range: tuple = (1.5, 3.5)):
        self.on_event = on_event
        self.interval_range = interval_range
        self._running = False
        self._task: asyncio.Task | None = None
        self.app_info = {
            "bundlePath": "/var/containers/Bundle/Application/8F9E-12AB-43CD/AcmeBank.app",
            "executablePath": "/var/containers/Bundle/Application/8F9E-12AB-43CD/AcmeBank.app/AcmeBank",
            "executableName": "AcmeBank",
            "baseAddress": "0x104800000",
            "arch": "arm64",
            "pageSize": 16384,
        }

    async def start(self) -> None:
        self._running = True
        # Emit initial 2 events immediately
        for item in MOCK_EVENTS_POOL[:2]:
            ev = dict(item)
            ev["id"] = f"mock_{random.randint(1000, 9999)}"
            ev["timestamp"] = datetime.now().isoformat()
            self.on_event(ev)

        self._task = asyncio.create_task(self._loop())

    async def _loop(self) -> None:
        idx = 2
        while self._running:
            delay = random.uniform(*self.interval_range)
            await asyncio.sleep(delay)
            if not self._running:
                break

            template = MOCK_EVENTS_POOL[idx % len(MOCK_EVENTS_POOL)]
            ev = dict(template)
            ev["id"] = f"mock_{random.randint(1000, 9999)}"
            ev["timestamp"] = datetime.now().isoformat()
            self.on_event(ev)
            idx += 1

    def start_sync(self):
        """Synchronous/threaded start for non-asyncio contexts."""
        import threading
        import time

        self._running = True
        for item in MOCK_EVENTS_POOL[:2]:
            ev = dict(item)
            ev["id"] = f"mock_{random.randint(1000, 9999)}"
            ev["timestamp"] = datetime.now().isoformat()
            self.on_event(ev)

        def _thread_loop():
            idx = 2
            while self._running:
                delay = random.uniform(*self.interval_range)
                time.sleep(delay)
                if not self._running:
                    break
                template = MOCK_EVENTS_POOL[idx % len(MOCK_EVENTS_POOL)]
                ev = dict(template)
                ev["id"] = f"mock_{random.randint(1000, 9999)}"
                ev["timestamp"] = datetime.now().isoformat()
                self.on_event(ev)
                idx += 1

        t = threading.Thread(target=_thread_loop, daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
