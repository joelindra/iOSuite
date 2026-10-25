"""
Unit tests for the Disassembler Synchronization Bridge (HTTP server).
"""

import urllib.request
import json
import pytest
from iosuite.core.bridge import DisassemblerBridge


def test_bridge_lifecycle_and_poll():
    bridge = DisassemblerBridge(host="127.0.0.1", port=1339)
    try:
        bridge.start()
        assert bridge._running is True

        # Test initial /poll
        req = urllib.request.Request("http://127.0.0.1:1339/poll")
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["action"] == "idle"

        # Broadcast jump event
        bridge.broadcast_jump(
            module_name="TestApp.app/TestApp",
            file_offset="0x104A20",
            target_symbol="-[LoginVC onLogin:]",
            impl_pc="0x1000104A20",
        )

        # Verify /jump endpoint reflects latest jump
        req_jump = urllib.request.Request("http://127.0.0.1:1339/jump")
        with urllib.request.urlopen(req_jump, timeout=2.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["action"] == "jump"
            assert data["offset"] == "0x104A20"
            assert data["symbol"] == "-[LoginVC onLogin:]"

        # Test /status
        req_status = urllib.request.Request("http://127.0.0.1:1339/status")
        with urllib.request.urlopen(req_status, timeout=2.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "running"

    finally:
        bridge.stop()
        assert bridge._running is False
