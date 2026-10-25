"""
Unit tests for Desktop Webview Orchestrator & Local Bridge Server
"""

import urllib.request
import json
import pytest
from iosuite.ui.webview_app import DesktopWebviewOrchestrator, HTML_INDEX_FILE


def test_html_index_asset_exists():
    """Verify that index.html exists and contains the required cyber UI tokens."""
    assert HTML_INDEX_FILE.exists(), "UI asset index.html must exist"
    content = HTML_INDEX_FILE.read_text(encoding="utf-8")
    assert "PetiteVue" in content
    assert "JetBrains Mono" in content
    assert "IDA Pro Jump" in content
    assert "Ghidra Jump" in content
    assert "Hopper Jump" in content
    assert "LLDB Breakpoint" in content
    assert "handleGlobalKey" in content


def test_webview_orchestrator_server():
    """Verify webview local HTTP server endpoints."""
    orchestrator = DesktopWebviewOrchestrator(
        target="AcmeBank",
        mock_mode=True,
    )
    url = orchestrator.start_server()
    assert url.startswith("http://127.0.0.1:")

    try:
        # Test index.html
        req = urllib.request.urlopen(f"{url}/index.html", timeout=3)
        assert req.status == 200
        html = req.read().decode("utf-8")
        assert "<!DOCTYPE html>" in html

        # Test /api/session
        req_session = urllib.request.urlopen(f"{url}/api/session", timeout=3)
        assert req_session.status == 200
        session_data = json.loads(req_session.read().decode("utf-8"))
        assert session_data["target"] == "AcmeBank"
        assert session_data["pid"] == 4912
        assert session_data["connected"] is True
        assert "status" in session_data

        # Test /status
        req_status = urllib.request.urlopen(f"{url}/status", timeout=3)
        assert req_status.status == 200
        status_data = json.loads(req_status.read().decode("utf-8"))
        assert status_data["status"] == "running"

        # Test /api/applications
        req_apps = urllib.request.urlopen(f"{url}/api/applications", timeout=3)
        assert req_apps.status == 200
        apps_data = json.loads(req_apps.read().decode("utf-8"))
        assert isinstance(apps_data, list)
        assert len(apps_data) > 0
        assert any(a["name"] == "MyTelkomsel" for a in apps_data)

        # Test /api/switch_target POST
        orchestrator.events = [{"id": "ev_1", "selector": "test"}]
        switch_data = json.dumps({"target": "Safari", "spawn": False}).encode("utf-8")
        switch_req = urllib.request.Request(
            f"{url}/api/switch_target",
            data=switch_data,
            headers={"Content-Type": "application/json"}
        )
        switch_resp = urllib.request.urlopen(switch_req, timeout=3)
        assert switch_resp.status == 200
        switch_res = json.loads(switch_resp.read().decode("utf-8"))
        assert switch_res["status"] == "ok"
        assert orchestrator.target == "Safari"
        assert len(orchestrator.events) == 0  # Events cleared on switch target

        # Test /api/jump POST
        post_data = json.dumps({
            "module": "AcmeBank",
            "offset": "0x21B240",
            "symbol": "onPayButtonTapped:",
            "pc": "0x104A1B240"
        }).encode("utf-8")
        post_req = urllib.request.Request(
            f"{url}/api/jump",
            data=post_data,
            headers={"Content-Type": "application/json"}
        )
        resp = urllib.request.urlopen(post_req, timeout=3)
        assert resp.status == 200
        resp_data = json.loads(resp.read().decode("utf-8"))
        assert resp_data["status"] == "ok"

    finally:
        orchestrator.stop()


def test_webview_launch_nonblocking():
    """Verify launch(block=False) initializes server and doesn't hang."""
    from unittest.mock import patch
    orchestrator = DesktopWebviewOrchestrator(
        target="AcmeBank",
        mock_mode=True,
    )
    with patch("webbrowser.open"), patch("subprocess.Popen"):
        try:
            orchestrator.launch(block=False)
            assert orchestrator._running is True
        finally:
            orchestrator.stop()


def test_webview_initial_detected_device_and_pid():
    """Verify orchestrator properly stores pre-detected hardware info."""
    orchestrator = DesktopWebviewOrchestrator(
        target="MyTsel staging",
        device_name="Apple iPhone (usb)",
        initial_pid=13813,
        mock_mode=False,
    )
    assert orchestrator.target == "MyTsel staging"
    assert orchestrator.device_name == "Apple iPhone (usb)"
    assert orchestrator.pid == 13813
    assert "13813" in orchestrator.status


def test_webview_rapid_switching_generation_lock():
    """Verify rapid consecutive target switches update generation and don't deadlock."""
    orchestrator = DesktopWebviewOrchestrator(
        target="AppA",
        mock_mode=True,
    )
    orchestrator.switch_target("AppB")
    gen1 = orchestrator._switch_generation
    orchestrator.switch_target("AppC")
    gen2 = orchestrator._switch_generation
    assert gen2 > gen1
    assert orchestrator.target == "AppC"


def test_webview_new_features_endpoints():
    """Verify live memory hex, classes, methods, eval, bypasses, and export_hook endpoints."""
    orchestrator = DesktopWebviewOrchestrator(
        target="AcmeBank",
        mock_mode=True,
    )
    url = orchestrator.start_server()

    try:
        # 1. /api/memory_hex
        req_hex = urllib.request.urlopen(f"{url}/api/memory_hex?address=0x104A1B240&size=32", timeout=3)
        assert req_hex.status == 200
        hex_data = json.loads(req_hex.read().decode("utf-8"))
        assert hex_data["success"] is True
        assert len(hex_data["rows"]) == 2
        assert hex_data["rows"][0]["offset"] == "0x104A1B240"
        assert len(hex_data["rows"][0]["bytes"]) == 16

        # 2. /api/classes
        req_cls = urllib.request.urlopen(f"{url}/api/classes?q=login", timeout=3)
        assert req_cls.status == 200
        cls_data = json.loads(req_cls.read().decode("utf-8"))
        assert cls_data["success"] is True
        assert any("Login" in c for c in cls_data["classes"])

        # 3. /api/methods
        req_mth = urllib.request.urlopen(f"{url}/api/methods?class=LoginViewController", timeout=3)
        assert req_mth.status == 200
        mth_data = json.loads(req_mth.read().decode("utf-8"))
        assert mth_data["success"] is True
        assert len(mth_data["methods"]) > 0
        assert mth_data["className"] == "LoginViewController"

        # 4. /api/eval
        eval_post = json.dumps({"code": "Process.arch"}).encode("utf-8")
        req_eval = urllib.request.Request(
            f"{url}/api/eval",
            data=eval_post,
            headers={"Content-Type": "application/json"}
        )
        resp_eval = urllib.request.urlopen(req_eval, timeout=3)
        assert resp_eval.status == 200
        eval_data = json.loads(resp_eval.read().decode("utf-8"))
        assert eval_data["success"] is True
        assert "Executed: Process.arch" in eval_data["result"]

        # 5. /api/bypasses GET and POST
        req_byp = urllib.request.urlopen(f"{url}/api/bypasses", timeout=3)
        assert req_byp.status == 200
        byp_data = json.loads(req_byp.read().decode("utf-8"))
        assert byp_data["success"] is True
        assert "sslPinning" in byp_data["bypasses"]

        byp_post = json.dumps({"feature": "sslPinning", "enabled": True}).encode("utf-8")
        req_byp_set = urllib.request.Request(
            f"{url}/api/bypasses",
            data=byp_post,
            headers={"Content-Type": "application/json"}
        )
        resp_byp_set = urllib.request.urlopen(req_byp_set, timeout=3)
        assert resp_byp_set.status == 200
        byp_set_data = json.loads(resp_byp_set.read().decode("utf-8"))
        assert byp_set_data["success"] is True
        assert byp_set_data["state"] is True

        # 6. /api/export_hook
        hook_post = json.dumps({
            "targetClass": "AuthService",
            "selector": "verifyPin:",
            "implementation": "0x104A1B240"
        }).encode("utf-8")
        req_hook = urllib.request.Request(
            f"{url}/api/export_hook",
            data=hook_post,
            headers={"Content-Type": "application/json"}
        )
        resp_hook = urllib.request.urlopen(req_hook, timeout=3)
        assert resp_hook.status == 200
        hook_data = json.loads(resp_hook.read().decode("utf-8"))
        assert hook_data["success"] is True
        assert hook_data["filename"] == "hook_AuthService_verifyPin_.js"
        assert "Interceptor.attach" in hook_data["script"]
        assert "0x104A1B240" in hook_data["script"]

        # 7. /api/proxy (GET & POST)
        req_proxy = urllib.request.urlopen(f"{url}/api/proxy", timeout=3)
        assert req_proxy.status == 200
        proxy_data = json.loads(req_proxy.read().decode("utf-8"))
        assert proxy_data["success"] is True
        assert "host" in proxy_data
        assert "port" in proxy_data

        proxy_post = json.dumps({"host": "192.168.50.216", "port": 1337, "enabled": True}).encode("utf-8")
        req_proxy_set = urllib.request.Request(
            f"{url}/api/proxy",
            data=proxy_post,
            headers={"Content-Type": "application/json"}
        )
        resp_proxy_set = urllib.request.urlopen(req_proxy_set, timeout=3)
        assert resp_proxy_set.status == 200
        proxy_set_data = json.loads(resp_proxy_set.read().decode("utf-8"))
        assert proxy_set_data["success"] is True
        assert proxy_set_data["host"] == "192.168.50.216"
        assert proxy_set_data["port"] == 1337
        assert proxy_set_data["enabled"] is True

    finally:
        orchestrator.stop()




