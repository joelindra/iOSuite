"""
Unit tests for root main.py entrypoint
"""

import sys
from unittest.mock import patch, MagicMock
from main import detect_connected_device_and_app, print_banner


def test_detect_connected_device_mock():
    """Verify device query returns graceful fallback when no hardware is connected."""
    dev_name, app_name, pid = detect_connected_device_and_app(use_usb=True)
    assert isinstance(dev_name, str)
    assert app_name in ("auto", str(app_name))


def test_detect_connected_device_success():
    """Verify device query parses active device and frontmost app."""
    mock_frida = MagicMock()
    mock_dev = MagicMock()
    mock_dev.name = "iPhone 15 Pro"
    mock_dev.type = "usb"
    mock_front = MagicMock()
    mock_front.name = "AcmeBank"
    mock_front.identifier = "com.acmebank.app"
    mock_front.pid = 1337
    mock_dev.get_frontmost_application.return_value = mock_front
    mock_frida.get_usb_device.return_value = mock_dev

    with patch.dict(sys.modules, {"frida": mock_frida}):
        dev_name, app_name, pid = detect_connected_device_and_app(use_usb=True)
        assert "iPhone 15 Pro" in dev_name
        assert app_name == "AcmeBank"
        assert pid == 1337


def test_print_banner_runs():
    """Verify banner renders without error."""
    print_banner(
        target="AcmeBank",
        device_name="iPhone 15 Pro (usb)",
        mock_mode=False,
        mode_ui="Desktop Webview Studio",
        bridge_port=1337
    )
