"""
Unit tests for FridaDeviceSession target resolution.
"""

from unittest.mock import MagicMock
from iosuite.core.session import FridaDeviceSession


class MockProc:
    def __init__(self, pid: int, name: str):
        self.pid = pid
        self.name = name


class MockApp:
    def __init__(self, identifier: str, name: str, pid: int = 0):
        self.identifier = identifier
        self.name = name
        self.pid = pid


def test_resolve_numeric_pid():
    session = FridaDeviceSession(target=13458)
    mock_dev = MagicMock()
    mock_dev.enumerate_processes.return_value = [
        MockProc(13458, "MyTsel staging"),
        MockProc(12968, "SpringBoard"),
    ]
    session.device = mock_dev
    pid, name, bundle_id = session._resolve_target()
    assert pid == 13458
    assert name == "MyTsel staging"
    assert bundle_id is None


def test_resolve_fuzzy_app_name():
    session = FridaDeviceSession(target="MyTelkomsel")
    mock_dev = MagicMock()
    mock_dev.enumerate_processes.return_value = [
        MockProc(13458, "MyTsel staging"),
        MockProc(12968, "SpringBoard"),
    ]
    mock_dev.enumerate_applications.return_value = [
        MockApp("telkomsel.mytelkomsel-dev", "MyTsel staging", pid=13458),
        MockApp("com.apple.Preferences", "Settings", pid=13414),
    ]
    session.device = mock_dev
    pid, name, bundle_id = session._resolve_target()
    assert pid == 13458
    assert "telkomsel" in bundle_id.lower()


def test_resolve_bundle_id():
    session = FridaDeviceSession(target="com.apple.Preferences")
    mock_dev = MagicMock()
    mock_dev.enumerate_processes.return_value = [
        MockProc(13414, "Preferences"),
    ]
    mock_dev.enumerate_applications.return_value = [
        MockApp("com.apple.Preferences", "Settings", pid=13414),
    ]
    session.device = mock_dev
    pid, name, bundle_id = session._resolve_target()
    assert pid == 13414
    assert bundle_id == "com.apple.Preferences"


def test_resolve_unlaunched_app_spawns():
    session = FridaDeviceSession(target="MyTelkomsel")
    mock_dev = MagicMock()
    mock_dev.enumerate_processes.return_value = [
        MockProc(12968, "SpringBoard"),
    ]
    mock_dev.enumerate_applications.return_value = [
        MockApp("telkomsel.mytelkomsel-dev", "MyTsel staging", pid=0),
    ]
    session.device = mock_dev
    pid, name, bundle_id = session._resolve_target()
    assert pid is None
    assert bundle_id == "telkomsel.mytelkomsel-dev"


def test_connect_auto_spawns_on_attach_mach_failure():
    import frida
    session = FridaDeviceSession(target="MyTelkomsel", use_usb=False)
    mock_dev = MagicMock()
    mock_dev.enumerate_processes.return_value = [
        MockProc(13458, "MyTsel staging"),
    ]
    mock_dev.enumerate_applications.return_value = [
        MockApp("telkomsel.mytelkomsel-dev", "MyTsel staging", pid=13458),
    ]

    # First attach fails with (os/kern) failure on suspended process
    mock_dev.attach.side_effect = [
        frida.NotSupportedError("unexpected error while resuming process: (os/kern) failure"),
        MagicMock(),  # Second attach succeeds on spawned PID
    ]
    mock_dev.spawn.return_value = 13555

    session.device = mock_dev
    session.connect()

    assert session.pid == 13555
    mock_dev.spawn.assert_called_once_with(["telkomsel.mytelkomsel-dev"])
    mock_dev.resume.assert_called_once_with(13555)


def test_connect_auto_spawns_on_attach_timeout():
    """Verify that timeout was reached on suspended iOS apps falls back to auto-spawning bundle."""
    import frida
    session = FridaDeviceSession(target="Photos", use_usb=False)
    mock_dev = MagicMock()
    mock_dev.enumerate_processes.return_value = [
        MockProc(12722, "Photos"),
    ]
    mock_dev.enumerate_applications.return_value = [
        MockApp("com.apple.mobileslideshow", "Photos", pid=12722),
    ]

    # Direct attach times out because process is suspended in background
    mock_dev.attach.side_effect = [
        frida.TransportError("timeout was reached"),
        MagicMock(),  # Second attach on spawned PID succeeds
    ]
    mock_dev.spawn.return_value = 14109

    session.device = mock_dev
    session.connect()

    assert session.pid == 14109
    mock_dev.spawn.assert_called_once_with(["com.apple.mobileslideshow"])
    mock_dev.resume.assert_called_once_with(14109)


