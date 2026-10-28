"""
Tests for the CA-trust pre-flight detector.

The device-side half (Frida + Security.framework) cannot run in CI, so these
cover the pure logic: how cert bytes are obtained, and how every device answer
maps to a state/hint. The device path itself was verified on hardware:
  * Burp PortSwigger CA      -> state "trusted"
  * throwaway self-signed CA -> state "untrusted", errCode -67843
"""
import socket
import threading

import pytest

from iosuite.core import cadetect
from iosuite.core.cadetect import _load_ca_file, _fetch_burp_ca, detect_ca_trust_state


# A minimal valid DER: only has to survive base64 transport in these tests.
_DER = bytes.fromhex("3082010a0282010100")


def test_load_ca_file_reads_der(tmp_path):
    p = tmp_path / "ca.der"
    p.write_bytes(_DER)
    assert _load_ca_file(str(p)) == _DER


def test_load_ca_file_decodes_pem(tmp_path):
    import base64
    p = tmp_path / "ca.pem"
    body = base64.b64encode(_DER).decode()
    p.write_text(
        "subject=CN=Test\n"
        "-----BEGIN CERTIFICATE-----\n"
        f"{body}\n"
        "-----END CERTIFICATE-----\n"
    )
    assert _load_ca_file(str(p)) == _DER


def test_load_ca_file_missing_returns_none(tmp_path):
    assert _load_ca_file(str(tmp_path / "nope.der")) is None


class _FakeBurp:
    """Answers GET http://burp/cert the way Burp's listener does."""

    def __init__(self, body: bytes = _DER):
        self.body = body
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
        except OSError:
            return
        try:
            conn.recv(4096)
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/pkix-cert\r\n"
                b"Content-Length: " + str(len(self.body)).encode() + b"\r\n\r\n" + self.body
            )
        finally:
            conn.close()

    def close(self):
        try:
            self._sock.close()
        except Exception:
            pass


def test_fetch_burp_ca_extracts_der_body():
    burp = _FakeBurp()
    try:
        assert _fetch_burp_ca("127.0.0.1", burp.port, timeout=3) == _DER
    finally:
        burp.close()


def test_fetch_burp_ca_unreachable_returns_none():
    # Port 1 is never a Burp listener.
    assert _fetch_burp_ca("127.0.0.1", 1, timeout=1) is None


def test_missing_ca_file_reports_error_not_exception():
    res = detect_ca_trust_state(ca_cert="definitely-not-here.der")
    assert res["state"] == "unavailable"
    assert res["error"] == "ca_file_unreadable"
    assert res["hint"] is None


def test_unreachable_burp_reports_actionable_detail():
    res = detect_ca_trust_state(burp_host="127.0.0.1", burp_port=1, attach_timeout=1)
    assert res["state"] == "unavailable"
    assert res["error"] == "burp_unreachable"
    # It must tell the user the escape hatch.
    assert "--ca-cert" in res["detail"]


def test_no_device_reports_unavailable(monkeypatch):
    """A device that is not plugged in must degrade cleanly, not raise."""

    def _raise(*a, **kw):
        raise RuntimeError("no device")

    monkeypatch.setattr(cadetect.frida, "get_usb_device", _raise)
    monkeypatch.setattr(cadetect, "_fetch_burp_ca", lambda *a, **kw: _DER)
    res = detect_ca_trust_state(burp_host="127.0.0.1", burp_port=1337)
    assert res["state"] == "unavailable"
    assert res["error"] == "no_device"
    assert "No USB iOS device" in res["detail"]


def test_state_mapping_trusted(monkeypatch):
    """Device says trusted -> state trusted, no hint."""
    monkeypatch.setattr(cadetect, "_fetch_burp_ca", lambda *a, **kw: _DER)
    monkeypatch.setattr(cadetect, "_run_on_device",
                        lambda b64, timeout=25.0: {"trusted": True, "subject": "PortSwigger CA"})
    res = detect_ca_trust_state(burp_host="127.0.0.1", burp_port=1337)
    assert res["state"] == "trusted"
    assert res["subject"] == "PortSwigger CA"
    assert res["hint"] is None


def test_state_mapping_untrusted_includes_fix(monkeypatch):
    """Device says untrusted -> state untrusted plus the install instructions."""
    monkeypatch.setattr(cadetect, "_fetch_burp_ca", lambda *a, **kw: _DER)
    monkeypatch.setattr(cadetect, "_run_on_device",
                        lambda b64, timeout=25.0: {"trusted": False, "subject": "PortSwigger CA",
                                        "errCode": -67843, "errDomain": "NSOSStatusErrorDomain"})
    res = detect_ca_trust_state(burp_host="10.0.0.5", burp_port=1337)
    assert res["state"] == "untrusted"
    assert res["errCode"] == -67843
    assert "Certificate Trust Settings" in res["hint"]
    assert "http://10.0.0.5:1337/cert" in res["hint"]


def test_device_error_reports_unavailable(monkeypatch):
    monkeypatch.setattr(cadetect, "_fetch_burp_ca", lambda *a, **kw: _DER)
    monkeypatch.setattr(cadetect, "_run_on_device",
                        lambda b64, timeout=25.0: {"error": "SecCertificateCreateWithData returned null"})
    res = detect_ca_trust_state(burp_host="127.0.0.1", burp_port=1337)
    assert res["state"] == "unavailable"
    assert "SecCertificateCreateWithData" in res["detail"]
    assert res["error"] == "SecCertificateCreateWithData returned null"
