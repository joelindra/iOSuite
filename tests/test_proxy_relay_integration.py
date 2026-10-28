"""
Integration tests for the orchestrator's relay-backed socket redirection.

This is the path the user actually drives from the UI:

    POST /api/proxy {enabled: true}
      -> orchestrator.set_proxy(burp_host, burp_port, True)
      -> relay starts in front of Burp
      -> device redirect target becomes the relay, NOT Burp

Regression under test: the redirect used to point straight at Burp, so raw TLS
from the device black-holed (Burp's listener has invisile proxying off).
"""
import socket
import ssl
import struct
import threading
import pytest

from iosuite.ui.webview_app import DesktopWebviewOrchestrator


class _StubBurp:
    """Minimal stand-in for Burp's proxy listener.

    Answers CONNECT with 200 then tunnels (echoing), and answers absolute-form
    HTTP with 200. Mirrors what the live Burp listener was measured doing.
    """

    def __init__(self):
        self.seen = []
        self._lock = threading.Lock()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            conn.settimeout(8)
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 65536:
                part = conn.recv(4096)
                if not part:
                    break
                head += part
            with self._lock:
                self.seen.append(head)
            if head.startswith(b"CONNECT"):
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                while True:
                    more = conn.recv(4096)
                    if not more:
                        break
                    conn.sendall(more)
            elif head.startswith(b"GET http://"):
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except Exception:
            pass


def _client_hello(sni: str) -> bytes:
    sni_bytes = sni.encode("utf-8")
    sn_list = b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
    sni_ext_data = struct.pack("!H", len(sn_list)) + sn_list
    ext = b"\x00\x00" + struct.pack("!H", len(sni_ext_data)) + sni_ext_data
    body = (
        b"\x01" + (b"\x00" * 3) + b"\x03\x01" + (b"\x00" * 32) + b"\x00"
        + struct.pack("!H", 4) + b"\x00\x05\x00\x0a"
        + b"\x01" + b"\x00"
        + struct.pack("!H", len(ext)) + ext
    )
    body = body[0:1] + struct.pack("!I", len(body) - 4)[1:] + body[4:]
    return b"\x16\x03\x01" + struct.pack("!H", len(body)) + body


class TestOrchestratorRelayWiring:
    def setup_method(self):
        self.burp = _StubBurp()
        self.orch = DesktopWebviewOrchestrator(mock_mode=True)

    def teardown_method(self):
        try:
            self.orch._stop_relay()
        except Exception:
            pass
        self.burp.stop()

    def test_enabling_proxy_starts_relay_and_redirects_to_it(self):
        res = self.orch.set_proxy("127.0.0.1", self.burp.port, True)

        assert res["success"], res
        assert res["enabled"] is True
        # The Burp listener is recorded as the upstream...
        assert res["host"] == "127.0.0.1"
        assert res["port"] == self.burp.port
        # ...but the device is pointed at the relay, on a different port.
        assert res["redirect"] is not None
        assert res["redirect"]["port"] != self.burp.port
        assert res["relay"]["running"] is True
        assert res["relay"]["upstream"] == f"127.0.0.1:{self.burp.port}"
        assert self.orch.relay.running

    def test_disabling_proxy_stops_relay(self):
        self.orch.set_proxy("127.0.0.1", self.burp.port, True)
        assert self.orch.relay is not None

        res = self.orch.set_proxy("127.0.0.1", self.burp.port, False)

        assert res["enabled"] is False
        assert res["relay"] is None
        assert self.orch.relay is None

    def test_raw_tls_through_redirect_becomes_connect(self):
        """THE regression: raw TLS to the redirect target must reach Burp.

        Before the relay this timed out -- Burp tried to parse the ClientHello
        as an HTTP request line and dropped the connection.
        """
        res = self.orch.set_proxy("127.0.0.1", self.burp.port, True)
        relay_port = res["redirect"]["port"]

        client = socket.create_connection(("127.0.0.1", relay_port), timeout=8)
        tag = b"TLS-APPLICATION-DATA"
        client.sendall(_client_hello("example.com") + tag)
        try:
            client.settimeout(6)
            echoed = client.recv(4096)
        finally:
            client.close()

        assert echoed, "relay returned nothing (regression: black-holed)"
        # Burp saw a well-formed CONNECT, not a raw ClientHello.
        assert self.burp.seen, "Burp stub saw no traffic"
        head = self.burp.seen[0]
        assert head.startswith(b"CONNECT example.com:443"), head[:120]
        # The proxy handshake must be swallowed from the protocol-unaware app.
        assert b"Connection established" not in echoed
        assert tag in echoed, echoed

    def test_plain_http_through_redirect_is_absolute_form(self):
        res = self.orch.set_proxy("127.0.0.1", self.burp.port, True)
        relay_port = res["redirect"]["port"]

        client = socket.create_connection(("127.0.0.1", relay_port), timeout=8)
        client.sendall(b"GET /thing HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        try:
            client.settimeout(6)
            data = client.recv(4096)
        finally:
            client.close()

        assert b"200 OK" in data, data
        assert self.burp.seen[0].startswith(b"GET http://example.com/thing HTTP/1.1")

    def test_get_proxy_reports_relay_status_for_ui(self):
        self.orch.set_proxy("127.0.0.1", self.burp.port, True)
        state = self.orch.get_proxy()

        assert state["enabled"] is True
        assert state["port"] == self.burp.port
        assert state["relay"]["running"] is True
        assert state["redirect"]["port"] == state["relay"]["listenPort"]

    def test_relay_counters_advance_with_traffic(self):
        res = self.orch.set_proxy("127.0.0.1", self.burp.port, True)
        relay_port = res["redirect"]["port"]
        for _ in range(2):
            c = socket.create_connection(("127.0.0.1", relay_port), timeout=8)
            c.sendall(_client_hello("example.com") + b"x")
            try:
                c.settimeout(5)
                c.recv(1024)
            finally:
                c.close()

        state = self.orch.get_proxy()
        assert state["relay"]["connections"] >= 2

    def test_relay_upstream_restarts_when_burp_port_changes(self):
        self.orch.set_proxy("127.0.0.1", self.burp.port, True)
        first = self.orch.relay

        other = _StubBurp()
        try:
            self.orch.set_proxy("127.0.0.1", other.port, True)
            assert self.orch.relay is not first
            assert self.orch.relay.upstream_port == other.port
        finally:
            other.stop()

    def test_relay_falls_back_when_adjacent_port_is_busy(self):
        """Regression: the bind-error wording differs per OS.

        Windows reports a taken port as "Only one usage of each socket address
        ...", not "address already in use", so matching on that substring made
        the relay give up instead of trying the next candidate -- an
        intermittent failure when burp_port+1 happened to be occupied.
        """
        squatter = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        squatter.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        squatter.bind(("0.0.0.0", 0))
        squatter.listen(1)
        taken = squatter.getsockname()[1]
        try:
            res = self.orch.set_proxy("127.0.0.1", taken - 1, True)

            assert res["success"], res
            assert res["relay"]["running"] is True
            # It must have moved off the busy port rather than failing.
            assert res["redirect"]["port"] != taken
            assert self.orch.relay.running
        finally:
            squatter.close()
