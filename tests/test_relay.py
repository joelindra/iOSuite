"""
Unit tests for the TransparentProxyRelay protocol-detection and request
reformatting logic. No device or Burp required.
"""
import socket
import struct
import threading
import pytest

from iosuite.core.relay import (
    TransparentProxyRelay,
    TLS_HANDSHAKE,
    _parse_sni_from_client_hello,
    _parse_http_host,
)

_to_absolute_form = TransparentProxyRelay._to_absolute_form


def _client_hello(sni: str) -> bytes:
    """Build a minimal TLS ClientHello carrying an SNI extension."""
    sni_bytes = sni.encode("idna")
    sn_list = b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes  # type + len + name
    sni_ext_data = struct.pack("!H", len(sn_list)) + sn_list          # list length
    ext = b"\x00\x00" + struct.pack("!H", len(sni_ext_data)) + sni_ext_data
    body = (
        b"\x01"  # ClientHello
        + (b"\x00" * 3)  # handshake length placeholder
        + b"\x03\x01"  # TLS 1.0
        + (b"\x00" * 32)   # random
        + b"\x00"          # session id len
        + struct.pack("!H", 4)  # cipher suites length
        + b"\x00\x05\x00\x0a"  # two cipher suites
        + b"\x01"          # compression methods len
        + b"\x00"          # null compression
        + struct.pack("!H", len(ext)) + ext
    )
    hs_len = len(body) - 4
    body = body[0:1] + struct.pack("!I", hs_len)[1:] + body[4:]
    return b"\x16\x03\x01" + struct.pack("!H", len(body)) + body


class TestSniParsing:
    def test_server_name_extracted(self):
        ch = _client_hello("example.com")
        assert _parse_sni_from_client_hello(ch) == "example.com"

    def test_short_buffer_returns_none(self):
        assert _parse_sni_from_client_hello(b"\x16\x03\x01\x00\x01") is None

    def test_non_client_hello_returns_none(self):
        assert _parse_sni_from_client_hello(b"\x16\x03\x01\x00\x04\x02\x00\x00\x00") is None


class TestHttpHostParsing:
    def test_absolute_form(self):
        head = b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        assert _parse_http_host(head) == "example.com"

    def test_origin_form_host(self):
        head = b"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        assert _parse_http_host(head) == "example.com"


class TestAbsoluteFormRewrite:
    def test_origin_form_becomes_absolute(self):
        head = b"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        out = _to_absolute_form(head, "example.com")
        assert out.startswith(b"GET http://example.com/path?q=1 HTTP/1.1\r\n")

    def test_already_absolute_form_untouched(self):
        head = b"GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n"
        assert _to_absolute_form(head, "example.com") == head


class TestRelayEndToEnd:
    """Live socket tests against a stub proxy that mirrors Burp's behaviour.

    The stub answers CONNECT with `200 Connection established` and then tunnels
    raw bytes, and answers absolute-form HTTP directly. This is what the probe
    against the real Burp listener showed it does.
    """

    def test_https_becomes_connect(self):
        seen, lock, port = self._start_relay()
        client = socket.create_connection(("127.0.0.1", port), timeout=8)
        tag = b"TLS-PAYLOAD-AFTER-HELLO"
        client.sendall(_client_hello("example.com") + tag)
        try:
            client.settimeout(6)
            echoed = client.recv(4096)
        finally:
            client.close()
        with lock:
            bodies = list(seen)
        self._teardown()

        assert bodies, "stub proxy saw nothing"
        head = bodies[0].split(b"\r\n\r\n", 1)[0]
        assert b"CONNECT example.com:443" in head, head
        # The relay must hide the proxy handshake from the protocol-unaware
        # client, so the client never sees the "200 Connection established".
        assert b"Connection established" not in echoed
        # Playload forwarded through the tunnel is echoed back by the stub.
        assert tag in echoed, echoed

    def test_http_becomes_absolute_form(self):
        seen, lock, port = self._start_relay()
        client = socket.create_connection(("127.0.0.1", port), timeout=8)
        client.sendall(b"GET /search?q=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        try:
            client.settimeout(6)
            data = client.recv(4096)
        finally:
            client.close()
        with lock:
            bodies = list(seen)
        self._teardown()

        assert bodies, "stub proxy saw nothing"
        first_line = bodies[0].split(b"\r\n", 1)[0]
        assert b"GET http://example.com/search?q=1 HTTP/1.1" in first_line, first_line
        assert b"200 OK" in data, data

    def _start_relay(self):
        upstream_seen = []
        upstream_lock = threading.Lock()

        def read_head(conn):
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 64 * 1024:
                part = conn.recv(4096)
                if not part:
                    break
                data += part
            return data

        def upstream_handler(conn, addr):
            try:
                conn.settimeout(8)
                data = read_head(conn)
                with upstream_lock:
                    upstream_seen.append(data)
                if data.startswith(b"CONNECT"):
                    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    # Tunnel: echo anything further so the test can prove the
                    # relay spliced bytes through in both directions.
                    while True:
                        more = conn.recv(4096)
                        if not more:
                            break
                        conn.sendall(more)
                else:
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(4)
        up_port = upstream.getsockname()[1]
        stop = threading.Event()

        def accept_loop():
            while not stop.is_set():
                try:
                    conn, addr = upstream.accept()
                except OSError:
                    return
                threading.Thread(target=upstream_handler, args=(conn, addr), daemon=True).start()

        at = threading.Thread(target=accept_loop, daemon=True)
        at.start()

        relay = TransparentProxyRelay(
            upstream_host="127.0.0.1",
            upstream_port=up_port,
            listen_host="127.0.0.1",
            listen_port=0,
        )
        relay.start()
        relay_port = relay.listen_port
        self._relay = relay
        self._upstream = upstream
        self._stop_event = stop
        return upstream_seen, upstream_lock, relay_port

    def _teardown(self):
        for closer in (
            lambda: self._stop_event.set(),
            lambda: self._relay.stop(),
            lambda: self._upstream.close(),
        ):
            try:
                closer()
            except Exception:
                pass


