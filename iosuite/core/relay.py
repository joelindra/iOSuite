"""
Transparent HTTP/HTTPS relay for iOSuite.

Why this module exists
----------------------
iOSuite's socket redirect (agent.js `connect()` hook) rewrites an app's
outbound socket for ports 80/443 to point at the configured proxy address.
That produces a *non-proxy-aware* connection: for HTTPS the client sends a raw
TLS ClientHello as the very first bytes on the wire.

Burp's proxy listener cannot consume that. Verified empirically against
Burp on 192.168.50.216:1337:

    raw TLS ClientHello                     -> handshake times out (black hole)
    absolute-form HTTP proxy request        -> 200 OK
    CONNECT example.com:443                 -> 200 Connection established
    origin-form HTTP (GET / + Host)         -> 200 OK

So pointing the redirect straight at Burp can never surface HTTPS traffic.
This relay sits between the two and speaks each side's protocol:

    app socket (raw TCP, TLS or HTTP)
        -> relay on 127.0.0.1:RELAY_PORT
            -> Burp proxy listener (CONNECT for TLS, absolute-form for HTTP)

The iOS device reaches the relay over the LAN, so the relay binds 0.0.0.0 and
advertises a LAN address to the UI.
"""

import re
import socket
import struct
import threading
from typing import Optional, Callable, Dict, Any, Tuple

# TLS record: ContentType(1) = 0x16 handshake. Version bytes follow.
TLS_HANDSHAKE = 0x16
# Bytes we need to sniff before deciding the protocol.
SNIFF_LEN = 1


def _tls_handshake_payload(buf: bytes) -> Optional[bytes]:
    """Concatenate the handshake payloads of consecutive TLS records.

    A ClientHello usually fits one record, but can be fragmented across
    several (large post-quantum key shares). Returns None while incomplete.
    """
    payload = b""
    p = 0
    while p + 5 <= len(buf):
        ctype = buf[p]
        if ctype != TLS_HANDSHAKE:
            return None
        rec_len = struct.unpack("!H", buf[p + 3:p + 5])[0]
        if len(buf) < p + 5 + rec_len:
            return None  # record not fully arrived yet
        payload += buf[p + 5:p + 5 + rec_len]
        p += 5 + rec_len
        # Stop as soon as the handshake message is complete.
        if len(payload) >= 4:
            hs_len = int.from_bytes(payload[1:4], "big")
            if len(payload) >= 4 + hs_len:
                return payload
    return None


def _parse_sni_from_client_hello(data: bytes) -> Optional[str]:
    """Extract the SNI hostname from a TLS ClientHello.

    Returns None if the buffer does not yet contain a complete ClientHello or
    carries no server_name extension (e.g. IP-literal connections).
    """
    try:
        hs = _tls_handshake_payload(data)
        if hs is None or len(hs) < 4:
            return None
        if hs[0] != 0x01:  # not a ClientHello
            return None
        p = 4
        p += 2 + 32  # client_version + random
        if p >= len(hs):
            return None
        sid_len = hs[p]
        p += 1 + sid_len
        if p + 2 > len(hs):
            return None
        cs_len = struct.unpack("!H", hs[p:p + 2])[0]
        p += 2 + cs_len
        if p >= len(hs):
            return None
        comp_len = hs[p]
        p += 1 + comp_len
        if p + 2 > len(hs):
            return None
        ext_total = struct.unpack("!H", hs[p:p + 2])[0]
        p += 2
        end = min(len(hs), p + ext_total)
        while p + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", hs[p:p + 4])
            p += 4
            if ext_type == 0x0000:  # server_name
                # ext_data = list_len(2) | name_type(1) | name_len(2) | name
                if p + 5 > len(hs):
                    return None
                name_len = struct.unpack("!H", hs[p + 3:p + 5])[0]
                if p + 5 + name_len > len(hs):
                    return None
                name = hs[p + 5:p + 5 + name_len]
                # SNI carries the hostname as UTF-8 bytes; "idna" refuses dots.
                return name.decode("utf-8", "replace") or None
            p += ext_len
    except Exception:
        return None
    return None


def _parse_http_host(head: bytes) -> Optional[str]:
    """Pull the destination host out of an HTTP request head.

    Handles both absolute-form (`GET http://host/path HTTP/1.1`, what a
    proxy-aware client sends) and origin-form (`GET /path` + `Host: host`).
    """
    try:
        text = head.decode("latin1", "replace")
        first = text.split("\r\n", 1)[0]
        m = re.match(r"^[A-Z]+ https?://([^/\s:]+)(?::(\d+))?", first, re.I)
        if m:
            return m.group(1)
        m = re.search(r"^Host:\s*([^:\r\n]+)", text, re.I | re.M)
        if m:
            return m.group(1).strip()
    except Exception:
        return None
    return None


class TransparentProxyRelay:
    """Accepts plain TCP from the device, re-emits it as HTTP/CONNECT to Burp.

    The redirect in the injected process is protocol-blind: it just moves the
    destination. This relay restores the missing proxy framing so Burp can
    decrypt and log HTTPS.
    """

    def __init__(
        self,
        upstream_host: str,
        upstream_port: int,
        listen_host: str = "0.0.0.0",
        listen_port: int = 1338,
        log: Optional[Callable[[str, str], None]] = None,
    ):
        self.upstream_host = upstream_host
        self.upstream_port = int(upstream_port)
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self._log = log or (lambda level, msg: None)
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._conns = 0
        self._conns_lock = threading.Lock()
        self.connections_seen = 0
        self.last_error: Optional[str] = None
        # Set by the caller to the LAN address it advertises to the device
        # (the bind address 0.0.0.0 is not connectable from the iPhone).
        self.listen_host_advertised: Optional[str] = None

    # ---- lifecycle -----------------------------------------------------
    @property
    def running(self) -> bool:
        return self._sock is not None and not self._stop.is_set()

    def start(self) -> Dict[str, Any]:
        if self.running:
            return {"success": True, "host": self.listen_host, "port": self.listen_port,
                    "already_running": True}
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Windows' SO_REUSEADDR is not Unix's: it lets a new socket steal a
            # port another process is actively listening on (bind succeeds, the
            # other listener stops receiving). SO_EXCLUSIVEADDRUSE is the
            # Windows flag that means "fail if taken, and don't be taken".
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.listen_host, self.listen_port))
            srv.listen(64)
            srv.settimeout(0.5)
            # Resolve an ephemeral port (listen_port=0) so callers can read it back.
            self.listen_port = srv.getsockname()[1]
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {e}"
            self._log("ERROR", f"Relay failed to bind {self.listen_host}:{self.listen_port}: {e}")
            try:
                srv.close()
            except Exception:
                pass
            return {"success": False, "error": self.last_error}
        self._sock = srv
        self._stop.clear()
        self._thread = threading.Thread(target=self._accept_loop, name="iosuite-relay", daemon=True)
        self._thread.start()
        self._log("INFO", f"Transparent relay listening on {self.listen_host}:{self.listen_port} "
                          f"-> {self.upstream_host}:{self.upstream_port}")
        return {"success": True, "host": self.listen_host, "port": self.listen_port}

    def stop(self) -> Dict[str, Any]:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None
        self._log("INFO", "Transparent relay stopped")
        return {"success": True}

    def status(self) -> Dict[str, Any]:
        return {
            "running": self.running,
            "listenHost": self.listen_host,
            "listenPort": self.listen_port,
            "listenHostAdvertised": self.listen_host_advertised,
            "upstream": f"{self.upstream_host}:{self.upstream_port}",
            "connections": self.connections_seen,
            "lastError": self.last_error,
        }

    # ---- internals -----------------------------------------------------
    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                client, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception as e:
                self.last_error = f"accept: {type(e).__name__}: {e}"
                continue
            with self._conns_lock:
                self.connections_seen += 1
                self._conns += 1
            threading.Thread(target=self._handle, args=(client, addr), daemon=True).start()

    def _handle(self, client: socket.socket, addr: Tuple[str, int]) -> None:
        try:
            client.settimeout(15)
            first = self._peek_first_byte(client)
            if not first:
                return
            if first[0] == TLS_HANDSHAKE:
                self._pipe_tls(client, addr)
            else:
                self._pipe_http(client, addr)
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {e}"
            self._log("WARN", f"Relay connection from {addr[0]} failed: {e}")
        finally:
            try:
                client.close()
            except Exception:
                pass
            with self._conns_lock:
                self._conns -= 1

    def _peek_first_byte(self, client: socket.socket) -> bytes:
        """Read the first byte without consuming it (MSG_PEEK)."""
        if not hasattr(socket, "MSG_PEEK"):
            # Windows has MSG_PEEK; fallback to a normal read otherwise.
            return client.recv(SNIFF_LEN) or b""
        data = client.recv(SNIFF_LEN, socket.MSG_PEEK)
        return data or b""

    def _connect_upstream(self) -> socket.socket:
        up = socket.create_connection((self.upstream_host, self.upstream_port), timeout=15)
        up.settimeout(None)
        return up

    # ---- HTTPS: frame the raw TLS stream as a CONNECT tunnel -----------
    def _pipe_tls(self, client: socket.socket, addr) -> None:
        client.settimeout(2.0)
        buf = b""
        try:
            # Read enough of the ClientHello to learn the SNI. Read in small
            # chunks so we stop as soon as the extension is present.
            while len(buf) < 16 * 1024:
                chunk = client.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) >= 5:
                    rec_len = struct.unpack("!H", buf[3:5])[0]
                    if len(buf) >= 5 + rec_len:
                        break
        except socket.timeout:
            pass
        finally:
            client.settimeout(None)

        host = _parse_sni_from_client_hello(buf)
        if not host:
            # No SNI: the client is reaching an IP literal or uses a rudimentary
            # TLS stack. There is no way to recover the original destination from
            # the stream alone (the redirect rewrote it), so surface it loudly
            # instead of tunnelling to a placeholder Burp cannot resolve.
            self.last_error = "TLS stream carried no SNI; cannot determine destination"
            self._log("WARN", f"HTTPS from {addr[0]} had no SNI extension — cannot frame CONNECT. "
                              f"If the app dials a raw IP, dial the hostname instead.")
            return
        target = host
        self._log("INFO", f"HTTPS from {addr[0]} -> CONNECT {target}:443")

        up = self._connect_upstream()
        up.sendall(f"CONNECT {target}:443 HTTP/1.1\r\nHost: {target}:443\r\n"
                   f"Proxy-Connection: keep-alive\r\n\r\n".encode("latin1"))
        # Read the proxy's reply head.
        reply = b""
        up.settimeout(15)
        while b"\r\n\r\n" not in reply:
            part = up.recv(4096)
            if not part:
                raise ConnectionError("proxy closed during CONNECT")
            reply += part
            if len(reply) > 64 * 1024:
                raise ConnectionError("CONNECT reply too large")
        up.settimeout(None)
        status = reply.split(b"\r\n", 1)[0]
        if b" 200 " not in status and not status.endswith(b" 200"):
            raise ConnectionError(f"proxy refused CONNECT: {status!r}")

        # Forward the ClientHello we already consumed, then splice.
        if buf:
            up.sendall(buf)
        self._splice(client, up)

    # ---- Plain HTTP: rewrite to absolute-form --------------------------
    def _pipe_http(self, client: socket.socket, addr) -> None:
        client.settimeout(2.0)
        buf = b""
        try:
            while b"\r\n\r\n" not in buf and len(buf) < 64 * 1024:
                chunk = client.recv(4096)
                if not chunk:
                    break
                buf += chunk
        finally:
            client.settimeout(None)

        if not buf:
            return
        head, _, rest = buf.partition(b"\r\n\r\n")
        head += b"\r\n\r\n"
        host = _parse_http_host(head)
        if not host:
            self._log("WARN", f"HTTP from {addr[0]} had no host; passing through unmodified")
        else:
            self._log("INFO", f"HTTP from {addr[0]} -> absolute-form {host}")
            head = self._to_absolute_form(head, host)

        up = self._connect_upstream()
        up.sendall(head + rest)
        self._splice(client, up)

    @staticmethod
    def _to_absolute_form(head: bytes, host: str) -> bytes:
        """Convert `GET /path HTTP/1.1` into `GET http://host/path HTTP/1.1`."""
        lines = head.split(b"\r\n")
        if not lines:
            return head
        m = re.match(rb"^([A-Z]+) (/[^\s]*) (HTTP/1\.[01])$", lines[0].strip())
        if not m:
            return head  # already absolute-form or not a simple request
        method, path, version = m.group(1), m.group(2), m.group(3)
        if path.startswith(b"/") and not path.startswith(b"//"):
            lines[0] = method + b" http://" + host.encode("latin1") + path + b" " + version
        return b"\r\n".join(lines)

    # ---- bidirectional copy -------------------------------------------
    def _splice(self, client: socket.socket, upstream: socket.socket) -> None:
        def copy(src, dst):
            try:
                while not self._stop.is_set():
                    data = src.recv(16384)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass

        t = threading.Thread(target=copy, args=(upstream, client), daemon=True)
        t.start()
        copy(client, upstream)
        t.join(timeout=5)
