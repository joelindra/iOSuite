"""
Lightweight synchronization bridge for IDA Pro, Ghidra, Hopper, and Binary Ninja.
Runs an embedded localhost HTTP server dispatching navigation jump events.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import threading
from typing import Optional, Dict, Any


class DisassemblerBridge:
    """Embedded HTTP micro-service to sync TUI jump actions with external disassemblers."""

    def __init__(self, host: str = "127.0.0.1", port: int = 1337):
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self.last_event: Optional[Dict[str, Any]] = None
        self._running = False

    def start(self) -> None:
        """Start background daemon thread for HTTP bridge."""
        if self._running:
            return

        parent = self

        class BridgeHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path in ("/poll", "/jump"):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    response = parent.last_event or {"action": "idle"}
                    self.wfile.write(json.dumps(response).encode("utf-8"))
                elif self.path == "/status":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"status": "running", "clients": 1}).encode("utf-8"))
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format, *args):
                pass  # Suppress console stderr logs to protect TUI display

        try:
            self.server = HTTPServer((self.host, self.port), BridgeHandler)
            self._running = True
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
        except OSError:
            # Port already in use or restricted; fail gracefully without crashing
            self._running = False

    def broadcast_jump(self, module_name: str, file_offset: str, target_symbol: str, impl_pc: str = "0x0") -> None:
        """Update last jump target so connected disassembler plugins jump immediately."""
        self.last_event = {
            "action": "jump",
            "module": module_name,
            "offset": str(file_offset),
            "symbol": target_symbol,
            "pc": impl_pc,
        }

    def stop(self) -> None:
        """Cleanly shutdown bridge server."""
        if self.server:
            self._running = False
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
            self.server = None
