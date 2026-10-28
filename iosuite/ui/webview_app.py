"""
Desktop Webview Orchestrator for iOSuite
Ultra-lightweight desktop user interface alternative using native OS webview / app mode.
Stack: Python HTTP micro-daemon + Native OS WebView2 / App-mode Browser + Petite-Vue zero-build HTML/JS.
Requires NO Node.js, NO npm, NO Rust compiler (substantially lighter and faster than Tauri).
"""

import sys
import os
import json
import socket
import threading
import webbrowser
import subprocess
import tempfile
import time
from pathlib import Path
from http.server import HTTPServer, ThreadingHTTPServer, SimpleHTTPRequestHandler
from typing import Optional, Dict, Any, List

from iosuite.core.mock import MockSessionGenerator
from iosuite.core.dispatcher import EventDispatcher, InterceptedEvent
from iosuite.core.bridge import DisassemblerBridge
from iosuite.core.relay import TransparentProxyRelay


ASSETS_DIR = Path(__file__).parent / "assets"
HTML_INDEX_FILE = ASSETS_DIR / "index.html"


def find_free_port(starting_port: int = 8484) -> int:
    """Find an available TCP port for the local webview server."""
    port = starting_port
    while port < 65535:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
        port += 1
    return 8484


class iOSuiteWebviewHandler(SimpleHTTPRequestHandler):
    """Custom HTTP handler serving the Single-File UI and REST endpoints."""

    def __init__(self, *args, orchestrator=None, **kwargs):
        self.orchestrator = orchestrator
        super().__init__(*args, directory=str(ASSETS_DIR), **kwargs)

    def _send_cors_headers(self):
        # Strict origin restriction to local interface
        origin = self.headers.get("Origin", "")
        if origin.startswith("http://127.0.0.1:") or origin.startswith("http://localhost:"):
            self.send_header("Access-Control-Allow-Origin", origin)
        else:
            self.send_header("Access-Control-Allow-Origin", f"http://127.0.0.1:{self.orchestrator.port if self.orchestrator else 8484}")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            if HTML_INDEX_FILE.exists():
                with open(HTML_INDEX_FILE, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.wfile.write(b"<h1>iOSuite UI index.html not found</h1>")
            return

        if self.path == "/api/session":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            data = {
                "target": self.orchestrator.target,
                "pid": self.orchestrator.pid,
                "device": self.orchestrator.device_name,
                "status": self.orchestrator.status,
                "connected": self.orchestrator.pid is not None,
                "bridgePort": 1337,
            }
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        if self.path.startswith("/api/events"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            events = self.orchestrator.get_events()
            self.wfile.write(json.dumps(events).encode("utf-8"))
            return

        if self.path.startswith("/api/logs"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            logs = self.orchestrator.get_logs() if self.orchestrator else []
            self.wfile.write(json.dumps(logs).encode("utf-8"))
            return

        if self.path.startswith("/api/applications"):
            force_refresh = "refresh=true" in self.path or "force=1" in self.path
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            apps = self.orchestrator.get_available_targets(force_refresh=force_refresh) if self.orchestrator else []
            self.wfile.write(json.dumps(apps).encode("utf-8"))
            return

        if self.path.startswith("/api/memory_hex"):
            import urllib.parse
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            addr = qs.get("address", ["0x0"])[0]
            size = int(qs.get("size", [64])[0]) if qs.get("size") else 64
            res = self.orchestrator.read_memory_hex(addr, size) if self.orchestrator else {"success": False, "error": "No orchestrator"}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
            return

        if self.path.startswith("/api/classes"):
            import urllib.parse
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            query = qs.get("q", [""])[0]
            res = self.orchestrator.enumerate_classes(query) if self.orchestrator else {"success": False, "classes": []}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
            return

        if self.path.startswith("/api/methods"):
            import urllib.parse
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            cls_name = qs.get("class", [""])[0]
            res = self.orchestrator.enumerate_methods(cls_name) if self.orchestrator else {"success": False, "methods": []}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
            return

        if self.path.startswith("/api/bypasses"):
            res = self.orchestrator.get_bypasses() if self.orchestrator else {"success": False, "bypasses": {}}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
            return

        if self.path.startswith("/api/proxy"):
            res = self.orchestrator.get_proxy() if self.orchestrator else {"success": False, "host": "192.168.50.216", "port": 1337, "enabled": False}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
            return

        if self.path.startswith("/status"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(b'{"status":"running","engine":"iosuite-webview"}')
            return

        # Serve static assets
        super().do_GET()

    def do_POST(self):
        if self.path == "/api/jump":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            try:
                data = json.loads(body)
                if self.orchestrator and self.orchestrator.bridge:
                    self.orchestrator.bridge.broadcast_jump(
                        module_name=data.get("module", "App"),
                        file_offset=data.get("offset", "0x0"),
                        target_symbol=data.get("symbol", "handler"),
                        impl_pc=data.get("pc", "0x0"),
                    )
            except Exception:
                pass

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return

        if self.path == "/api/replay":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            res = {"success": False, "message": "No active orchestrator"}
            try:
                data = json.loads(body)
                if self.orchestrator:
                    res = self.orchestrator.invoke_handler(
                        target_ptr=data.get("targetPointer", "0x0"),
                        selector=data.get("selector", ""),
                        sender_ptr=data.get("senderPointer", "0x0"),
                    )
            except Exception as e:
                res = {"success": False, "message": str(e)}

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
            return

        if self.path == "/api/clear":
            if self.orchestrator:
                self.orchestrator.clear_events()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return

        if self.path == "/api/pause":
            if self.orchestrator:
                self.orchestrator.toggle_pause()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return

        if self.path == "/api/switch_target":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            res = {"status": "error", "message": "No active orchestrator"}
            try:
                data = json.loads(body)
                target = data.get("target")
                spawn = bool(data.get("spawn", False))
                if self.orchestrator and target:
                    res = self.orchestrator.switch_target(target, spawn=spawn)
            except Exception as e:
                res = {"status": "error", "message": str(e)}

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
            return

        if self.path == "/api/eval":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            res = {"success": False, "error": "No orchestrator"}
            try:
                data = json.loads(body)
                code = data.get("code", "")
                if self.orchestrator:
                    res = self.orchestrator.eval_js(code)
            except Exception as e:
                res = {"success": False, "error": str(e)}

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
            return

        if self.path == "/api/relaunch":
            res = {"success": False, "error": "No orchestrator"}
            try:
                if self.orchestrator:
                    res = self.orchestrator.relaunch_target()
            except Exception as e:
                res = {"success": False, "error": str(e)}

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
            return

        if self.path == "/api/bypasses":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            res = {"success": False, "error": "No orchestrator"}
            try:
                data = json.loads(body)
                feature = data.get("feature", "")
                enabled = bool(data.get("enabled", False))
                if self.orchestrator:
                    res = self.orchestrator.set_bypass(feature, enabled)
            except Exception as e:
                res = {"success": False, "error": str(e)}

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
            return

        if self.path == "/api/proxy":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            res = {"success": False, "error": "No orchestrator"}
            try:
                data = json.loads(body)
                host = data.get("host", "192.168.50.216")
                port = int(data.get("port", 1337))
                enabled = bool(data.get("enabled", False))
                if self.orchestrator:
                    res = self.orchestrator.set_proxy(host, port, enabled)
            except Exception as e:
                res = {"success": False, "error": str(e)}

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
            return

        if self.path == "/api/export_hook":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            res = {"success": False, "error": "No orchestrator"}
            try:
                data = json.loads(body)
                target_cls = data.get("targetClass", "Target")
                selector = data.get("selector", "init")
                impl = data.get("implementation", "0x0")
                if self.orchestrator:
                    res = self.orchestrator.export_hook(target_cls, selector, impl)
            except Exception as e:
                res = {"success": False, "error": str(e)}

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        # Quiet logger to keep terminal clean
        pass


class DesktopWebviewOrchestrator:
    """
    Manages the lifecycle of the desktop webview window, HTTP daemon,
    and event synchronization with live Frida session or mock generator.
    """

    def __init__(
        self,
        target: str = "DemoApp",
        device_id: Optional[str] = None,
        device_name: Optional[str] = None,
        initial_pid: Optional[int] = None,
        use_usb: bool = True,
        spawn: bool = False,
        mock_mode: bool = False,
        port: Optional[int] = None,
    ):
        self.target = target
        self.device_id = device_id
        self.use_usb = use_usb
        self.spawn = spawn
        self.mock_mode = mock_mode
        self.pid: Optional[int] = 4912 if mock_mode else initial_pid
        if mock_mode:
            self.device_name = "iPhone 14 Pro (Mock)"
            self.status = "Running Mock Mode"
        elif device_name:
            self.device_name = device_name
            self.status = f"Attached to PID {initial_pid}" if initial_pid else f"Connecting to {target}..."
        else:
            self.device_name = "Detecting iOS Device..."
            self.status = "Connecting to iOS device..."
        self.port = port or find_free_port(8484)
        self.server: Optional[ThreadingHTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.bridge: Optional[DisassemblerBridge] = None
        self.dispatcher = EventDispatcher()
        self.events: List[Dict[str, Any]] = []
        self.logs: List[Dict[str, Any]] = []
        self.session = None
        self.mock_gen = None
        self._running = False
        self._paused = False

        # Transparent proxy relay that sits between the protocol-blind socket
        # redirect (agent.js) and Burp. HTTPS/raw TLS from the device is framed
        # as CONNECT → Burp; plain HTTP is rewritten to absolute form.
        # Burp's own proxy listener is the upstream target (1337 by default);
        # the relay listens on the next port (1338 by default).
        self.relay: Optional[TransparentProxyRelay] = None
        self._proxy_upstream: Dict[str, Any] = {"host": "192.168.50.216", "port": 1337, "enabled": False}

        # Target switching generation counter to prevent race conditions on fast app switching
        self._switch_generation = 0
        self._connection_lock = threading.Lock()

        # Cache for enumerate_applications / enumerate_processes (TTL: 8s)
        self._targets_cache: List[Dict[str, Any]] = []
        self._targets_cache_time: float = 0.0
        self._targets_cache_lock = threading.Lock()

    def add_log(self, level: str, message: str) -> None:
        """Add timestamped log entry."""
        from datetime import datetime
        self.logs.insert(0, {
            "time": datetime.now().strftime("%H:%M:%S"),
            "level": level.upper(),
            "message": str(message),
        })
        if len(self.logs) > 500:
            self.logs.pop()

    def get_logs(self) -> List[Dict[str, Any]]:
        return self.logs

    def clear_events(self) -> None:
        self.events.clear()
        self.dispatcher.clear()
        self.add_log("INFO", "Event queue cleared")

    def toggle_pause(self) -> bool:
        self._paused = not self._paused
        self.dispatcher.set_paused(self._paused)
        self.add_log("WARN" if self._paused else "INFO", f"Event stream {'PAUSED' if self._paused else 'RESUMED'}")
        return self._paused

    def _on_raw_event(self, raw_payload: Dict[str, Any]) -> None:
        """Callback processing raw Frida event dict."""
        if self._paused:
            return
        ev = self.dispatcher.process_raw_event(raw_payload)
        if not ev:
            return

        evt_dict = {
            "id": ev.id,
            "category": ev.category,
            "actionType": ev.action_type,
            "summary": ev.summary,
            "targetClass": ev.target_class,
            "selector": ev.selector,
            "targetPointer": ev.target_pointer,
            "sender": ev.sender,
            "location": ev.location or {},
            "backtrace": ev.backtrace or {},
            "hitCount": ev.hit_count,
            "timestamp": ev.timestamp.split("T")[-1][:8] if "T" in str(ev.timestamp) else str(ev.timestamp),
            "pinned": ev.pinned,
            "swiftDemangled": getattr(ev, "swift_demangled", ev.selector),
        }

        # Deduplication check: if event with matching ID exists, update it
        for i, existing in enumerate(self.events):
            if existing.get("id") == ev.id:
                self.events[i] = evt_dict
                return

        self.events.insert(0, evt_dict)
        if len(self.events) > 1000:
            self.events.pop()

    def _on_raw_log(self, level: str, message: str) -> None:
        self.add_log(level, message)

    def _connect_real_session(self, expected_generation: Optional[int] = None) -> None:
        """Connect to live iOS device via Frida and hook handlers."""
        from iosuite.core.session import FridaDeviceSession
        import frida

        # Acquire lock to ensure only one connection setup executes at a time
        with self._connection_lock:
            # If a newer switch request occurred while waiting, abort this stale connection
            if expected_generation is not None and expected_generation != self._switch_generation:
                return

            actual_target = self.target
            try:
                if self.device_id:
                    dev = frida.get_device(self.device_id)
                elif self.use_usb:
                    dev = frida.get_usb_device()
                else:
                    dev = frida.get_local_device()

                self.device_name = f"{dev.name} ({dev.type})"
                self.add_log("INFO", f"Connected to {dev.name} ({dev.type})")

                # Auto-detect frontmost application if no target or default target specified
                if actual_target in ("auto", "DemoApp", ""):
                    try:
                        front = dev.get_frontmost_application()
                        if front:
                            actual_target = front.identifier
                            self.target = front.name or front.identifier
                            self.add_log("INFO", f"Auto-detected frontmost app: {front.name} ({front.identifier})")
                    except Exception:
                        pass

                # Re-verify generation before blocking Frida attach/spawn
                if expected_generation is not None and expected_generation != self._switch_generation:
                    return

                new_session = FridaDeviceSession(
                    target=actual_target,
                    device_id=self.device_id,
                    use_usb=self.use_usb,
                    spawn=self.spawn,
                )
                new_session.set_callbacks(
                    on_event=self._on_raw_event,
                    on_log=self._on_raw_log,
                )
                self.add_log("INFO", f"Attaching to target '{actual_target}'...")
                new_session.connect()

                # If another switch occurred while connect() was running, cleanly detach
                if expected_generation is not None and expected_generation != self._switch_generation:
                    try:
                        new_session.detach()
                    except Exception:
                        pass
                    return

                self.session = new_session
                self.pid = self.session.pid
                target_name = self.session.app_info.get("executableName", str(actual_target))
                self.target = target_name
                self.status = f"Attached to PID {self.pid}"
                self.add_log("INFO", f"Attached to {target_name} (PID: {self.pid}) on {self.device_name}")

                # Re-apply an already-enabled socket redirect to the fresh process:
                # agent.js keeps its proxyConfig per-injected-process, so a new
                # attach starts from the default (off).
                if self._proxy_upstream.get("enabled") and self.relay and self.relay.running:
                    rh = self.relay.listen_host_advertised or self.relay.listen_host
                    rp = self.relay.listen_port
                    try:
                        new_session.set_proxy(rh, rp, True)
                        self.add_log("INFO", f"Re-applied socket redirect to PID {self.pid}: "
                                             f"device -> {rh}:{rp} (relay) -> "
                                             f"{self.relay.upstream_host}:{self.relay.upstream_port}")
                    except Exception as e:
                        self.add_log("WARN", f"Could not re-apply socket redirect: {e}")

            except Exception as e:
                if expected_generation is None or expected_generation == self._switch_generation:
                    self.status = f"Connection Failed: {e}"
                    self.add_log("ERROR", f"Frida connection failed: {e}")
                    self.add_log("WARN", "Make sure your iOS device is connected via USB with frida-server running.")

    def get_available_targets(self, force_refresh: bool = False) -> List[Dict[str, Any]]:
        """List running applications and installed apps with TTL caching to avoid blocking UI."""
        if self.mock_mode:
            return [
                {"name": "MyTelkomsel", "identifier": "telkomsel.mytelkomsel-dev", "pid": 13813, "isRunning": True, "type": "app"},
                {"name": "AcmeBank", "identifier": "com.acme.bankapp", "pid": 4912, "isRunning": True, "type": "app"},
                {"name": "Safari", "identifier": "com.apple.mobilesafari", "pid": 1204, "isRunning": True, "type": "app"},
                {"name": "Settings", "identifier": "com.apple.Preferences", "pid": None, "isRunning": False, "type": "app"},
                {"name": "App Store", "identifier": "com.apple.AppStore", "pid": None, "isRunning": False, "type": "app"},
                {"name": "Health", "identifier": "com.apple.Health", "pid": None, "isRunning": False, "type": "app"},
                {"name": "DemoApp", "identifier": "com.iosuite.demo", "pid": None, "isRunning": False, "type": "app"},
            ]

        with self._targets_cache_lock:
            now = time.time()
            if not force_refresh and self._targets_cache and (now - self._targets_cache_time < 8.0):
                return self._targets_cache

            targets: List[Dict[str, Any]] = []
            try:
                import frida
                if self.device_id:
                    dev = frida.get_device(self.device_id)
                elif self.use_usb:
                    dev = frida.get_usb_device(timeout=3)
                else:
                    dev = frida.get_local_device()

                # Enumerate installed applications
                try:
                    apps = dev.enumerate_applications()
                except Exception:
                    apps = []

                # Enumerate running processes
                try:
                    procs = dev.enumerate_processes()
                except Exception:
                    procs = []

                seen_ids = set()
                for a in apps:
                    pid = getattr(a, "pid", None)
                    if pid == 0:
                        pid = None
                    is_running = pid is not None and pid > 0
                    targets.append({
                        "name": a.name or a.identifier,
                        "identifier": a.identifier,
                        "pid": pid,
                        "isRunning": is_running,
                        "type": "app",
                    })
                    seen_ids.add(a.identifier.lower())
                    if a.name:
                        seen_ids.add(a.name.lower())

                # Also add running processes that might not have matched an installed app
                for p in procs:
                    if p.name.lower() not in seen_ids and p.pid != 0:
                        targets.append({
                            "name": p.name,
                            "identifier": p.name,
                            "pid": p.pid,
                            "isRunning": True,
                            "type": "process",
                        })

                # Sort priority:
                # 1. Running GUI Apps
                # 2. Installed GUI Apps
                # 3. Running processes (daemons)
                def sort_key(x):
                    is_app = x.get("type") == "app"
                    is_run = bool(x.get("isRunning"))
                    priority = 0 if (is_app and is_run) else (1 if is_app else 2)
                    return (priority, str(x.get("name", "")).lower())

                targets.sort(key=sort_key)
                self._targets_cache = targets
                self._targets_cache_time = now
            except Exception as e:
                self.add_log("WARN", f"Failed to enumerate applications: {e}")
                if self._targets_cache:
                    return self._targets_cache
                if self.target and self.target != "auto":
                    targets.append({
                        "name": str(self.target),
                        "identifier": str(self.target),
                        "pid": self.pid,
                        "isRunning": self.pid is not None,
                        "type": "app",
                    })

            return targets

    def switch_target(self, new_target: str, spawn: bool = False) -> Dict[str, Any]:
        """Switch active interception to a different application or PID."""
        self.add_log("INFO", f"Switching target to '{new_target}' (spawn={spawn})...")

        # 1. Increment generation counter to cancel any in-flight connection thread
        self._switch_generation += 1
        current_gen = self._switch_generation

        # 2. Detach existing session safely
        if self.session:
            old_sess = self.session
            self.session = None
            try:
                threading.Thread(target=old_sess.detach, daemon=True).start()
            except Exception as e:
                self.add_log("WARN", f"Error detaching previous session: {e}")

        # 3. Update target parameters
        self.target = new_target
        self.spawn = spawn
        self.pid = None
        self.status = f"Attaching to {new_target}..."
        self.clear_events()

        if self.mock_mode:
            self.pid = 9999 if spawn else 13813
            self.status = f"Attached to PID {self.pid}"
            self.add_log("INFO", f"[Mock] Switched to target {new_target} (PID: {self.pid})")
            return {"status": "ok", "target": self.target, "pid": self.pid}

        # 4. Connect to new target in background thread with generation check
        threading.Thread(target=self._connect_real_session, args=(current_gen,), daemon=True).start()
        return {"status": "ok", "target": self.target, "message": "Connecting..."}

    def invoke_handler(self, target_ptr: str, selector: str, sender_ptr: str = "0x0") -> Dict[str, Any]:
        """Invoke or replay handler via Frida RPC."""
        if self.session:
            res = self.session.invoke_handler(target_ptr, selector, sender_ptr)
            self.add_log("INFO" if res.get("success") else "ERROR", f"Replay -[{target_ptr} {selector}]: {res.get('message', 'Done')}")
            return res
        elif self.mock_mode:
            self.add_log("INFO", f"[Mock Replay] Simulated replay on -[{target_ptr} {selector}]")
            return {"success": True, "message": "Simulated replay in mock mode"}
        return {"success": False, "message": "No active Frida session connected"}

    def read_memory_hex(self, addr_str: str, size: int = 64) -> Dict[str, Any]:
        """Read bytes directly from process memory via Frida RPC."""
        if self.session:
            return self.session.read_memory_hex(addr_str, size)
        elif self.mock_mode:
            base_int = int(addr_str, 16) if addr_str.startswith("0x") else 0x104A1B240
            rows = []
            sample_bytes = [
                0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                0x1B, 0x00, 0x00, 0x00, 0x58, 0x05, 0x00, 0x00,
                0x85, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
            for i in range(0, min(size, 64), 16):
                chunk = sample_bytes[i:i+16]
                bytes_hex = [f"{b:02X}" for b in chunk]
                ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                rows.append({
                    "offset": f"0x{base_int + i:08X}",
                    "bytes": bytes_hex,
                    "ascii": ascii_str
                })
            return {"success": True, "address": addr_str, "size": size, "rows": rows}
        return {"success": False, "error": "No active device session"}

    def enumerate_classes(self, query: str = "") -> Dict[str, Any]:
        """Enumerate runtime classes matching query."""
        if self.session:
            return self.session.enumerate_classes(query)
        elif self.mock_mode:
            sample_classes = [
                "LoginViewController", "PaymentService", "AccountManager",
                "SecurityTokenHandler", "LAContext", "NSURLSession", "AppDelegate"
            ]
            q = query.lower()
            filtered = [c for c in sample_classes if not q or q in c.lower()]
            return {"success": True, "total": len(filtered), "classes": filtered}
        return {"success": False, "error": "No active device session", "classes": []}

    def enumerate_methods(self, class_name: str) -> Dict[str, Any]:
        """Enumerate method selectors and implementations for a class."""
        if self.session:
            return self.session.enumerate_methods(class_name)
        elif self.mock_mode:
            return {
                "success": True,
                "className": class_name,
                "total": 3,
                "methods": [
                    {"selector": "init", "implementation": "0x104A1A000"},
                    {"selector": "handleAuthentication:", "implementation": "0x104A1B240"},
                    {"selector": "validateToken:", "implementation": "0x104A1C500"}
                ]
            }
        return {"success": False, "error": "No active device session", "methods": []}

    def eval_js(self, code: str) -> Dict[str, Any]:
        """Execute arbitrary JavaScript in the Frida agent context."""
        if self.session:
            return self.session.eval_js(code)
        elif self.mock_mode:
            return {"success": True, "result": f"[Mock Eval] Executed: {code}"}
        return {"success": False, "error": "No active device session"}

    def set_bypass(self, feature: str, enabled: bool) -> Dict[str, Any]:
        """Toggle security assistant bypass."""
        if self.session:
            res = self.session.set_bypass(feature, enabled)
            self.add_log("INFO", f"Security Bypass '{feature}' set to {enabled}")
            return res
        elif self.mock_mode:
            self.add_log("INFO", f"[Mock] Security Bypass '{feature}' set to {enabled}")
            return {"success": True, "feature": feature, "state": enabled}
        return {"success": False, "error": "No active device session"}

    def get_bypasses(self) -> Dict[str, Any]:
        """Get bypass status."""
        if self.session:
            return self.session.get_bypasses()
        elif self.mock_mode:
            return {"success": True, "bypasses": {"sslPinning": False, "jailbreak": False}}
        return {"success": False, "bypasses": {"sslPinning": False, "jailbreak": False}}

    def set_proxy(self, host: str, port: int, enabled: bool) -> Dict[str, Any]:
        """Configure socket redirection to Burp *through* the transparent relay.

        The injected redirect is protocol-blind: it rewrites a :443 socket's
        destination with no CONNECT preposition, which Burp's listener cannot
        parse (proven: raw TLS to a Burp proxy port times out). So the device is
        pointed at a local relay instead, and the relay re-frames the stream as
        `CONNECT host:443` / absolute-form HTTP toward Burp.

        `host:port` below is the **Burp listener**. The device redirect target is
        the returned `redirect.host:redirect.port`.
        """
        port = int(port or 1337)
        self._proxy_upstream = {"host": host, "port": port, "enabled": bool(enabled)}

        if not enabled:
            self._stop_relay()
            if self.session:
                res = self.session.set_proxy(host, port, False)
            elif self.mock_mode:
                res = {"success": True}
            else:
                res = {"success": False, "error": "No active device session"}
            self.add_log("INFO", f"Socket redirect disabled (Burp upstream {host}:{port})")
            return {
                "success": bool(res.get("success")),
                "host": host,
                "port": port,
                "enabled": False,
                "relay": None,
                "redirect": None,
                "error": res.get("error"),
            }

        relay_res = self._ensure_relay(host, port)
        if not relay_res.get("success"):
            self.add_log("ERROR", f"Relay could not start: {relay_res.get('error')}")
            return {"success": False, "host": host, "port": port, "enabled": False,
                    "error": relay_res.get("error"), "relay": None, "redirect": None}

        redirect_host = relay_res["advertisedHost"]
        redirect_port = relay_res["port"]

        if self.session:
            res = self.session.set_proxy(redirect_host, redirect_port, True)
        elif self.mock_mode:
            res = {"success": True}
        else:
            # Relay is live; the redirect is applied automatically once a
            # session attaches (see _connect_real_session).
            res = {"success": True, "pending": True,
                   "message": "Relay started; redirect will apply when a session attaches"}
        applied = bool(res.get("success"))

        self.add_log(
            "INFO" if applied else "WARN",
            f"Socket redirect {'enabled' if applied else 'pending'}: "
            f"device -> {redirect_host}:{redirect_port} (relay) -> Burp {host}:{port}"
        )
        return {
            "success": applied,
            "host": host,
            "port": port,
            "enabled": applied,
            "pending": bool(res.get("pending", False)),
            "error": res.get("error"),
            "redirect": {"host": redirect_host, "port": redirect_port},
            "relay": self.relay.status() if self.relay else None,
        }

    def get_proxy(self) -> Dict[str, Any]:
        """Get socket proxy configuration plus live relay status."""
        relay_status = self.relay.status() if self.relay else None
        upstream = dict(self._proxy_upstream)
        base = {
            "success": True,
            "host": upstream.get("host", "192.168.50.216"),
            "port": int(upstream.get("port", 1337)),
            "enabled": bool(upstream.get("enabled", False)),
            "relay": relay_status,
            "redirect": (
                {
                    "host": relay_status.get("listenHostAdvertised") or relay_status["listenHost"],
                    "port": relay_status["listenPort"],
                }
                if relay_status and relay_status.get("running") else None
            ),
        }
        if self.session:
            try:
                dev = self.session.get_proxy() or {}
                base["device"] = dev
                # If the orchestrator never configured a proxy, surface whatever
                # the injected agent currently has so the UI reflects reality.
                if not upstream.get("enabled") and dev.get("host") and dev.get("port"):
                    base["deviceHost"] = dev["host"]
                    base["devicePort"] = int(dev["port"])
                    base["deviceEnabled"] = bool(dev.get("enabled", False))
            except Exception as e:
                base["error"] = str(e)
        return base

    # ---- transparent relay helpers -------------------------------------
    @staticmethod
    def _is_local_address(addr: str) -> bool:
        """True when `addr` is bound to one of this machine's interfaces."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.bind((addr, 0))
                return True
            finally:
                s.close()
        except OSError:
            return False

    def _detect_lan_ip(self, preferred: Optional[str] = None) -> str:
        """Pick the address the iPhone should use to reach this machine.

        If the Burp host is one of our own interfaces (the common single-machine
        setup) it is already device-reachable. Otherwise ask the routing table
        which local address reaches that host.
        """
        if preferred and self._is_local_address(preferred):
            return preferred
        probe = preferred or "8.8.8.8"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect((probe, 9))  # no packets are sent for UDP connect
                addr = s.getsockname()[0]
                if addr and not addr.startswith("127."):
                    return addr
            finally:
                s.close()
        except OSError:
            pass
        return preferred or "127.0.0.1"

    def _ensure_relay(self, burp_host: str, burp_port: int) -> Dict[str, Any]:
        """Start (or reuse) the relay in front of the configured Burp listener."""
        advertised = self._detect_lan_ip(burp_host)
        if self.relay and self.relay.running:
            if (self.relay.upstream_host, self.relay.upstream_port) == (burp_host, burp_port):
                return {"success": True, "port": self.relay.listen_port,
                        "advertisedHost": advertised}
            self._stop_relay()

        # Prefer a port adjacent to Burp's so the UI stays predictable.
        candidates = [burp_port + 1, burp_port + 2, 0]
        last_err = None
        for cand in candidates:
            relay = TransparentProxyRelay(
                upstream_host=burp_host,
                upstream_port=burp_port,
                listen_host="0.0.0.0",
                listen_port=cand,
                log=self.add_log,
            )
            res = relay.start()
            if res.get("success"):
                relay.listen_host_advertised = advertised
                self.relay = relay
                return {"success": True, "port": relay.listen_port,
                        "advertisedHost": advertised}
            last_err = res.get("error")
            # Try every candidate regardless of wording: the bind-error message
            # varies by OS ("address already in use" vs "Only one usage ..."),
            # so don't gate retries on a substring match. A distinct free port
            # may be the next candidate, and 0 always resolves to ephemeral.
        return {"success": False, "error": last_err or "relay failed to start"}

    def _stop_relay(self) -> None:
        if self.relay:
            try:
                self.relay.stop()
            except Exception:
                pass
            self.relay = None

    def relaunch_target(self) -> Dict[str, Any]:
        """Cleanly re-spawns current target application so early BoringSSL and TLS hooks attach before main()."""
        curr = self.target
        self.add_log("INFO", f"Triggering clean early spawn for '{curr}' to activate SSL pinning bypass at startup...")
        return self.switch_target(curr, spawn=True)

    def export_hook(self, target_class: str, selector: str, implementation: str) -> Dict[str, Any]:
        """Generate standalone standalone Frida hook script."""
        code = f"""/**
 * iOSuite Standalone Frida Hook Script
 * Target: {target_class}
 * Selector: -[{target_class} {selector}]
 * Implementation Address: {implementation}
 * Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}
 */

(function () {{
    console.log("[*] iOSuite Hook initialized for {target_class} -> {selector}");

    var targetImpl = ptr("{implementation}");
    if (!targetImpl || targetImpl.isNull() || targetImpl.toString() === "0x0") {{
        if (ObjC.available) {{
            var cls = ObjC.classes["{target_class}"];
            if (cls && cls["{selector}"]) {{
                targetImpl = cls["{selector}"].implementation;
            }}
        }}
    }}

    if (!targetImpl || targetImpl.isNull() || targetImpl.toString() === "0x0") {{
        console.error("[-] Could not resolve target implementation address for {selector}");
        return;
    }}

    console.log("[+] Hook attached at " + targetImpl.toString());
    Interceptor.attach(targetImpl, {{
        onEnter: function (args) {{
            console.log("\\n=======================================================");
            console.log("[+] TRIGGERED: -[{target_class} {selector}]");
            console.log("    Self:   " + args[0]);
            console.log("    _cmd:   " + args[1]);
            console.log("    Arg2:   " + args[2]);
            console.log("    Arg3:   " + args[3]);
            console.log("    Caller: " + this.returnAddress);
            try {{
                var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                console.log("    Backtrace:");
                for (var i = 0; i < bt.length; i++) {{
                    console.log("      " + DebugSymbol.fromAddress(bt[i]));
                }}
            }} catch (e) {{}}
            console.log("=======================================================\\n");
        }},
        onLeave: function (retval) {{
            console.log("[*] Return value from {selector}: " + retval);
            // Example modification:
            // retval.replace(ptr(1));
        }}
    }});
}})();
"""
        clean_sel = selector.replace(':', '_')
        filename = f"hook_{target_class}_{clean_sel}.js"
        return {"success": True, "filename": filename, "script": code}

    def start_server(self) -> str:
        """Start local HTTP server daemon and return the listening URL."""
        orchestrator = self

        def handler_factory(*args, **kwargs):
            return iOSuiteWebviewHandler(*args, orchestrator=orchestrator, **kwargs)

        self.server = ThreadingHTTPServer(("127.0.0.1", self.port), handler_factory)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        self._running = True

        # Start disassembler sync bridge
        self.bridge = DisassemblerBridge()
        self.bridge.start()

        # Start session (real Frida or mock)
        if self.mock_mode:
            self.mock_gen = MockSessionGenerator(on_event=self._on_raw_event)
            self.mock_gen.start_sync()
            self.add_log("INFO", "Running in Mock Demonstration Mode")
        else:
            threading.Thread(target=self._connect_real_session, daemon=True).start()

        return f"http://127.0.0.1:{self.port}"

    def get_events(self) -> List[Dict[str, Any]]:
        return self.events

    def add_event(self, event_dict: Dict[str, Any]):
        self.events.append(event_dict)


    def launch(self, block: bool = True):
        """
        Launch desktop UI window using the best available frontend driver:
        1. pywebview (native embedded window)
        2. Microsoft Edge / Google Chrome app-mode (frameless desktop window)
        3. Default OS browser

        When block=True, keeps the Python process and local HTTP daemon alive
        until the window is closed or interrupted with Ctrl+C.
        """
        url = self.start_server()

        # Try pywebview if installed
        try:
            import webview
            webview.create_window(
                title=f"iOSuite - {self.target} (Reverse Engineering Studio)",
                url=url,
                width=1400,
                height=900,
                min_size=(1024, 700),
                background_color="#07080b",
            )
            webview.start()
            self.stop()
            return
        except ImportError:
            pass

        # Try launching Edge or Chrome in standalone App Mode
        launched_app = False
        app_proc: Optional[subprocess.Popen] = None
        temp_profile = Path(tempfile.gettempdir()) / "iosuite_edge_profile"

        if sys.platform == "win32":
            edge_paths = [
                os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
                os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
            ]
            for edge_bin in edge_paths:
                if os.path.exists(edge_bin):
                    app_proc = subprocess.Popen([
                        edge_bin,
                        f"--app={url}",
                        f"--user-data-dir={temp_profile}",
                        "--window-size=1400,900",
                        "--no-first-run",
                        "--no-default-browser-check",
                    ])
                    launched_app = True
                    break

        elif sys.platform == "darwin":
            # macOS Chrome app mode
            chrome_app = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
            if os.path.exists(chrome_app):
                app_proc = subprocess.Popen([
                    chrome_app,
                    f"--app={url}",
                    "--window-size=1400,900"
                ])
                launched_app = True

        if not launched_app:
            # Fallback to system default browser
            webbrowser.open(url)

        if block:
            try:
                # If app_proc was started as a separate process, monitor it
                if app_proc:
                    # Give it a short moment to establish
                    time.sleep(1.0)
                    if app_proc.poll() is None:
                        while app_proc.poll() is None and self._running:
                            time.sleep(0.5)
                        self.stop()
                        return

                # If attached to existing browser instance or fallback browser:
                while self._running:
                    time.sleep(0.5)
            except (KeyboardInterrupt, SystemExit):
                pass
            finally:
                self.stop()

    def wait(self):
        """Block until the orchestrator is stopped or interrupted."""
        try:
            while self._running:
                time.sleep(0.5)
        except (KeyboardInterrupt, SystemExit):
            self.stop()

    def stop(self):
        """Clean shutdown."""
        self._running = False
        self._stop_relay()
        if self.bridge:
            self.bridge.stop()
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
            self.server = None
