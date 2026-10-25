"""
Frida Session & Device Connection Manager
Handles device enumeration, process attaching/spawning, script injection, and RPC.
"""

from typing import List, Dict, Any, Optional, Callable, Tuple
import frida
from iosuite.agent.loader import get_agent_script


class FridaDeviceSession:
    """Manages connection to an iOS device and target process via Frida."""

    def __init__(
        self,
        target: str | int,
        device_id: Optional[str] = None,
        use_usb: bool = True,
        spawn: bool = False,
        remote_host: Optional[str] = None,
    ):
        self.target = target
        self.device_id = device_id
        self.use_usb = use_usb
        self.spawn = spawn
        self.remote_host = remote_host

        self.device: Optional[frida.core.Device] = None
        self.session: Optional[frida.core.Session] = None
        self.script: Optional[frida.core.Script] = None
        self.pid: Optional[int] = None
        self.app_info: Dict[str, Any] = {}
        self._on_event_callback: Optional[Callable[[Dict[str, Any]], None]] = None
        self._on_log_callback: Optional[Callable[[str, str], None]] = None

    @classmethod
    def list_devices(cls) -> List[Dict[str, Any]]:
        """List all available Frida devices."""
        devices = []
        for dev in frida.enumerate_devices():
            devices.append({
                "id": dev.id,
                "name": dev.name,
                "type": dev.type,
            })
        return devices

    @classmethod
    def list_processes(cls, device_id: Optional[str] = None, use_usb: bool = True) -> List[Dict[str, Any]]:
        """List running processes on the selected device."""
        if device_id:
            device = frida.get_device(device_id)
        elif use_usb:
            device = frida.get_usb_device()
        else:
            device = frida.get_local_device()

        processes = []
        for proc in device.enumerate_processes():
            processes.append({
                "pid": proc.pid,
                "name": proc.name,
                "parameters": proc.parameters,
            })
        return processes

    def set_callbacks(
        self,
        on_event: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_log: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self._on_event_callback = on_event
        self._on_log_callback = on_log

    def _log(self, level: str, message: str) -> None:
        if self._on_log_callback:
            try:
                self._on_log_callback(level, message)
            except Exception:
                pass

    def _resolve_target(self) -> Tuple[Optional[int], str, Optional[str]]:
        """
        Intelligently resolves target parameter to:
        (resolved_pid, display_name, bundle_identifier)
        Supports:
          - Numeric PID (e.g. 13458)
          - Process name exact or fuzzy (e.g. 'MyTsel staging', 'Preferences')
          - App name exact or fuzzy (e.g. 'MyTelkomsel', 'MyTsel', 'Settings')
          - Bundle identifier (e.g. 'telkomsel.mytelkomsel-dev', 'com.apple.Preferences')
        """
        raw = str(self.target).strip()
        target_lower = raw.lower()

        # 1. Numeric PID
        if raw.isdigit():
            pid = int(raw)
            proc_name = raw
            bundle_id = None
            if self.device:
                try:
                    for proc in self.device.enumerate_processes():
                        if proc.pid == pid:
                            proc_name = proc.name
                            break
                except Exception:
                    pass
                try:
                    apps_list = self.device.enumerate_applications()
                    if isinstance(apps_list, list):
                        for a in apps_list:
                            if getattr(a, "pid", None) == pid or getattr(a, "name", "").lower() == proc_name.lower():
                                bundle_id = a.identifier
                                break
                except Exception:
                    pass
            return pid, proc_name, bundle_id

        procs: List[Any] = []
        apps: List[Any] = []
        if self.device:
            try:
                p_list = self.device.enumerate_processes()
                if isinstance(p_list, list):
                    procs = p_list
            except Exception:
                pass
            try:
                a_list = self.device.enumerate_applications()
                if isinstance(a_list, list):
                    apps = a_list
            except Exception:
                pass

        # Helper to find bundle_id for a given proc
        def get_bundle_for_proc(p_name: str, p_pid: Optional[int]) -> Optional[str]:
            for a in apps:
                if p_pid and getattr(a, "pid", None) == p_pid:
                    return a.identifier
                if getattr(a, "name", "").lower() == p_name.lower():
                    return a.identifier
                if p_name.lower() in getattr(a, "identifier", "").lower():
                    return a.identifier
            return None

        # 2. Check running processes (exact match)
        for p in procs:
            if p.name.lower() == target_lower:
                return p.pid, p.name, get_bundle_for_proc(p.name, p.pid)

        # 3. Check installed applications (exact bundle ID)
        for a in apps:
            if a.identifier.lower() == target_lower:
                return (a.pid if a.pid > 0 else None), a.name, a.identifier

        # 4. Check installed applications (exact name)
        for a in apps:
            if a.name.lower() == target_lower:
                return (a.pid if a.pid > 0 else None), a.name, a.identifier

        # 5. Fuzzy match in running processes
        for p in procs:
            if target_lower in p.name.lower() or p.name.lower() in target_lower:
                return p.pid, p.name, get_bundle_for_proc(p.name, p.pid)

        # 6. Fuzzy match in installed applications
        for a in apps:
            if target_lower in a.name.lower() or target_lower in a.identifier.lower():
                return (a.pid if a.pid > 0 else None), a.name, a.identifier

        # Fallback
        return None, raw, raw

    def connect(self) -> None:
        """Establish connection, attach/spawn process, and load agent script."""
        # 1. Resolve Device
        if not self.device:
            if self.remote_host:
                self.device = frida.get_device_manager().add_remote_device(self.remote_host)
            elif self.device_id:
                self.device = frida.get_device(self.device_id)
            elif self.use_usb:
                try:
                    self.device = frida.get_usb_device(timeout=5)
                except Exception:
                    # Fallback to local device / simulator if USB not found
                    self.device = frida.get_local_device()
            else:
                self.device = frida.get_local_device()

        # 2. Resolve Target (PID, Name, Bundle ID)
        pid, name, bundle_id = self._resolve_target()

        # 3. Attach or Spawn
        should_spawn = self.spawn or (pid is None and bundle_id is not None)

        if should_spawn:
            bundle_to_spawn = bundle_id or name
            self.pid = self.device.spawn([bundle_to_spawn])
            self.session = self.device.attach(self.pid)

            # Load agent script FIRST before resuming so early lifecycle hooks are caught
            script_code = get_agent_script()
            self.script = self.session.create_script(script_code)
            self.script.on("message", self._handle_frida_message)
            self.script.load()

            # Resume process, gracefully handling Mach kernel (os/kern) failure on Dopamine rootless
            try:
                self.device.resume(self.pid)
            except Exception as e:
                err_msg = str(e).lower()
                if "os/kern" in err_msg or "resume" in err_msg or "already" in err_msg:
                    # Non-fatal: process was already resumed by iOS FrontBoard
                    pass
                else:
                    raise
        else:
            if pid is not None:
                self.pid = pid
            else:
                # Fallback attach by name
                try:
                    self.pid = self.device.get_process(name).pid
                except Exception:
                    self.pid = None

            attach_succeeded = False
            if self.pid is not None:
                try:
                    self.session = self.device.attach(self.pid)
                    script_code = get_agent_script()
                    self.script = self.session.create_script(script_code)
                    self.script.on("message", self._handle_frida_message)
                    self.script.load()
                    attach_succeeded = True
                except Exception as attach_err:
                    err_str = str(attach_err).lower()
                    self._log("warn", f"Direct attach to PID {self.pid} failed: {attach_err}")
                    if not (
                        "os/kern" in err_str
                        or "not supported" in err_str
                        or "resume" in err_str
                        or "unable to find" in err_str
                        or "process not found" in err_str
                        or "closed" in err_str
                        or "timeout" in err_str
                        or "timed out" in err_str
                        or "transport" in err_str
                    ):
                        raise

            if not attach_succeeded:
                # Resolve bundle identifier if missing
                target_bundle = bundle_id
                if not target_bundle and self.device:
                    try:
                        for a in self.device.enumerate_applications():
                            t_low = str(self.target).lower() if self.target else ""
                            n_low = name.lower() if name else ""
                            if (t_low and t_low in a.identifier.lower()) or (t_low and t_low in a.name.lower()) or (n_low and n_low in a.name.lower()):
                                target_bundle = a.identifier
                                break
                    except Exception:
                        pass

                if target_bundle:
                    self._log("info", f"Auto-spawning bundle {target_bundle}...")
                    self.pid = self.device.spawn([target_bundle])
                    self.session = self.device.attach(self.pid)
                    script_code = get_agent_script()
                    self.script = self.session.create_script(script_code)
                    self.script.on("message", self._handle_frida_message)
                    self.script.load()
                    try:
                        self.device.resume(self.pid)
                    except Exception as e:
                        err_msg = str(e).lower()
                        if not ("os/kern" in err_msg or "resume" in err_msg or "already" in err_msg):
                            raise
                else:
                    raise frida.ProcessNotFoundError(f"Unable to attach to or spawn target: {self.target}")

        # 4. Fetch initial App Info via RPC
        try:
            self.app_info = self.script.exports_sync.get_app_info()
        except Exception:
            self.app_info = {
                "bundlePath": "Unknown",
                "executableName": str(self.target),
                "baseAddress": "0x0",
                "arch": "arm64",
            }

    def _handle_frida_message(self, message: Dict[str, Any], data: Any) -> None:
        """Internal callback for messages sent from Frida agent via send()."""
        m_type = message.get("type")
        if m_type == "send":
            payload = message.get("payload", {})
            if isinstance(payload, dict):
                p_type = payload.get("type")
                if p_type == "event" and self._on_event_callback:
                    self._on_event_callback(payload.get("payload", {}))
                elif p_type == "log" and self._on_log_callback:
                    self._on_log_callback(payload.get("level", "info"), payload.get("message", ""))
        elif m_type == "error":
            description = message.get("description", "Unknown Frida error")
            if self._on_log_callback:
                self._on_log_callback("error", description)

    def get_app_info(self) -> Dict[str, Any]:
        """Get application metadata retrieved from agent."""
        return self.app_info

    def invoke_handler(self, target_ptr: str, selector: str, sender_ptr: str = "0x0") -> Dict[str, Any]:
        """Replay an intercepted handler directly on the iOS app's main queue."""
        if not self.script:
            return {"success": False, "message": "No active script session"}
        try:
            return self.script.exports_sync.invoke_handler(target_ptr, selector, sender_ptr)
        except Exception as e:
            return {"success": False, "message": str(e)}

    def read_memory_hex(self, addr_str: str, size: int = 64) -> Dict[str, Any]:
        """Read real bytes from process memory via Frida RPC."""
        if not self.script:
            return {"success": False, "error": "No active Frida session"}
        try:
            return self.script.exports_sync.read_memory_hex(addr_str, size)
        except Exception as e:
            return {"success": False, "error": str(e)}

    def enumerate_classes(self, query: str = "") -> Dict[str, Any]:
        """Enumerate live Objective-C/Swift classes via Frida RPC."""
        if not self.script:
            return {"success": False, "error": "No active Frida session", "classes": []}
        try:
            return self.script.exports_sync.enumerate_classes(query)
        except Exception as e:
            return {"success": False, "error": str(e), "classes": []}

    def enumerate_methods(self, class_name: str) -> Dict[str, Any]:
        """Enumerate methods of a class via Frida RPC."""
        if not self.script:
            return {"success": False, "error": "No active Frida session", "methods": []}
        try:
            return self.script.exports_sync.enumerate_methods(class_name)
        except Exception as e:
            return {"success": False, "error": str(e), "methods": []}

    def eval_js(self, code: str) -> Dict[str, Any]:
        """Evaluate arbitrary JavaScript within the target iOS app context."""
        if not self.script:
            return {"success": False, "error": "No active Frida session"}
        try:
            return self.script.exports_sync.eval_js(code)
        except Exception as e:
            return {"success": False, "error": str(e)}

    def set_bypass(self, feature_name: str, enabled: bool) -> Dict[str, Any]:
        """Toggle security bypass in agent (e.g. sslPinning, jailbreak)."""
        if not self.script:
            return {"success": False, "error": "No active Frida session"}
        try:
            return self.script.exports_sync.set_bypass(feature_name, enabled)
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_bypasses(self) -> Dict[str, Any]:
        """Get current bypass status."""
        if not self.script:
            return {"success": False, "bypasses": {"sslPinning": False, "jailbreak": False}}
        try:
            return self.script.exports_sync.get_bypasses()
        except Exception as e:
            return {"success": False, "bypasses": {"sslPinning": False, "jailbreak": False}}

    def set_proxy(self, host: str, port: int, enabled: bool) -> Dict[str, Any]:
        """Configure in-app socket redirection to proxy."""
        if not self.script:
            return {"success": False, "error": "No active Frida session"}
        try:
            return self.script.exports_sync.set_proxy(host, port, enabled)
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_proxy(self) -> Dict[str, Any]:
        """Get current in-app proxy redirection configuration."""
        if not self.script:
            return {"success": False, "host": "192.168.50.216", "port": 1337, "enabled": False}
        try:
            return self.script.exports_sync.get_proxy()
        except Exception as e:
            return {"success": False, "error": str(e)}

    def set_app_only_filter(self, enabled: bool) -> None:
        if self.script:
            try:
                self.script.exports_sync.set_app_only_filter(enabled)
            except Exception:
                pass

    def detach(self) -> None:
        """Safely unload script and detach from target process."""
        if self.script:
            try:
                self.script.unload()
            except Exception:
                pass
            self.script = None

        if self.session:
            try:
                self.session.detach()
            except Exception:
                pass
            self.session = None
