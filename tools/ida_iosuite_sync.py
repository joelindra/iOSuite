"""
iOSuite Trace Companion Sync Plugin for IDA Pro
Syncs IDA Pro cursor with live handler selections in the iOSuite Trace TUI.

Usage:
    File -> Script file... -> select ida_iosuite_sync.py
    Or run in IDA Python console:
        import ida_iosuite_sync; ida_iosuite_sync.start_sync()
"""

import json
import urllib.request
import ida_kernwin
import ida_nalt

_SYNC_TIMER = None
_LAST_SEEN_OFFSET = None


def _poll_iosuite_jump():
    global _LAST_SEEN_OFFSET
    try:
        url = "http://127.0.0.1:1337/jump"
        req = urllib.request.Request(url, headers={"User-Agent": "IDA-iOSuite-Sync"})
        with urllib.request.urlopen(req, timeout=0.3) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                if data.get("action") == "jump":
                    offset_str = data.get("offset", "0x0")
                    if offset_str and offset_str != _LAST_SEEN_OFFSET:
                        _LAST_SEEN_OFFSET = offset_str
                        offset_int = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
                        image_base = ida_nalt.get_imagebase()
                        target_ea = image_base + offset_int
                        print(f"[iOSuite-Sync] Jumping to offset {offset_str} (EA: 0x{target_ea:X}) - {data.get('symbol', '')}")
                        ida_kernwin.jumpto(target_ea)
    except Exception:
        pass
    return 500  # Poll every 500ms


def start_sync():
    """Start timer hook polling iOSuite disassembler bridge."""
    global _SYNC_TIMER
    if _SYNC_TIMER is not None:
        ida_kernwin.unregister_timer(_SYNC_TIMER)
    _SYNC_TIMER = ida_kernwin.register_timer(500, _poll_iosuite_jump)
    print("[iOSuite-Sync] Bridge polling active on 127.0.0.1:1337.")


def stop_sync():
    """Stop synchronization timer."""
    global _SYNC_TIMER
    if _SYNC_TIMER is not None:
        ida_kernwin.unregister_timer(_SYNC_TIMER)
        _SYNC_TIMER = None
        print("[iOSuite-Sync] Bridge polling stopped.")


if __name__ == "__main__":
    start_sync()
