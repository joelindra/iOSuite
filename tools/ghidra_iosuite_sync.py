# iOSuite Trace Companion Sync Script for Ghidra
# Automatically jumps Ghidra cursor to offsets clicked in iOSuite TUI.
# @category iOSuite
# @author iOSuite Team

import json
import urllib2
import time
from ghidra.app.script import GhidraScript


class GhidraIOSuiteSync(GhidraScript):
    def run(self):
        print("[iOSuite-Sync] Listening to http://127.0.0.1:1337/jump...")
        last_offset = None
        base_addr = currentProgram.getImageBase().getOffset()

        while not monitor.isCancelled():
            try:
                req = urllib2.Request("http://127.0.0.1:1337/jump")
                resp = urllib2.urlopen(req, timeout=1)
                data = json.loads(resp.read())
                if data.get("action") == "jump":
                    offset_str = data.get("offset")
                    if offset_str and offset_str != last_offset:
                        last_offset = offset_str
                        offset_int = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
                        target_addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(base_addr + offset_int)
                        goTo(target_addr)
                        println("[iOSuite-Sync] Jumped to: " + str(target_addr) + " (" + str(data.get("symbol")) + ")")
            except Exception:
                pass
            time.sleep(0.5)


if __name__ == "__main__":
    GhidraIOSuiteSync().run()
