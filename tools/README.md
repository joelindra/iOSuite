# iOSuite Companion Disassembler Plugins ⚡

This directory contains live synchronization scripts that bridge **iOSuite** with professional reverse-engineering disassemblers (**IDA Pro** and **Ghidra**).

When you inspect a handler or function in iOSuite (via Desktop Webview or Terminal TUI), iOSuite hosts a local HTTP sync bridge on `http://127.0.0.1:1337/jump`. These plugins listen to the bridge and automatically reposition your disassembler's disassembly view to the target's static Mach-O file offset in real-time.

---

## 1. IDA Pro Sync (`ida_iosuite_sync.py`)

### Requirements
- IDA Pro 7.x / 8.x / 9.x with Python 3 support (`ida_kernwin`, `ida_nalt`).
- Target binary (Mach-O executable) loaded in IDA Pro.

### How to Use
1. Open the target application's decrypted Mach-O binary in IDA Pro.
2. In IDA Pro menu:
   - Click **File** -> **Script file...**
   - Select `tools/ida_iosuite_sync.py`
3. Alternatively, in IDA Python console:
   ```python
   import sys
   sys.path.append(r"/path/to/iOSuite/tools")
   import ida_iosuite_sync
   ida_iosuite_sync.start_sync()
   ```
4. Output log:
   ```
   [iOSuite-Sync] Bridge polling active on 127.0.0.1:1337.
   ```
5. Whenever you select an event in iOSuite or press **`c`** to jump, IDA Pro will immediately navigate to the target address (`imagebase + offset`).

---

## 2. Ghidra Sync (`ghidra_iosuite_sync.py`)

### Requirements
- Ghidra 10.x / 11.x (Java / Jython or Ghidra Bridge).
- Target binary loaded in CodeBrowser.

### How to Use
1. Open the decrypted iOS Mach-O binary in Ghidra **CodeBrowser**.
2. Open **Window** -> **Script Manager**.
3. Add the `tools/` folder to the Script Directories list (or click the green "+" icon).
4. Search for `ghidra_iosuite_sync.py` under the **iOSuite** category.
5. Click **Run Script** (Play button).
6. Ghidra console will output:
   ```
   [iOSuite-Sync] Listening to http://127.0.0.1:1337/jump...
   ```
7. When you click an event in iOSuite, Ghidra automatically jumps to the calculated program address.
