# iOSuite ⚡

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white)
![Frida Version](https://img.shields.io/badge/frida-16.0%2B-red.svg?style=for-the-badge&logo=frida&logoColor=white)
![Platform](https://img.shields.io/badge/platform-iOS%20%7C%20macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)
![Tests](https://img.shields.io/badge/tests-33%20passed-success.svg?style=for-the-badge)

**Dynamic iOS Feature & Handler Interception Studio with Interactive Desktop Webview & Terminal TUI**

*Bridge the gap between live iOS application interactions and static binary analysis in IDA Pro, Ghidra, and Hopper in real-time.*

[Key Features](#-key-features) • [Quick Start](#-quick-start) • [Architecture](#-architecture) • [Disassembler Sync](#-disassembler-companion-sync) • [CLI Reference](#-cli-reference) • [Keyboard Shortcuts](#-keyboard-shortcuts) • [Testing](#-testing)

</div>

---

## 📖 Overview

**iOSuite** is a professional-grade dynamic reverse-engineering and security analysis studio for iOS applications. Powered by **Frida**, it automatically hooks and traces every user interface action, gesture, navigation transition, deep link, WebKit script message, and network trigger as you interact with an iOS device.

Whenever a button is tapped or a screen is opened, iOSuite instantly resolves:
- **Mach-O Static File Offset**: Exact position in the decrypted binary on disk ($\text{Offset} = \text{Address} - \text{Base}$).
- **Symbol Demangling**: Swift mangled symbols (`$s...` / `_$s...`) demangled into readable class, method, and closure signatures.
- **Accurate Call Stack**: Multi-frame backtrace distinguishing target application code (`[APP]`) from system libraries (`[SYS]`).
- **Live Disassembly**: Contextual ARM64 assembly instructions around the execution target via Capstone.
- **Bi-directional Live Sync**: Auto-jump cursor in **IDA Pro** or **Ghidra** to the corresponding code offset via a local HTTP bridge.
- **Main Thread Replay**: Re-trigger any intercepted handler on the device using Frida RPC without touching the screen.
- **Standalone Hook Generator**: Export one-click standalone Frida JavaScript hooks for any intercepted method.

iOSuite provides two distinct user interfaces:
1. **Desktop Webview Studio**: Modern, high-performance GUI using native OS WebView2 / App-Mode + Petite-Vue (zero build steps, ~40MB idle RAM).
2. **Terminal TUI**: Keyboard-driven terminal interface powered by Textual & Rich, ideal for SSH and headless environments.

---

## ⚡ Quick Start

### Prerequisites
- **Python 3.10+**
- A jailbroken iOS device connected via USB with `frida-server` running, or Corellium / iOS Simulator.
- *(Optional)* No physical device? Use **Mock Mode (`--mock`)** to simulate live events.

### Installation

```bash
# Clone repository
git clone https://github.com/your-username/iOSuite.git
cd iOSuite

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies in editable mode
pip install -e .
```

### Launching iOSuite

```bash
# 1. Desktop Webview Studio (Default Production Launcher)
# Automatically detects USB device and active frontmost application:
python main.py

# 2. Attach to a specific app by Name, PID, or Bundle ID:
python main.py MyBankingApp
python main.py com.apple.mobilesafari

# 3. Spawn application from cold start:
python main.py com.example.app --spawn

# 4. Interactive Terminal TUI Mode (Headless / Remote SSH):
python main.py MyBankingApp --tui

# 5. Offline Simulation Mode (Demo without physical device):
python main.py --mock
```

---

## 🖥️ User Interfaces

### 1. Desktop Webview Studio (`python main.py` or `iosuite gui`)

Ultra-lightweight desktop GUI running via Python HTTP micro-daemon and the native OS Webview (Edge WebView2 on Windows, WebKit on macOS, Chromium app-mode on Linux).

- **Zero Build Toolchain**: No Node.js, npm, or Rust toolchains required.
- **Ultra-low Memory Footprint**: ~40MB idle RAM (85% lighter than Electron).
- **Interactive Tabs**:
  - **Overview**: Target class, selector, implementation pointer, Mach-O module, base address, static file offset, ASLR slide.
  - **Backtrace**: Full call stack with visual `[APP]` vs `[SYS]` frame separation.
  - **Arguments & Sender**: Detailed sender info, view hierarchy, tags, titles, and payload dictionaries.
  - **Disassembly**: Syntax-highlighted ARM64 instructions around the target method pointer.
  - **Memory Hex**: Live hex and ASCII inspector for ARM64 memory pages directly from the device.
  - **In-App Frida REPL**: Execute arbitrary Frida JavaScript commands inside the target process context (`/api/eval`).
- **Security Assistant**: Real-time one-click toggles for **SSL Pinning Bypass** (`SecTrustEvaluateWithError`) and **Jailbreak Detection Bypass**.
- **Runtime Explorer**: Live class search and method enumeration (`class_copyMethodList`).

---

### 2. Terminal TUI Mode (`python main.py --tui` or `iosuite trace`)

Built with **Textual** and **Rich** for terminals and remote SSH sessions.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ [iOSuite Trace] Target: MobileBank (PID: 14201) | Device: iPhone (USB) | [● REC]       │
├──────────────────────────────────┬─────────────────────────────────────────────────────┤
│ 🔍 Filter: [checkout           ] │ [1: Overview] [2: Backtrace] [3: Args] [4: Disasm]  │
├──────────────────────────────────┼─────────────────────────────────────────────────────┤
│ 14:02:10 [UI Action] (x1)        │  HANDLER LOCATION & BINARY METADATA                 │
│   UIButton -> onPayButtonTapped: │  Target Class:        CheckoutViewController        │
│   App.CheckoutViewController     │  Selector / Method:   -[onPayButtonTapped:]         │
│                                  │  Implementation (PC): 0x0000000104A1B240            │
│ 14:02:11 [SwiftUI]               │  Mach-O Module:       MobileBank.app/MobileBank     │
│   QuickTransferCardView          │  Base Address:        0x0000000104800000            │
│   App.QuickTransferCardView      │  Mach-O File Offset:  0x0021B240 (Slide: 0x10480000)│
│                                  │                                                     │
│ 14:02:13 [Navigation]            │  DISASSEMBLER QUICK-JUMP (Press 'c' to copy)        │
│   Push Nav -> PaymentConfirmVC   │  IDA Pro:  ida_kernwin.jumpto(get_imagebase()+0x21B)│
│                                  │  Ghidra:   toAddr(0x21B240)                         │
│ 14:02:15 [WebKit]                │  Hopper:   s 0x21B240                               │
│   bridge: "nativePayToken"       │                                                     │
│   body: {"amount": 250000}       │  SENDER CONTEXT                                     │
│                                  │  Class:    UIButton ("Pay Now")                     │
│ 14:02:16 [Network]               │  Tag:      101 | ID: "btn_pay_checkout"             │
│   POST /v2/transactions/pay      │  View Hierarchy: Window -> TabBar -> Nav -> PayBtn  │
├──────────────────────────────────┴─────────────────────────────────────────────────────┤
│ [F1] Help | [F2] Pause/Resume | [/] Filter | [r] Replay | [g] Gen Script | [F5] Export │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Key Features

### 1. Comprehensive Dynamic Interception
- **UIKit Target-Action**: Hooks `-[UIApplication sendAction:to:from:forEvent:]` and `-[UIControl sendAction:to:forEvent:]` to capture button taps, switches, sliders, text fields, and segmented controls.
- **SwiftUI Support**: Intercepts internal gesture recognizers on `_UIHostingView` / `UIHostingController` and closure dispatches.
- **View Lifecycle & Navigation**: Captures `-[UIViewController viewDidAppear:]`, modal presentations (`presentViewController:animated:completion:`), and navigation pushes (`pushViewController:animated:`).
- **Deep Links & Universal Links**: Intercepts `-[UIApplication openURL:options:completionHandler:]` and scene open operations.
- **WebKit JavaScript Bridges**: Intercepts hybrid bridge calls (`userContentController:didReceiveScriptMessage:`).
- **Network Request Triggers**: Correlates user interaction with outgoing `NSURLSession` tasks.

### 2. Hardened App & Anti-Debug Resilience
- Employs **direct method implementation hooking** and fallback to the native `libobjc` ABI (`class_getMethodImplementation`, `sel_registerName`).
- Bypasses mass memory scans (`ApiResolver('objc')`) that commonly trigger integrity watchdogs or anti-cheat detections in hardened applications (e.g., banking apps, gaming titles, social platforms).

### 3. Static Binary Offset Resolver
- Automatically maps virtual memory execution pointers (`PC`) back to the static file offset on disk:
  $$\text{File Offset} = \text{Address} - \text{Module Base}$$
- Formats ready-to-use jump commands for:
  - **IDA Pro**: `ida_kernwin.jumpto(get_imagebase() + 0x<offset>)`
  - **Ghidra**: `goTo(toAddr(0x<offset>))`
  - **Hopper**: `s 0x<offset>`
  - **Binary Ninja**: `bv.navigate(bv.view, bv.start + 0x<offset>)`
  - **Radare2 / Rizin**: `s 0x<offset>`

### 4. Interactive Control & RPC Replay
- **Replay Handler (`r`)**: Execute the intercepted selector directly from the terminal or GUI via `objc_msgSend` on the iOS main thread.
- **Generate Standalone Script (`g`)**: Export an isolated, self-contained Frida JavaScript script template ready for independent debugging.
- **Noise Reduction ("App-Only")**: Filter out background iOS system calls so only application handlers appear.
- **Session Export (`F5`)**: Save full interception traces to structured Markdown and JSON reports.

---

## 🔌 Disassembler Companion Sync

iOSuite features a live synchronization bridge hosted on `http://127.0.0.1:1337/jump`. When you select any event in iOSuite, your disassembler automatically navigates to that function's file offset.

Companion plugins are included in the `tools/` folder:

### IDA Pro Integration
1. Open the target binary in IDA Pro.
2. In IDA, go to **File** -> **Script file...** and select `tools/ida_iosuite_sync.py`.
3. IDA will start polling the bridge every 500ms and jump whenever an event is selected in iOSuite.

### Ghidra Integration
1. Open the binary in Ghidra **CodeBrowser**.
2. Open **Window** -> **Script Manager**.
3. Add the `tools/` directory and run `ghidra_iosuite_sync.py`.
4. Ghidra's cursor will automatically follow your actions in iOSuite.

See [tools/README.md](tools/README.md) for full setup instructions.

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Description |
| :--- | :--- |
| **Up / Down** | Navigate handler events list |
| **1 / 2 / 3 / 4** | Switch detail tabs (Overview, Backtrace, Arguments, Disassembly) |
| **`/`** | Focus filter / search bar |
| **Esc** | Clear filter / return focus to event list |
| **F2** | Pause / Resume live event recording |
| **F3** | Clear event list |
| **r** | Replay selected handler on iOS main thread |
| **g** | Generate standalone Frida hook script (`hook_<Target>_<Selector>.js`) |
| **c** | Copy disassembler jump commands to clipboard |
| **F5** | Export session trace to Markdown & JSON |
| **F1** | Open interactive help modal |
| **q** | Safely detach and exit |

---

## 🛠️ CLI Reference

iOSuite provides a Typer-powered CLI interface via `iosuite` (or `python -m iosuite.cli`):

```bash
# Launch Desktop Webview Studio (Default GUI)
iosuite gui [TARGET] [-u] [-s] [-m]

# Launch Terminal TUI
iosuite trace [TARGET] [-u] [-s] [-m]

# List connected USB and remote Frida devices
iosuite devices

# List running processes on connected iOS device
iosuite ps [-u] [-d DEVICE_ID]

# Show version
iosuite version
```

### Options:
- `-u, --usb`: Connect to physical iOS device over USB (default: true).
- `-d, --device <ID>`: Specify a specific Frida device ID.
- `-s, --spawn`: Spawn application from cold start instead of attaching to running process.
- `-m, --mock`: Offline simulation mode using synthetic events.
- `-w, --webview`: Launch desktop webview from the trace command.

---

## 🏛️ Architecture

```
                          ┌─────────────────────────────────────┐
                          │         Target iOS Process          │
                          │   (UIKit / SwiftUI / WebKit / Net)  │
                          └──────────────────┬──────────────────┘
                                             │ Frida Agent Injection
                                             ▼
                          ┌─────────────────────────────────────┐
                          │      iosuite/agent/scripts/agent.js │
                          │  (Direct libobjc Hooks & Demangler) │
                          └──────────────────┬──────────────────┘
                                             │ JSON IPC Messages
                                             ▼
                          ┌─────────────────────────────────────┐
                          │     FridaDeviceSession (Python)     │
                          └──────────────────┬──────────────────┘
                                             │ Dispatched Events
                   ┌─────────────────────────┴─────────────────────────┐
                   ▼                                                   ▼
┌──────────────────────────────────────┐            ┌──────────────────────────────────────┐
│       Desktop Webview Studio         │            │             Terminal TUI             │
│ (HTTP Micro-daemon + SSE + Vue SPA)  │            │     (Textual + Rich Split Pane)      │
└──────────────────┬───────────────────┘            └──────────────────┬───────────────────┘
                   │                                                   │
                   └─────────────────────────┬─────────────────────────┘
                                             │ HTTP Jump Notifications
                                             ▼
                          ┌─────────────────────────────────────┐
                          │    Sync Bridge (127.0.0.1:1337)     │
                          ├──────────────────┬──────────────────┤
                          │                  │                  │
                          ▼                  ▼                  ▼
                    ┌───────────┐      ┌───────────┐      ┌───────────┐
                    │  IDA Pro  │      │  Ghidra   │      │  Hopper   │
                    └───────────┘      └───────────┘      └───────────┘
```

---

## 🧪 Testing

iOSuite includes a test suite covering the event dispatcher, demangler, disassembler, resolver, HTTP bridge, exporter, CLI entrypoints, and mock TUI.

Run all tests:
```bash
python -m pytest tests/
```

Results:
```
============================= 33 passed in 15.00s =============================
```

---

## 📁 Repository Structure

```
iOSuite/
├── iosuite/
│   ├── __init__.py           # Package version and metadata
│   ├── app.py                # Textual TUI Application
│   ├── cli.py                # Typer CLI subcommands
│   ├── agent/
│   │   ├── __init__.py
│   │   ├── loader.py         # Frida script injector & loader
│   │   └── scripts/
│   │       └── agent.js      # Core dynamic instrumentation agent
│   ├── core/
│   │   ├── __init__.py
│   │   ├── bridge.py         # HTTP Disassembler Sync Bridge (:1337)
│   │   ├── demangler.py      # Swift symbol demangler
│   │   ├── disasm.py         # Capstone ARM64 disassembler
│   │   ├── dispatcher.py     # Event dispatcher & deduplication
│   │   ├── exporter.py       # Markdown/JSON reporter & hook generator
│   │   ├── mock.py           # Synthetic event generator for testing
│   │   ├── resolver.py       # Mach-O offset calculator & jump formatters
│   │   └── session.py        # Frida session lifecycle manager
│   └── ui/
│       ├── __init__.py
│       ├── dialogs.py        # Textual modal dialogs
│       ├── styles.tcss       # Textual CSS stylesheet
│       ├── webview_app.py    # Desktop Webview Studio orchestrator
│       ├── widgets.py        # Textual custom widgets
│       └── assets/
│           └── index.html    # Single-page Desktop Webview Studio app
├── tests/                    # Automated pytest suite (33 tests)
├── tools/
│   ├── README.md             # Companion scripts guide
│   ├── ida_iosuite_sync.py   # IDA Pro live sync plugin
│   └── ghidra_iosuite_sync.py# Ghidra live sync script
├── main.py                   # Direct production launcher
├── pyproject.toml            # Project packaging specification
├── LICENSE                   # MIT License
└── README.md                 # Project documentation
```

---

## ⚖️ License & Disclaimer

This project is licensed under the [MIT License](LICENSE).

**Disclaimer**: iOSuite is developed for authorized security research, application penetration testing, and educational reverse engineering. Ensure you have proper authorization before analyzing third-party applications.
