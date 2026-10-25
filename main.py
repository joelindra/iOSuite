#!/usr/bin/env python3
"""
iOSuite - Dynamic iOS Feature & Handler Interception Studio
Direct Application Entrypoint

Usage:
    python main.py                    # Auto-detects frontmost app on USB iOS device and opens GUI
    python main.py MyApp              # Attaches to MyApp and opens GUI
    python main.py com.apple.mobilesafari --spawn   # Spawns Safari and opens GUI
    python main.py --tui              # Opens in interactive terminal TUI mode
    python main.py --mock             # Offline simulation mode (no physical device)
"""

import sys
import argparse
import signal
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


def detect_connected_device_and_app(use_usb: bool = True, device_id: str | None = None) -> tuple[str, str, int | None]:
    """
    Attempt to query Frida to detect the connected iOS device and frontmost app.
    Returns (device_name, app_identifier, pid).
    """
    try:
        import frida
        if device_id:
            dev = frida.get_device(device_id)
        elif use_usb:
            dev = frida.get_usb_device(timeout=2)
        else:
            dev = frida.get_local_device()

        device_name = f"{dev.name} ({dev.type})"
        app_name = "auto"
        pid = None

        try:
            front = dev.get_frontmost_application()
            if front:
                app_name = front.name or front.identifier
                pid = front.pid
        except Exception:
            pass

        return device_name, app_name, pid
    except Exception as e:
        return f"Unknown ({e})", "auto", None


def print_banner(target: str, device_name: str, mock_mode: bool, mode_ui: str, bridge_port: int = 1337):
    """Render startup dashboard banner."""
    banner_text = Text()
    banner_text.append(" iOSuite Studio ", style="bold black on cyan")
    banner_text.append("  Dynamic iOS Reverse Engineering & Interception\n\n", style="bold white")

    banner_text.append(" Mode:        ", style="gray")
    if mock_mode:
        banner_text.append("OFFLINE SIMULATION (Mock Mode)\n", style="bold yellow")
    else:
        banner_text.append("LIVE HARDWARE INTERCEPTION (Real Frida)\n", style="bold green")

    banner_text.append(" Interface:   ", style="gray")
    banner_text.append(f"{mode_ui.upper()}\n", style="bold cyan")

    banner_text.append(" Device:      ", style="gray")
    banner_text.append(f"{device_name}\n", style="bold white")

    banner_text.append(" Target:      ", style="gray")
    banner_text.append(f"{target}\n", style="bold yellow")

    banner_text.append(" Sync Bridge: ", style="gray")
    banner_text.append(f"http://127.0.0.1:{bridge_port} (IDA / Ghidra / Hopper / LLDB)\n", style="bold magenta")

    console.print(Panel(banner_text, border_style="cyan", title="[bold cyan]SYSTEM INITIALIZED[/bold cyan]", title_align="left"))


def main():
    parser = argparse.ArgumentParser(
        description="iOSuite - Dynamic iOS Feature & Handler Interception Studio",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="auto",
        help="Target process name, PID, or bundle ID (defaults to 'auto' for frontmost app)",
    )
    parser.add_argument(
        "-u", "--usb",
        action="store_true",
        default=True,
        help="Connect to physical iOS device via USB (default: True)",
    )
    parser.add_argument(
        "-d", "--device",
        type=str,
        default=None,
        help="Specific Frida device ID to connect to",
    )
    parser.add_argument(
        "-s", "--spawn",
        action="store_true",
        default=False,
        help="Spawn the application package instead of attaching to running PID",
    )
    parser.add_argument(
        "-m", "--mock",
        action="store_true",
        default=False,
        help="Run offline simulation mode with synthetic events (no physical device)",
    )
    parser.add_argument(
        "-t", "--tui",
        action="store_true",
        default=False,
        help="Run terminal TUI interface instead of desktop webview GUI",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=None,
        help="Custom HTTP port for webview micro-daemon (default: auto)",
    )

    args = parser.parse_args()

    # Device & App Resolution
    device_name = "Simulated iPhone 14 Pro" if args.mock else "Connecting..."
    target = args.target
    initial_pid = None

    if not args.mock:
        dev_info, front_app, pid = detect_connected_device_and_app(use_usb=args.usb, device_id=args.device)
        if "Unknown" not in dev_info:
            device_name = dev_info
            initial_pid = pid
            if target == "auto" and front_app != "auto":
                target = front_app
        elif target == "auto":
            console.print("[bold yellow][!] No active USB device or frontmost app detected immediately.[/bold yellow]")
            console.print("[gray]Waiting for device connection or specify target: python main.py <AppName>[/gray]\n")

    mode_label = "Terminal TUI" if args.tui else "Desktop Webview Studio"
    print_banner(target=target, device_name=device_name, mock_mode=args.mock, mode_ui=mode_label)

    # 1. Terminal TUI Mode
    if args.tui:
        from iosuite.app import iOSuiteTraceApp
        app = iOSuiteTraceApp(
            target=target,
            device_id=args.device,
            use_usb=args.usb,
            spawn=args.spawn,
            mock_mode=args.mock,
        )
        app.run()
        return

    # 2. Desktop Webview GUI Mode (Default)
    from iosuite.ui.webview_app import DesktopWebviewOrchestrator
    orchestrator = DesktopWebviewOrchestrator(
        target=target,
        device_id=args.device,
        device_name=device_name if not args.mock and "Unknown" not in device_name else None,
        initial_pid=initial_pid,
        use_usb=args.usb,
        spawn=args.spawn,
        mock_mode=args.mock,
        port=args.port,
    )

    def handle_sigint(sig, frame):
        console.print("\n[bold yellow]Shutting down iOSuite Studio...[/bold yellow]")
        orchestrator.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    try:
        console.print("[bold green]Starting local daemon & opening GUI window...[/bold green]")
        console.print(f"[bold cyan]Desktop Webview Studio running at: http://127.0.0.1:{orchestrator.port}[/bold cyan]")
        console.print("[dim]Press Ctrl+C in this terminal to shut down the studio.[/dim]\n")
        orchestrator.launch(block=True)
    except KeyboardInterrupt:
        orchestrator.stop()
        console.print("\n[bold yellow]iOSuite Studio terminated.[/bold yellow]")


if __name__ == "__main__":
    main()
