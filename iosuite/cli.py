"""
iOSuite Command Line Interface
Main CLI entrypoint with subcommands for tracing, device enumeration, and process listing.
"""

from typing import Optional
import typer
from rich.console import Console
from rich.table import Table

from iosuite import __version__
from iosuite.core.session import FridaDeviceSession
from iosuite.app import iOSuiteTraceApp

cli = typer.Typer(
    name="iosuite",
    help="Dynamic iOS Feature & Handler Interception CLI with Interactive TUI",
    add_completion=False,
)
console = Console()


@cli.command("trace")
def trace(
    target: str = typer.Argument(
        "DemoApp",
        help="Target iOS App (Process Name, PID, or Bundle Identifier)",
    ),
    usb: bool = typer.Option(
        True,
        "--usb",
        "-u",
        help="Connect to USB iOS device",
    ),
    device_id: Optional[str] = typer.Option(
        None,
        "--device",
        "-d",
        help="Specific Frida device ID to connect to",
    ),
    spawn: bool = typer.Option(
        False,
        "--spawn",
        "-s",
        help="Spawn the application instead of attaching to a running process",
    ),
    mock: bool = typer.Option(
        False,
        "--mock",
        "-m",
        help="Run in mock/simulation mode (no physical device required)",
    ),
    webview: bool = typer.Option(
        False,
        "--webview",
        "-w",
        help="Launch in ultra-modern Desktop Webview GUI instead of terminal TUI",
    ),
):
    """
    Launch interactive TUI or Desktop Webview for real-time handler interception.
    """
    if webview:
        from iosuite.ui.webview_app import DesktopWebviewOrchestrator
        orchestrator = DesktopWebviewOrchestrator(
            target=target,
            device_id=device_id,
            use_usb=usb,
            spawn=spawn,
            mock_mode=mock,
        )
        console.print(f"[bold cyan]Launching iOSuite Desktop Webview Studio for {target}...[/bold cyan]")
        console.print(f"[bold green]Studio URL: http://127.0.0.1:{orchestrator.port}[/bold green]")
        console.print("[dim]Press Ctrl+C to shut down.[/dim]\n")
        orchestrator.launch(block=True)
        return

    app = iOSuiteTraceApp(
        target=target,
        device_id=device_id,
        use_usb=usb,
        spawn=spawn,
        mock_mode=mock,
    )
    app.run()


@cli.command("gui")
def gui(
    target: str = typer.Argument(
        "auto",
        help="Target iOS App (Process Name, PID, or Bundle Identifier). Defaults to 'auto' for frontmost app.",
    ),
    usb: bool = typer.Option(
        True,
        "--usb",
        "-u",
        help="Connect to USB iOS device",
    ),
    device_id: Optional[str] = typer.Option(
        None,
        "--device",
        "-d",
        help="Specific Frida device ID to connect to",
    ),
    spawn: bool = typer.Option(
        False,
        "--spawn",
        "-s",
        help="Spawn the application instead of attaching to a running process",
    ),
    mock: bool = typer.Option(
        False,
        "--mock",
        "-m",
        help="Run in mock/simulation mode (no physical device required)",
    ),
):
    """
    Launch ultra-modern cyber-minimalist Desktop Webview Studio.
    """
    from iosuite.ui.webview_app import DesktopWebviewOrchestrator
    orchestrator = DesktopWebviewOrchestrator(
        target=target,
        device_id=device_id,
        use_usb=usb,
        spawn=spawn,
        mock_mode=mock,
    )
    console.print(f"[bold cyan]Launching iOSuite Desktop Webview Studio for {target}...[/bold cyan]")
    console.print(f"[bold green]Studio URL: http://127.0.0.1:{orchestrator.port}[/bold green]")
    console.print("[dim]Press Ctrl+C to shut down.[/dim]\n")
    orchestrator.launch(block=True)


@cli.command("devices")
def list_devices():
    """
    List all connected iOS and local Frida devices.
    """
    try:
        devices = FridaDeviceSession.list_devices()
        table = Table(title="Connected Devices", border_style="cyan")
        table.add_column("ID", style="bold white")
        table.add_column("Name", style="green")
        table.add_column("Type", style="yellow")

        for d in devices:
            table.add_row(d["id"], d["name"], d["type"])

        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Failed to enumerate devices:[/bold red] {e}")


@cli.command("ps")
def list_processes(
    usb: bool = typer.Option(
        True,
        "--usb",
        "-u",
        help="List processes from USB device",
    ),
    device_id: Optional[str] = typer.Option(
        None,
        "--device",
        "-d",
        help="Specific device ID",
    ),
):
    """
    List running processes on the iOS device.
    """
    try:
        procs = FridaDeviceSession.list_processes(device_id=device_id, use_usb=usb)
        table = Table(title="Running Processes on Device", border_style="green")
        table.add_column("PID", style="bold yellow", justify="right", width=8)
        table.add_column("Name", style="bold white")

        for p in procs:
            table.add_row(str(p["pid"]), p["name"])

        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Failed to enumerate processes:[/bold red] {e}")


@cli.command("version")
def version():
    """Show iOSuite version."""
    console.print(f"[bold cyan]iOSuite-Trace[/bold cyan] version [bold white]{__version__}[/bold white]")


def main():
    cli()


if __name__ == "__main__":
    main()
