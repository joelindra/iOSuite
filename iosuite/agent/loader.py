"""
iOSuite Agent Loader
Reads and bundles the agent JavaScript script for injection into Frida.
"""

from pathlib import Path

AGENT_SCRIPT_PATH = Path(__file__).parent / "scripts" / "agent.js"


def get_agent_script() -> str:
    """Read and return the unified Frida agent JavaScript source code."""
    if not AGENT_SCRIPT_PATH.exists():
        raise FileNotFoundError(f"Agent script not found at {AGENT_SCRIPT_PATH}")
    return AGENT_SCRIPT_PATH.read_text(encoding="utf-8")
