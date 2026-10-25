"""
Unit tests for session exporter and Frida hook script generator.
"""

from pathlib import Path
from iosuite.core.dispatcher import InterceptedEvent
from iosuite.core.exporter import export_to_markdown, export_to_json, generate_frida_hook_script


def test_export_markdown_and_json(tmp_path: Path):
    ev = InterceptedEvent(
        id="test_1",
        timestamp="2026-10-22T10:00:00Z",
        category="ui_action",
        action_type="sendAction",
        summary="UIButton -> onPayTapped:",
        target_class="CheckoutViewController",
        selector="onPayTapped:",
        location={
            "moduleName": "MainApp.app/MainApp",
            "offset": "0x21B240",
            "implementation": "0x104A1B240",
        },
        sender={
            "className": "UIButton",
            "title": "Bayar Sekarang",
            "hierarchy": ["UIWindow", "CheckoutViewController", "UIButton"],
        },
    )

    md_path = tmp_path / "export.md"
    json_path = tmp_path / "export.json"
    hook_path = tmp_path / "hook.js"

    saved_md = export_to_markdown([ev], "MainApp", md_path)
    assert Path(saved_md).exists()
    md_content = Path(saved_md).read_text(encoding="utf-8")
    assert "CheckoutViewController" in md_content
    assert "0x21B240" in md_content

    saved_json = export_to_json([ev], "MainApp", json_path)
    assert Path(saved_json).exists()
    json_content = Path(saved_json).read_text(encoding="utf-8")
    assert "MainApp" in json_content
    assert "onPayTapped:" in json_content

    saved_hook = generate_frida_hook_script(ev, hook_path)
    assert Path(saved_hook).exists()
    hook_content = Path(saved_hook).read_text(encoding="utf-8")
    assert "Interceptor.attach" in hook_content
    assert "CheckoutViewController" in hook_content
    assert "onPayTapped:" in hook_content
