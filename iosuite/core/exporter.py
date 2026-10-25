"""
Session Exporter & Frida Hook Script Generator
Exports captured trace events to Markdown, JSON, and creates standalone Frida hook scripts.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from iosuite.core.dispatcher import InterceptedEvent
from iosuite.core.demangler import format_symbol_display


def export_to_json(events: List[InterceptedEvent], target_app: str, output_path: str | Path) -> str:
    """Export all events to a structured JSON file."""
    path = Path(output_path)
    event_dicts = []
    for ev in events:
        if ev.raw:
            event_dicts.append(ev.raw)
        else:
            event_dicts.append({
                "id": ev.id,
                "timestamp": ev.timestamp,
                "category": ev.category,
                "actionType": ev.action_type,
                "summary": ev.summary,
                "targetClass": ev.target_class,
                "selector": ev.selector,
                "targetPointer": ev.target_pointer,
                "location": ev.location,
                "sender": ev.sender,
                "backtrace": ev.backtrace,
                "hitCount": ev.hit_count,
            })

    data = {
        "metadata": {
            "tool": "iOSuite-Trace",
            "targetApp": target_app,
            "exportTime": datetime.now().isoformat(),
            "totalEvents": len(events),
        },
        "events": event_dicts,
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(path.resolve())


def export_to_markdown(events: List[InterceptedEvent], target_app: str, output_path: str | Path) -> str:
    """Export all events to an executive security & reverse-engineering Markdown report."""
    path = Path(output_path)
    lines = [
        f"# iOSuite Trace Session Report",
        f"",
        f"- **Target Application:** `{target_app}`",
        f"- **Export Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- **Total Intercepted Events:** {len(events)}",
        f"",
        f"---",
        f"",
        f"## 1. Summary Table",
        f"",
        f"| # | Time | Category | Target / Feature | Mach-O Offset | Hits |",
        f"| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for idx, ev in enumerate(events, start=1):
        loc = ev.location or {}
        offset = loc.get("offset", "N/A")
        if offset != "N/A" and not offset.startswith("0x"):
            try:
                offset = f"0x{int(offset):X}"
            except ValueError:
                pass
        target_display = ev.target_class or ev.summary
        if ev.selector:
            target_display += f" -> {ev.selector}"

        lines.append(f"| {idx} | {ev.time_str} | `{ev.category}` | `{target_display}` | `{offset}` | {ev.hit_count} |")

    lines.extend([
        f"",
        f"---",
        f"",
        f"## 2. Detailed Handler Analysis",
        f"",
    ])

    seen_keys = set()
    for ev in events:
        if ev.key in seen_keys:
            continue
        seen_keys.add(ev.key)

        loc = ev.location or {}
        bt = ev.backtrace or {}
        frames = bt.get("frames", [])

        lines.append(f"### {ev.summary}")
        lines.append(f"")
        lines.append(f"- **Category:** `{ev.category}`")
        lines.append(f"- **Action Type:** `{ev.action_type}`")
        if ev.target_class:
            lines.append(f"- **Target Class:** `{ev.target_class}`")
        if ev.selector:
            lines.append(f"- **Selector / Method:** `{ev.selector}`")
        if loc.get("moduleName"):
            lines.append(f"- **Module:** `{loc.get('moduleName')}`")
        if loc.get("offset"):
            lines.append(f"- **Mach-O Offset:** `{loc.get('offset')}`")
        if loc.get("implementation"):
            lines.append(f"- **Implementation Pointer:** `{loc.get('implementation')}`")

        # Sender Context
        if ev.sender:
            s = ev.sender
            lines.append(f"")
            lines.append(f"**Sender Context:**")
            lines.append(f"- Class: `{s.get('className')}`")
            if s.get("title"):
                lines.append(f"- Title: \"{s.get('title')}\"")
            if s.get("tag"):
                lines.append(f"- Tag: `{s.get('tag')}`")
            if s.get("hierarchy"):
                lines.append(f"- View Hierarchy: `{' -> '.join(s.get('hierarchy'))}`")

        # Call Stack / Backtrace
        if frames:
            lines.append(f"")
            lines.append(f"**Call Stack (Accurate Backtrace):**")
            lines.append(f"```text")
            for f in frames:
                marker = "[APP]" if f.get("isApp") else "[SYS]"
                sym = f.get("symbol") or f.get("address")
                lines.append(f"  {f.get('index', 0):2d}: {marker} {f.get('moduleName')}!{sym} (+{f.get('offset')})")
            lines.append(f"```")

        # Disassembly snippet
        disasm = loc.get("disassembly", [])
        if disasm:
            lines.append(f"")
            lines.append(f"**Disassembly Context:**")
            lines.append(f"```assembly")
            for ins in disasm:
                lines.append(f"  {ins.get('address')}  {ins.get('mnemonic')} {ins.get('opStr')}")
            lines.append(f"```")

        lines.append(f"")
        lines.append(f"---")
        lines.append(f"")

    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path.resolve())


def generate_frida_hook_script(event: InterceptedEvent, output_path: str | Path) -> str:
    """Generate a ready-to-run Frida script targeting this specific handler."""
    path = Path(output_path)
    cls_name = event.target_class or "TargetClass"
    sel_name = event.selector or "selector:"

    script_template = f"""/**
 * Auto-generated Frida Hook for:
 * Class:    {cls_name}
 * Selector: {sel_name}
 * Action:   {event.summary}
 * Generated by iOSuite-Trace
 */

'use strict';

if (ObjC.available) {{
    try {{
        var targetCls = ObjC.classes['{cls_name}'];
        var selName = '{sel_name}';
        var method = targetCls['- ' + selName] || targetCls['+ ' + selName];

        if (method) {{
            Interceptor.attach(method.implementation, {{
                onEnter: function (args) {{
                    console.log('\\n[+] === Intercepted {cls_name} ' + selName + ' ===');
                    console.log('    Self:   ' + args[0]);
                    console.log('    Sender: ' + (args[2] ? new ObjC.Object(args[2]) : 'nil'));

                    // Print Callstack
                    console.log('    Callstack:\\n' +
                        Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join('\\n        ')
                    );
                }},
                onLeave: function (retval) {{
                    console.log('[-] Return Value: ' + retval);
                }}
            }});
            console.log('[*] Successfully hooked {cls_name} ' + selName);
        }} else {{
            console.log('[-] Method {sel_name} not found on class {cls_name}');
        }}
    }} catch (e) {{
        console.log('[-] Hook Error: ' + e.message);
    }}
}} else {{
    console.log('[-] Objective-C runtime not available');
}}
"""
    path.write_text(script_template, encoding="utf-8")
    return str(path.resolve())
