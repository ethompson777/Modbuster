"""TUI for analyze (live or PCAP): scrolling view, filter by protocol/unit, pause/resume."""

import sys
from typing import Any, Callable, Dict, List, Optional

from modbuster.interpreter import format_line
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.layout import Layout


def run_tui_pcap(
    pcap_path: str,
    protocol_filter: Optional[List[str]] = None,
    bpf_filter: Optional[str] = None,
) -> None:
    """Run TUI over PCAP: stream interpreted lines with rich."""
    from modbuster.capture import iter_pcap

    console = Console()
    lines: List[str] = []
    max_lines = 200

    def make_display() -> Panel:
        content = Text("\n".join(lines[-max_lines:]))
        return Panel(content, title=f"PCAP: {pcap_path}", border_style="blue")

    try:
        with Live(make_display(), console=console, refresh_per_second=4) as live:
            for pkt, name, parsed in iter_pcap(pcap_path, bpf_filter=bpf_filter, protocol_filter=protocol_filter):
                line = format_line(pkt, name, parsed)
                lines.append(line)
                live.update(make_display())
    except KeyboardInterrupt:
        pass


def run_tui_live(
    iface: Optional[str] = None,
    count: int = 0,
    protocol_filter: Optional[List[str]] = None,
    bpf_filter: Optional[str] = None,
) -> None:
    """Run TUI over live capture. count=0 runs until Ctrl+C."""
    from modbuster.capture import iter_live

    console = Console()
    lines: List[str] = []
    max_lines = 200

    def make_display() -> Panel:
        content = Text("\n".join(lines[-max_lines:]))
        title = "Live capture" + (f" (iface={iface})" if iface else "")
        return Panel(content, title=title, border_style="green")

    try:
        with Live(make_display(), console=console, refresh_per_second=4) as live:
            for pkt, name, parsed in iter_live(
                iface=iface, count=count, protocol_filter=protocol_filter, bpf_filter=bpf_filter
            ):
                line = format_line(pkt, name, parsed)
                lines.append(line)
                live.update(make_display())
                if count > 0 and len(lines) >= count:
                    break
    except KeyboardInterrupt:
        pass
