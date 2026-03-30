"""CLI: analyze (--pcap / --live, --protocol, --tui), inject, replay."""

import argparse
import sys
from typing import List, Optional

from modbuster.capture import iter_live, iter_pcap
from modbuster.export import export_csv, export_json
from modbuster.interpreter import format_line
from modbuster.inject import (
    inject_modbus_read_holding,
    inject_modbus_write_register,
    inject_modbus_write_multiple_registers,
)
from modbuster.replay import get_messages_from_pcap, replay_one
from modbuster.tui import run_tui_live, run_tui_pcap
from modbuster.protocols import list_protocols


def _protocol_list(s: str) -> List[str]:
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]


def cmd_analyze(args: argparse.Namespace) -> int:
    protocol_filter = _protocol_list(args.protocol) if getattr(args, "protocol", None) else None
    bpf = getattr(args, "filter", None) or None
    export_path = getattr(args, "export", None) or None
    use_tui = getattr(args, "tui", False)

    if use_tui:
        if args.pcap:
            run_tui_pcap(args.pcap, protocol_filter=protocol_filter, bpf_filter=bpf)
        elif args.live:
            run_tui_live(
                iface=getattr(args, "iface", None),
                count=getattr(args, "count", 0) or 0,
                protocol_filter=protocol_filter,
                bpf_filter=bpf,
            )
        return 0

    records = []
    try:
        if args.pcap:
            it = iter_pcap(args.pcap, bpf_filter=bpf, protocol_filter=protocol_filter)
        elif args.live:
            it = iter_live(
                iface=getattr(args, "iface", None),
                count=getattr(args, "count", 0) or 0,
                protocol_filter=protocol_filter,
                bpf_filter=bpf,
            )
        else:
            print("error: specify --pcap <path> or --live", file=sys.stderr)
            return 1

        for pkt, name, parsed in it:
            records.append(parsed)
            if not getattr(args, "quiet", False):
                print(format_line(pkt, name, parsed))

        if export_path:
            if export_path.endswith(".csv"):
                export_csv(records, export_path)
            else:
                export_json(records, export_path)
            if not getattr(args, "quiet", False):
                print(f"Exported to {export_path}", file=sys.stderr)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        if getattr(args, "verbose", False):
            raise
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_inject(args: argparse.Namespace) -> int:
    target = args.target
    port = getattr(args, "port", 502) or 502
    protocol = getattr(args, "protocol", "modbus") or "modbus"
    write_flag = getattr(args, "write", False)

    if protocol != "modbus":
        print("error: only modbus inject is supported in this build", file=sys.stderr)
        return 1

    inject_cmd = getattr(args, "inject_cmd", None)
    try:
        if inject_cmd == "read-holding":
            resp = inject_modbus_read_holding(
                target, port, args.unit, getattr(args, "addr", 0), getattr(args, "count", 1)
            )
        elif inject_cmd == "write-register":
            resp = inject_modbus_write_register(
                target, port, args.unit, getattr(args, "addr", 0), args.value,
                write_flag=write_flag,
            )
        elif inject_cmd == "write-registers":
            resp = inject_modbus_write_multiple_registers(
                target, port, args.unit, getattr(args, "addr", 0), getattr(args, "values", []),
                write_flag=write_flag,
            )
        else:
            print("error: use read-holding, write-register, or write-registers subcommand", file=sys.stderr)
            return 1

        if resp is not None:
            if getattr(args, "verbose", False):
                print(resp.hex())
            return 0
        print("error: no response or send failed", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def cmd_gui(args: argparse.Namespace) -> int:
    """Launch the GUI."""
    from modbuster.gui import main as gui_main
    gui_main()
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    pcap_path = args.pcap
    target = args.target
    port = getattr(args, "port", 502) or 502
    index = getattr(args, "index", None)
    write_flag = getattr(args, "write", False)
    count = getattr(args, "count", 1) or 1

    protocol_filter = _protocol_list(getattr(args, "protocol", "") or "modbus")
    msgs = get_messages_from_pcap(pcap_path, protocol_filter=protocol_filter, index=index)
    if not msgs:
        print("error: no messages found", file=sys.stderr)
        return 1

    n = 0
    errors = 0
    for pkt, name, parsed in msgs:
        if n >= count:
            break
        try:
            resp = replay_one(pkt, name, target, port, write_flag=write_flag)
        except PermissionError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        if resp is not None:
            n += 1
            if getattr(args, "verbose", False):
                print(resp.hex())
        else:
            errors += 1

    if n == 0:
        print("error: no packets were successfully replayed", file=sys.stderr)
        return 1
    if errors:
        print(f"warning: {errors} packet(s) failed to send", file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="modbuster", description="SCADA traffic analysis and injection")
    ap.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    ap.add_argument("--quiet", "-q", action="store_true", help="Minimal output")

    sub = ap.add_subparsers(dest="command", required=True)

    # gui
    sub.add_parser("gui", help="Launch GUI").set_defaults(func=cmd_gui)

    # analyze
    an = sub.add_parser("analyze", help="Analyze PCAP or live capture")
    an.add_argument("--pcap", metavar="PATH", help="Path to PCAP file")
    an.add_argument("--live", action="store_true", help="Live capture")
    an.add_argument("--iface", default=None, help="Interface for live capture")
    an.add_argument("--count", type=int, default=0, help="Max packets for live (0 = until interrupted)")
    an.add_argument("--protocol", default=None, help="Comma-separated protocols (e.g. modbus)")
    an.add_argument("--filter", dest="filter", default=None, help="BPF filter")
    an.add_argument("--export", metavar="PATH", default=None, help="Export to JSON or CSV")
    an.add_argument("--tui", action="store_true", help="Use TUI")
    an.set_defaults(func=cmd_analyze)

    # inject
    inj = sub.add_parser("inject", help="Inject Modbus (or other) commands")
    inj.add_argument("--protocol", default="modbus", choices=list_protocols(), help="Protocol")
    inj.add_argument("--target", "-t", required=True, help="Target IP")
    inj.add_argument("--port", "-p", type=int, default=502, help="Target port")
    inj.add_argument("--unit", "-u", type=int, default=1, help="Unit ID")
    inj.add_argument("--write", action="store_true", help="Allow write operations")
    inj.set_defaults(func=cmd_inject)

    sub_inj = inj.add_subparsers(dest="inject_cmd")
    rh = sub_inj.add_parser("read-holding", help="Read holding registers")
    rh.add_argument("--addr", type=int, default=0, help="Start address")
    rh.add_argument("--count", "-n", type=int, default=1, help="Quantity")
    rh.set_defaults(addr=0, count=1)

    wr = sub_inj.add_parser("write-register", help="Write single register")
    wr.add_argument("--addr", type=int, required=True)
    wr.add_argument("--value", type=int, required=True)
    wr.set_defaults(addr=None, value=None)

    wrs = sub_inj.add_parser("write-registers", help="Write multiple registers")
    wrs.add_argument("--addr", type=int, required=True)
    wrs.add_argument("--values", type=int, nargs="+", required=True)
    wrs.set_defaults(addr=None, values=None)

    # replay
    rp = sub.add_parser("replay", help="Replay messages from PCAP to target")
    rp.add_argument("--pcap", required=True, help="PCAP path")
    rp.add_argument("--target", "-t", required=True, help="Target IP")
    rp.add_argument("--port", "-p", type=int, default=502)
    rp.add_argument("--index", type=int, default=None, help="Message index to replay")
    rp.add_argument("--count", type=int, default=1)
    rp.add_argument("--write", action="store_true", help="Allow replay of write messages")
    rp.add_argument("--protocol", default="modbus")
    rp.set_defaults(func=cmd_replay)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
