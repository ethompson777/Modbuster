"""
Modbuster GUI: Analyze (PCAP/live), Inject, Replay.
Uses customtkinter for a modern look.
"""

import queue
import threading
import tkinter.filedialog
from pathlib import Path
from typing import Any, List, Optional, Tuple

import customtkinter as ctk

from modbuster.capture import iter_live, iter_pcap
from modbuster.export import export_csv, export_json
from modbuster.interpreter import format_line
from modbuster.inject import (
    inject_modbus_read_holding,
    inject_modbus_write_register,
    inject_modbus_write_multiple_registers,
)
from modbuster.replay import get_messages_from_pcap, replay_one


# Theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# SCADA protocols and default ports (from plan); all selected by default for live monitor
SCADA_PORTS = [
    ("Modbus TCP", 502, "tcp"),
    ("DNP3", 20000, "tcp"),
    ("IEC 60870-5-104", 2404, "tcp"),
    ("BACnet", 47808, "udp"),
    ("EtherNet/IP (CIP)", 44818, "tcp"),
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


class ModbusterApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Modbuster — SCADA Traffic Analysis & Injection")
        self.geometry("900x620")
        self.minsize(700, 500)

        self._analyze_records: List[dict] = []
        self._live_running = False
        self._msg_queue: queue.Queue = queue.Queue()

        self._build_ui()
        self._poll_queue()

    def _build_ui(self) -> None:
        self.tabs = ctk.CTkTabview(self, width=880, height=560)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=10)
        self.tabs.add("Analyze")
        self.tabs.add("Inject")
        self.tabs.add("Replay")

        self._build_analyze_tab()
        self._build_inject_tab()
        self._build_replay_tab()

        self.status = ctk.CTkLabel(self, text="Ready", anchor="w", font=("", 11))
        self.status.pack(fill="x", padx=10, pady=(0, 8))

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
        self.ports_btn = ctk.CTkButton(iface_row, text="5 port(s) selected", width=180, command=self._toggle_ports_dropdown)
        self.ports_btn.pack(side="left", padx=4)
        # Dropdown panel with checkboxes (shown below the row when button clicked)
        self.ports_dropdown = ctk.CTkFrame(live_frame, fg_color=("gray80", "gray30"), corner_radius=6, border_width=1)
        for (label, port, _), var in zip(SCADA_PORTS, self.port_vars):
            cb = ctk.CTkCheckBox(self.ports_dropdown, text=f"{label} ({port})", variable=var, width=0, command=self._update_ports_button_text)
            cb.pack(anchor="w", padx=14, pady=6)
        self.ports_dropdown.pack(fill="x", pady=(0, 6), padx=(0, 0))
        self.ports_dropdown.pack_forget()
        # Click outside dropdown to close it
        top.bind("<ButtonPress>", self._maybe_close_ports_dropdown)

        self.analyze_text = ctk.CTkTextbox(top, font=("Consolas", 11), wrap="word")
        self.analyze_text.pack(fill="both", expand=True, pady=(8, 0))

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
            self.live_btn.configure(text="Start Live")
            self._log_status("Live capture stopped.")
            return
        iface_val = (self.iface_var.get() or "").strip()
        iface = None
        if iface_val and iface_val != "Default":
            # Resolve display name to device name for Scapy
            iface = next((d[1] for d in self._iface_choices if d[0] == iface_val), iface_val)
        bpf_filter = _build_bpf_from_ports(self.port_vars)
        self._live_running = True
        self.live_btn.configure(text="Stop Live")
        self.analyze_text.delete("1.0", "end")
        self._analyze_records = []
        self._log_status("Starting live capture…")
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
                    self._msg_queue.put(("analyze_append", line))
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
        self._log_status("Loading PCAP…")
        selected_ports = [(port, proto) for (_, port, proto), var in zip(SCADA_PORTS, self.port_vars) if var.get()]
        threading.Thread(target=self._run_pcap_thread, args=(path, selected_ports), daemon=True).start()
        # Drain queue soon so first load shows without waiting for the 200ms poll
        self.after(10, self._poll_queue)

    def _run_pcap_thread(self, path: str, selected_ports: Optional[List[tuple]] = None) -> None:
        try:
            for pkt, name, parsed in iter_pcap(path, selected_ports=selected_ports or None):
                line = format_line(pkt, name, parsed)
                self._analyze_records.append(parsed)
                self._msg_queue.put(("analyze_append", line))
            self._msg_queue.put(("status", f"Loaded {len(self._analyze_records)} messages."))
        except Exception as e:
            self._msg_queue.put(("status", f"Error: {e}"))

    def _export_analyze(self) -> None:
        if not self._analyze_records:
            self._log_status("No data to export. Load a PCAP or run live capture first.")
            return
        path = tkinter.filedialog.asksaveasfilename(
            title="Export",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("CSV", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            if path.lower().endswith(".csv"):
                export_csv(self._analyze_records, path)
            else:
                export_json(self._analyze_records, path)
            self._log_status(f"Exported to {path}")
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
        ctk.CTkLabel(f, text="Unit ID:").pack(side="left", padx=(12, 4))
        self.inject_unit = ctk.CTkEntry(f, width=50)
        self.inject_unit.insert(0, "1")
        self.inject_unit.pack(side="left", padx=4)

        self.inject_cmd = ctk.StringVar(value="read_holding")
        ctk.CTkRadioButton(top, text="Read holding registers", variable=self.inject_cmd, value="read_holding").pack(anchor="w", pady=2)
        ctk.CTkRadioButton(top, text="Write single register", variable=self.inject_cmd, value="write_register").pack(anchor="w", pady=2)
        ctk.CTkRadioButton(top, text="Write multiple registers", variable=self.inject_cmd, value="write_registers").pack(anchor="w", pady=2)

        row2 = ctk.CTkFrame(top, fg_color="transparent")
        row2.pack(fill="x", pady=8)
        ctk.CTkLabel(row2, text="Addr:").pack(side="left", padx=(0, 4))
        self.inject_addr = ctk.CTkEntry(row2, width=80)
        self.inject_addr.insert(0, "0")
        self.inject_addr.pack(side="left", padx=4)
        ctk.CTkLabel(row2, text="Count:").pack(side="left", padx=(12, 4))
        self.inject_count = ctk.CTkEntry(row2, width=60)
        self.inject_count.insert(0, "10")
        self.inject_count.pack(side="left", padx=4)
        ctk.CTkLabel(row2, text="Value (single):").pack(side="left", padx=(12, 4))
        self.inject_value = ctk.CTkEntry(row2, width=80)
        self.inject_value.pack(side="left", padx=4)
        ctk.CTkLabel(row2, text="Values (comma):").pack(side="left", padx=(12, 4))
        self.inject_values = ctk.CTkEntry(row2, width=120, placeholder_text="1,2,3")
        self.inject_values.pack(side="left", padx=4)

        row3 = ctk.CTkFrame(top, fg_color="transparent")
        row3.pack(fill="x", pady=4)
        self.inject_allow_write = ctk.CTkCheckBox(row3, text="Allow write (required for write commands)")
        self.inject_allow_write.pack(side="left", padx=0)
        ctk.CTkButton(row3, text="Execute", width=100, command=self._do_inject).pack(side="left", padx=20)

        self.inject_log = ctk.CTkTextbox(top, height=120, font=("Consolas", 10))
        self.inject_log.pack(fill="both", expand=True, pady=(12, 0))

    def _do_inject(self) -> None:
        def _log(msg: str) -> None:
            self._msg_queue.put(("inject_log", msg))

        target = self.inject_target.get().strip()
        if not target:
            _log("Enter target IP.")
            return
        try:
            port = int(self.inject_port.get().strip() or "502")
        except ValueError:
            _log("Invalid port.")
            return
        try:
            unit = int(self.inject_unit.get().strip() or "1")
        except ValueError:
            _log("Invalid unit ID.")
            return

        cmd = self.inject_cmd.get()
        allow_write = self.inject_allow_write.get()

        def run() -> None:
            try:
                if cmd == "read_holding":
                    addr = int(self.inject_addr.get().strip() or "0")
                    count = int(self.inject_count.get().strip() or "1")
                    resp = inject_modbus_read_holding(target, port, unit, addr, count)
                    if resp:
                        _log(f"OK: {len(resp)} bytes")
                    else:
                        _log("No response or error.")
                elif cmd == "write_register":
                    if not allow_write:
                        _log("Check 'Allow write' for write commands.")
                        return
                    addr = int(self.inject_addr.get().strip() or "0")
                    value = int(self.inject_value.get().strip() or "0")
                    resp = inject_modbus_write_register(target, port, unit, addr, value, write_flag=True)
                    if resp:
                        _log(f"Write OK: {len(resp)} bytes")
                    else:
                        _log("No response or error.")
                elif cmd == "write_registers":
                    if not allow_write:
                        _log("Check 'Allow write' for write commands.")
                        return
                    addr = int(self.inject_addr.get().strip() or "0")
                    raw = self.inject_values.get().strip()
                    values = [int(x.strip()) for x in raw.split(",") if x.strip()]
                    if not values:
                        _log("Enter comma-separated values.")
                        return
                    resp = inject_modbus_write_multiple_registers(target, port, unit, addr, values, write_flag=True)
                    if resp:
                        _log(f"Write multiple OK: {len(resp)} bytes")
                    else:
                        _log("No response or error.")
            except ValueError as e:
                _log(f"Invalid input: {e}")
            except Exception as e:
                _log(f"Error: {e}")

        threading.Thread(target=run, daemon=True).start()

    def _build_replay_tab(self) -> None:
        top = self.tabs.tab("Replay")
        row = ctk.CTkFrame(top, fg_color="transparent")
        row.pack(fill="x", pady=4)
        ctk.CTkLabel(row, text="PCAP:").pack(side="left", padx=(0, 6))
        self.replay_pcap = ctk.CTkEntry(row, width=350, placeholder_text="Path to PCAP")
        self.replay_pcap.pack(side="left", padx=4, fill="x", expand=True)
        ctk.CTkButton(row, text="Browse", width=80, command=self._browse_replay_pcap).pack(side="left", padx=8)
        row2 = ctk.CTkFrame(top, fg_color="transparent")
        row2.pack(fill="x", pady=8)
        ctk.CTkLabel(row2, text="Target:").pack(side="left", padx=(0, 6))
        self.replay_target = ctk.CTkEntry(row2, width=140, placeholder_text="192.168.1.10")
        self.replay_target.pack(side="left", padx=4)
        ctk.CTkLabel(row2, text="Port:").pack(side="left", padx=(12, 4))
        self.replay_port = ctk.CTkEntry(row2, width=60)
        self.replay_port.insert(0, "502")
        self.replay_port.pack(side="left", padx=4)
        ctk.CTkLabel(row2, text="Index (optional):").pack(side="left", padx=(12, 4))
        self.replay_index = ctk.CTkEntry(row2, width=60, placeholder_text="0")
        self.replay_index.pack(side="left", padx=4)
        ctk.CTkButton(row2, text="Replay", width=90, command=self._do_replay).pack(side="left", padx=16)
        self.replay_log = ctk.CTkTextbox(top, height=200, font=("Consolas", 10))
        self.replay_log.pack(fill="both", expand=True, pady=(12, 0))

    def _browse_replay_pcap(self) -> None:
        path = tkinter.filedialog.askopenfilename(
            title="Select PCAP",
            filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")],
        )
        if path:
            self.replay_pcap.delete(0, "end")
            self.replay_pcap.insert(0, path)

    def _do_replay(self) -> None:
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

        def run() -> None:
            try:
                msgs = get_messages_from_pcap(pcap_path, protocol_filter=["modbus"], index=index)
                if not msgs:
                    self._msg_queue.put(("replay_log", "No messages found."))
                    return
                pkt, name, parsed = msgs[0]
                resp = replay_one(pkt, name, target, port)
                if resp is not None:
                    self._msg_queue.put(("replay_log", f"Replayed 1 message, response {len(resp)} bytes."))
                else:
                    self._msg_queue.put(("replay_log", "Replay failed or no response."))
            except Exception as e:
                self._msg_queue.put(("replay_log", f"Error: {e}"))

        threading.Thread(target=run, daemon=True).start()

    def _log_status(self, msg: str) -> None:
        self.status.configure(text=msg)

    def _poll_queue(self) -> None:
        had_analyze = False
        try:
            while True:
                msg = self._msg_queue.get_nowait()
                if msg[0] == "analyze_append":
                    self.analyze_text.insert("end", msg[1] + "\n")
                    self.analyze_text.see("end")
                    had_analyze = True
                elif msg[0] == "status":
                    self._log_status(str(msg[1]))
                elif msg[0] == "live_stopped":
                    self._live_running = False
                    self.live_btn.configure(text="Start Live")
                    self._log_status("Live capture stopped.")
                elif msg[0] == "inject_log":
                    self.inject_log.insert("end", msg[1] + "\n")
                    self.inject_log.see("end")
                elif msg[0] == "replay_log":
                    self.replay_log.insert("end", msg[1] + "\n")
                    self.replay_log.see("end")
        except queue.Empty:
            pass
        if had_analyze:
            self.analyze_text.update_idletasks()
        self.after(200, self._poll_queue)


def main() -> None:
    app = ModbusterApp()
    app.mainloop()


if __name__ == "__main__":
    main()
