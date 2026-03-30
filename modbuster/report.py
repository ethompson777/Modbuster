"""
report.py — Modbuster pentest report generator.

Produces PDF or Markdown reports from session data: discovered hosts,
register classifications, successful writes, and auto-scored findings.
PDF requires fpdf2 (pip install fpdf2).
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

# ── Severity ordering ─────────────────────────────────────────────────────────
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Severity badge colours  (R, G, B)
_SEV_COLOUR = {
    "CRITICAL": (180,  30,  30),
    "HIGH":     (210,  90,   0),
    "MEDIUM":   (180, 140,   0),
    "LOW":      ( 40, 130,  60),
    "INFO":     ( 60,  90, 160),
}

# Brand colours
_ORANGE  = (255, 105,   0)
_DARK    = ( 30,  30,  30)
_MID     = ( 80,  80,  80)
_LIGHT   = (245, 245, 245)
_WHITE   = (255, 255, 255)

# ── Unit ID context ───────────────────────────────────────────────────────────
_UNIT_CONTEXT: dict[int, tuple[str, str]] = {
    1: ("Main Propulsion",       "HIGH"),
    2: ("Navigation / Bridge",   "HIGH"),
    3: ("Ballast / Safety",      "CRITICAL"),
    4: ("Power Management",      "HIGH"),
    5: ("HVAC / Environmental",  "MEDIUM"),
    6: ("Fire Safety & Alarms",  "CRITICAL"),
    7: ("Fuel Management",       "HIGH"),
    8: ("Stabilizer / Motion",   "MEDIUM"),
}

_SAFETY_TYPES = {"Binary On/Off", "Alarm / Event", "Command"}


def _unit_label(uid: int) -> str:
    ctx = _UNIT_CONTEXT.get(uid)
    return f"Unit {uid} \u2014 {ctx[0]}" if ctx else f"Unit {uid}"


def _p(text: str) -> str:
    """Convert a string to latin-1-safe text for fpdf2's built-in fonts."""
    return text.replace("\u2014", " - ").replace("\u2713", "*").replace(
        "\u2712", "*").replace("\u26a1", "").encode("latin-1", "replace").decode("latin-1")


def _base_severity(uid: int) -> str:
    return _UNIT_CONTEXT.get(uid, ("Unknown", "LOW"))[1]


def _score(rec: dict[str, Any], written: set[tuple[str, int, int]]) -> str:
    uid   = rec["unit_id"]
    addr  = rec["addr"]
    rtype = rec.get("type", "")
    was_written = (rec.get("ip", ""), uid, addr) in written
    base = _base_severity(uid)
    if was_written:
        if base == "CRITICAL" or rtype in _SAFETY_TYPES:
            return "CRITICAL"
        return "HIGH"
    if rec.get("writable") and rtype in _SAFETY_TYPES:
        return "HIGH" if base != "CRITICAL" else "CRITICAL"
    if rec.get("writable"):
        return "MEDIUM"
    return "LOW"


# ── Shared data builder ───────────────────────────────────────────────────────

def _build_findings(
    controllers: set[str],
    field_devices: set[str],
    classifications: list[dict[str, Any]],
    written: set[tuple[str, int, int]],
) -> list[dict]:
    findings: list[dict] = []
    all_hosts = sorted(controllers | field_devices)

    if all_hosts:
        findings.append({
            "severity": "CRITICAL",
            "title":    "Modbus TCP provides no authentication or encryption",
            "hosts":    all_hosts,
            "detail":   (
                "Modbus TCP has no built-in authentication, session management, or encryption. "
                "Any host on the same network segment can read all registers and issue write "
                "commands to any unit ID without credentials. Successful unauthenticated reads "
                "and writes were confirmed during this assessment."
            ),
            "rec": (
                "Deploy a Modbus application-layer firewall to enforce read-only access for "
                "monitoring stations and whitelist write access by source IP, function code, "
                "unit ID, and address range. Segment the OT network with a unidirectional "
                "data diode for monitoring traffic."
            ),
        })

    if classifications:
        n_units = len(set(r["unit_id"] for r in classifications))
        findings.append({
            "severity": "INFO",
            "title":    f"All {len(classifications)} holding registers readable without authentication",
            "hosts":    sorted(field_devices),
            "detail":   (
                f"{len(classifications)} holding registers across {n_units} unit ID(s) were "
                "enumerated using FC3 (Read Holding Registers) with no credentials."
            ),
            "rec": "Restrict FC3 reads to authorised SCADA/HMI IP addresses via Modbus firewall rules.",
        })

    writable_recs = [
        r for r in classifications
        if (r.get("ip", ""), r["unit_id"], r["addr"]) in written or r.get("writable")
    ]
    for rec in sorted(writable_recs,
                      key=lambda r: (_SEV_ORDER.get(_score(r, written), 9),
                                     r["unit_id"], r["addr"])):
        sev    = _score(rec, written)
        uid    = rec["unit_id"]
        addr   = rec["addr"]
        rtype  = rec.get("type", "Unknown")
        conf   = rec.get("confidence", "?")
        hint   = rec.get("hint", "").split("\u26a1")[0].strip()
        mn, mx = rec.get("min", "?"), rec.get("max", "?")
        origin = "injected during this assessment" if (rec.get("ip", ""), uid, addr) in written \
                 else "observed in captured Modbus traffic"
        findings.append({
            "severity": sev,
            "title":    f"Unauthenticated write accepted — {_unit_label(uid)}, Addr {addr} ({rtype})",
            "hosts":    sorted(field_devices),
            "detail":   (
                f"An FC6 (Write Single Register) command targeting Unit {uid}, Address {addr} "
                f"was accepted with no authentication ({origin}). Register classified as "
                f"{rtype} ({conf} confidence), observed range {mn}-{mx}. {hint}"
            ),
            "rec": (
                "Enforce write-protection at the gateway. Safety-system outputs must require "
                "hardware interlock confirmation and must not be activatable via unauthenticated "
                "Modbus TCP alone."
            ),
        })

    findings.sort(key=lambda f: _SEV_ORDER.get(f["severity"], 9))
    return findings


# ── Markdown generator ────────────────────────────────────────────────────────

def _generate_markdown(
    *,
    controllers: set[str],
    field_devices: set[str],
    classifications: list[dict[str, Any]],
    written: set[tuple[str, int, int]],
    packet_count: int,
    target_network: str,
    ts: str,
    output_path: Path,
) -> Path:
    findings = _build_findings(controllers, field_devices, classifications, written)
    counts: dict[str, int] = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        counts[f["severity"]] += 1

    L: list[str] = []
    def a(s: str = "") -> None: L.append(s)

    a("# Modbuster — OT/ICS Penetration Test Report")
    a()
    a(f"**Date:** {ts}  ")
    a(f"**Tool:** Modbuster  ")
    if target_network:
        a(f"**Target Network:** {target_network}  ")
    a()
    a("> **AUTHORIZED USE ONLY.**")
    a()
    a("---")
    a()
    a("## Executive Summary")
    a()
    a("| Severity | Findings |")
    a("|----------|----------|")
    for sev in _SEV_ORDER:
        if counts[sev]:
            a(f"| **{sev}** | {counts[sev]} |")
    a()
    a("## Vulnerability Findings")
    a()
    for i, f in enumerate(findings, 1):
        a(f"### Finding {i} — [{f['severity']}] {f['title']}")
        a()
        a(f"**Severity:** {f['severity']}  ")
        a(f"**Hosts:** {', '.join(f['hosts']) if f['hosts'] else 'N/A'}  ")
        a()
        a(f"**Description:** {f['detail']}")
        a()
        a(f"**Recommendation:** {f['rec']}")
        a()
        a("---")
        a()
    a("## Register Classification Map")
    a()
    by_unit: dict[int, list] = {}
    for r in classifications:
        by_unit.setdefault(r["unit_id"], []).append(r)
    for uid in sorted(by_unit):
        a(f"### {_unit_label(uid)}")
        a()
        a("| Addr | Type | Conf | Last Val | Range | Hint |")
        a("|------|------|------|----------|-------|------|")
        for r in sorted(by_unit[uid], key=lambda x: x["addr"]):
            mark = " ✎" if (r.get("ip", ""), uid, r["addr"]) in written else ""
            hint = r.get("hint", "").split("⚡")[0].strip().replace("|", "\\|")
            a(f"| {r['addr']}{mark} | {r.get('type','?')} | {r.get('confidence','?')} "
              f"| {r.get('last_value','?')} | {r.get('min','?')}–{r.get('max','?')} | {hint} |")
        a()
    a("## General Recommendations")
    a()
    recs = [
        ("Network segmentation", "Isolate OT on dedicated VLANs with unidirectional data diodes for monitoring."),
        ("Modbus application firewall", "Enforce read-only for monitoring; whitelist writes by IP, FC, unit, and address range."),
        ("Block write FCs at boundary", "Block FC5/FC6/FC15/FC16 for all sources except authorised controller IP."),
        ("Hardware interlocks on safety outputs", "Safety actuators must require physical confirmation, not software alone."),
        ("Continuous OT monitoring", "Deploy passive monitoring to alert on anomalous writes or new unit IDs."),
        ("Vendor register documentation", "Obtain full register map and validate against discovered layout."),
    ]
    for i, (title, body) in enumerate(recs, 1):
        a(f"{i}. **{title}** — {body}")
    a()
    a("---")
    a()
    a(f"*Report generated by Modbuster · {ts}. Requires validation before remediation.*")

    output_path.write_text("\n".join(L), encoding="utf-8")
    return output_path


# ── PDF generator ─────────────────────────────────────────────────────────────

def _generate_pdf(
    *,
    controllers: set[str],
    field_devices: set[str],
    classifications: list[dict[str, Any]],
    written: set[tuple[str, int, int]],
    packet_count: int,
    target_network: str,
    ts: str,
    output_path: Path,
) -> Path:
    from fpdf import FPDF  # lazy import — optional dependency

    class _PDF(FPDF):
        def __init__(self, title: str, ts: str):
            super().__init__()
            self._doc_title = title
            self._doc_ts    = ts
            self.set_auto_page_break(auto=True, margin=18)
            self.set_margins(18, 18, 18)

        def header(self) -> None:
            self.set_fill_color(*_ORANGE)
            self.rect(0, 0, 210, 8, "F")
            self.set_y(11)
            self.set_font("Helvetica", "B", 8)
            self.set_text_color(*_MID)
            self.cell(0, 4, "MODBUSTER - OT/ICS PENTEST REPORT  |  CONFIDENTIAL", align="C")
            self.ln(4)

        def footer(self) -> None:
            self.set_y(-14)
            self.set_font("Helvetica", "", 7)
            self.set_text_color(*_MID)
            self.cell(0, 4, f"{self._doc_ts}  |  Modbuster  |  Authorized Use Only", align="L")
            self.cell(0, 4, f"Page {self.page_no()}", align="R")

        def h1(self, text: str) -> None:
            self.ln(6)
            self.set_font("Helvetica", "B", 16)
            self.set_text_color(*_ORANGE)
            self.cell(0, 9, _p(text), ln=True)
            self.set_draw_color(*_ORANGE)
            self.set_line_width(0.6)
            self.line(18, self.get_y(), 192, self.get_y())
            self.ln(4)

        def h2(self, text: str) -> None:
            self.ln(4)
            self.set_font("Helvetica", "B", 12)
            self.set_text_color(*_DARK)
            self.set_fill_color(*_LIGHT)
            self.cell(0, 7, f"  {_p(text)}", fill=True, ln=True)
            self.ln(2)

        def h3(self, text: str) -> None:
            self.ln(3)
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*_DARK)
            self.cell(0, 6, _p(text), ln=True)

        def body(self, text: str, indent: float = 0) -> None:
            self.set_font("Helvetica", "", 9)
            self.set_text_color(*_MID)
            self.set_x(18 + indent)
            self.multi_cell(0, 5, _p(text))
            self.ln(1)

        def sev_badge(self, sev: str, x: float, y: float) -> None:
            col = _SEV_COLOUR.get(sev, _MID)
            self.set_fill_color(*col)
            self.set_text_color(*_WHITE)
            self.set_font("Helvetica", "B", 8)
            self.set_xy(x, y)
            self.cell(22, 5, sev, fill=True, align="C")
            self.set_text_color(*_DARK)

        def finding_box(self, num: int, sev: str, title: str,
                        hosts: list[str], detail: str, rec: str) -> None:
            col = _SEV_COLOUR.get(sev, _MID)
            self.set_fill_color(*col)
            top_y = self.get_y()
            self.rect(18, top_y, 3, 32, "F")
            self.set_x(24)
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(*_DARK)
            self.cell(22, 6, f"Finding {num}", ln=False)
            self.sev_badge(sev, self.get_x(), self.get_y())
            self.set_x(self.get_x() + 24)
            self.set_font("Helvetica", "B", 9)
            self.multi_cell(0, 6, _p(title))
            self.set_x(24)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(*_MID)
            self.cell(0, 4, "Affected: " + _p(", ".join(hosts) if hosts else "N/A"), ln=True)
            self.set_x(24)
            self.set_font("Helvetica", "", 8.5)
            self.multi_cell(0, 4.5, _p(detail))
            self.set_x(24)
            self.set_font("Helvetica", "B", 8.5)
            self.set_text_color(*_DARK)
            self.cell(28, 4.5, "Recommendation: ")
            self.set_font("Helvetica", "", 8.5)
            self.set_text_color(*_MID)
            self.multi_cell(0, 4.5, _p(rec))
            bot_y = self.get_y()
            self.set_fill_color(*col)
            self.rect(18, top_y, 3, bot_y - top_y, "F")
            self.ln(4)

        def table_header(self, cols: list[tuple[str, float]]) -> None:
            self.set_fill_color(*_DARK)
            self.set_text_color(*_WHITE)
            self.set_font("Helvetica", "B", 8)
            for label, w in cols:
                self.cell(w, 6, _p(label), border=0, fill=True, align="C")
            self.ln()
            self.set_text_color(*_DARK)

        def table_row(self, cells: list[tuple[str, float]],
                      shade: bool = False,
                      col_overrides: dict[int, tuple[int,int,int]] | None = None) -> None:
            self.set_font("Helvetica", "", 7.5)
            self.set_fill_color(*(_LIGHT if shade else _WHITE))
            col_overrides = col_overrides or {}
            for i, (text, w) in enumerate(cells):
                self.set_text_color(*(col_overrides.get(i, _DARK)))
                self.cell(w, 5, _p(text), border="B", fill=True)
            self.ln()
            self.set_text_color(*_DARK)

    findings = _build_findings(controllers, field_devices, classifications, written)
    counts: dict[str, int] = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        counts[f["severity"]] += 1

    pdf = _PDF(title="Modbuster Pentest Report", ts=ts)
    pdf.add_page()

    # Cover block
    pdf.set_fill_color(*_DARK)
    pdf.rect(18, 20, 174, 38, "F")
    pdf.set_xy(22, 24)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*_ORANGE)
    pdf.cell(0, 10, "Modbuster", ln=True)
    pdf.set_x(22)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*_WHITE)
    pdf.cell(0, 6, "OT / ICS Penetration Test Report", ln=True)
    pdf.set_x(22)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(180, 180, 180)
    meta = f"Date: {ts}"
    if target_network:
        meta += f"   |   Target: {target_network}"
    pdf.cell(0, 6, meta, ln=True)
    pdf.set_y(62)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(*_MID)
    pdf.cell(0, 5,
             "AUTHORIZED USE ONLY - Generated from active testing against explicitly authorized systems.",
             align="C", ln=True)
    pdf.ln(4)

    # ── Executive Summary ─────────────────────────────────────────────────────
    pdf.h1("Executive Summary")
    pdf.body(
        "Active unauthenticated access to the OT network confirmed multiple vulnerabilities. "
        "The Modbus TCP protocol provides no authentication mechanism. All holding registers "
        "across all unit IDs were accessible for read operations, and write commands were "
        "accepted with no credentials from an unprivileged network position."
    )
    pdf.ln(2)

    cols = [("Severity", 50), ("Findings", 30), ("Description", 94)]
    pdf.table_header(cols)
    sev_desc = {
        "CRITICAL": "Direct physical impact; safety systems affected",
        "HIGH":     "Write access to operational systems confirmed",
        "MEDIUM":   "Write traffic observed; impact requires verification",
        "LOW":      "Read-only access to operational registers",
        "INFO":     "Protocol-level observations",
    }
    for i, sev in enumerate(_SEV_ORDER):
        if counts.get(sev, 0):
            pdf.table_row(
                [(sev, 50), (str(counts[sev]), 30), (sev_desc.get(sev, ""), 94)],
                shade=(i % 2 == 0),
                col_overrides={0: _SEV_COLOUR[sev]},
            )
    pdf.ln(4)

    # ── Methodology ───────────────────────────────────────────────────────────
    pdf.h1("Scope & Methodology")
    steps = [
        ("1", "Passive traffic analysis via SPAN port capture of Modbus TCP traffic"),
        ("2", "Host discovery - TCP/UDP probe of OT subnet for live devices"),
        ("3", "Unit ID sweep - FC3 across all 247 Modbus unit IDs per host"),
        ("4", "Register mapping - FC3 bulk read, address range 0-1000"),
        ("5", "Offline classification - 19-rule inference engine applied to traffic patterns"),
        ("6", "Injection testing - FC6 writes to confirm unauthenticated write access"),
    ]
    cols = [("Step", 18), ("Action", 156)]
    pdf.table_header(cols)
    for i, (step, action) in enumerate(steps):
        pdf.table_row([(step, 18), (action, 156)], shade=(i % 2 == 0))
    pdf.ln(4)

    # ── Discovered Hosts ──────────────────────────────────────────────────────
    pdf.h1("Discovered Hosts")
    cols = [("IP Address", 50), ("Role", 80), ("Service", 44)]
    pdf.table_header(cols)
    all_rows = (
        [(ip, "Controller / Modbus Master", "TCP :502") for ip in sorted(controllers)] +
        [(ip, "Field Device / Modbus Slave", "TCP :502") for ip in sorted(field_devices)]
    )
    if not all_rows:
        all_rows = [("-", "No hosts discovered in this session", "-")]
    for i, (ip, role, svc) in enumerate(all_rows):
        pdf.table_row([(ip, 50), (role, 80), (svc, 44)], shade=(i % 2 == 0))
    pdf.ln(4)

    # ── Findings ──────────────────────────────────────────────────────────────
    pdf.h1("Vulnerability Findings")
    for i, f in enumerate(findings, 1):
        pdf.finding_box(
            num=i, sev=f["severity"], title=f["title"],
            hosts=f["hosts"], detail=f["detail"], rec=f["rec"],
        )

    # ── Register Map ──────────────────────────────────────────────────────────
    pdf.h1("Register Classification Map")
    n_units = len(set(r["unit_id"] for r in classifications))
    pdf.body(
        f"{len(classifications)} registers classified across {n_units} unit ID(s) "
        f"from {packet_count:,} observed packets.  \u2712 = written during this assessment."
    )

    by_unit: dict[int, list] = {}
    for r in classifications:
        by_unit.setdefault(r["unit_id"], []).append(r)

    cols = [("Addr", 16), ("Type", 40), ("Conf", 20), ("Last Val", 20),
            ("Range", 26), ("Hint", 52)]
    for uid in sorted(by_unit):
        pdf.h2(_unit_label(uid))
        pdf.table_header(cols)
        for j, r in enumerate(sorted(by_unit[uid], key=lambda x: x["addr"])):
            mark = " \u2712" if (r.get("ip", ""), uid, r["addr"]) in written else ""
            hint = r.get("hint", "").split("\u26a1")[0].strip()[:60]
            mn, mx = str(r.get("min", "?")), str(r.get("max", "?"))
            overrides = {0: _ORANGE} if (r.get("ip", ""), uid, r["addr"]) in written else {}
            pdf.table_row(
                [(str(r["addr"]) + mark, 16),
                 (r.get("type", "?"), 40),
                 (r.get("confidence", "?"), 20),
                 (str(r.get("last_value", "?")), 20),
                 (f"{mn}-{mx}", 26),
                 (hint, 52)],
                shade=(j % 2 == 0),
                col_overrides=overrides,
            )
        pdf.ln(2)

    # ── Recommendations ───────────────────────────────────────────────────────
    pdf.h1("General Recommendations")
    recs = [
        ("1. Network segmentation",
         "Isolate OT devices on dedicated VLANs with no direct path from IT or guest networks. "
         "Use unidirectional data diodes for north-bound monitoring traffic."),
        ("2. Modbus application firewall",
         "Deploy a protocol-aware firewall enforcing read-only for monitoring stations, "
         "write restrictions by source IP and function code, and unit ID/address-range whitelisting."),
        ("3. Block write function codes at the boundary",
         "If the SCADA system only reads data, block FC5, FC6, FC15, and FC16 at the gateway "
         "for all sources except the authorised controller IP."),
        ("4. Hardware interlocks on safety outputs",
         "Fire suppression, bilge pumps, and flood-control registers must require physical "
         "confirmation (key switch, hardware interlock) - not software-activatable alone."),
        ("5. Continuous OT monitoring",
         "Deploy passive monitoring (Dragos, Claroty, or Zeek with Modbus scripts) to alert "
         "on anomalous writes, new unit IDs, or unusual register access patterns."),
        ("6. Vendor register documentation",
         "Obtain a complete register map for all PLCs/RTUs and validate it against this "
         "assessment's discovered register layout to identify undocumented addresses."),
    ]
    for title, body in recs:
        pdf.h3(title)
        pdf.body(body, indent=4)

    pdf.ln(4)
    pdf.set_font("Helvetica", "I", 7.5)
    pdf.set_text_color(*_MID)
    pdf.multi_cell(
        0, 4,
        f"Report generated by Modbuster · {ts}. All findings require validation against "
        "specific device firmware, configuration, and operational context before remediation."
    )

    pdf.output(str(output_path))
    return output_path


# ── Public entry point ────────────────────────────────────────────────────────

def generate(
    *,
    controllers:     set[str],
    field_devices:   set[str],
    classifications: list[dict[str, Any]],
    written:         set[tuple[str, int, int]],
    packet_count:    int,
    target_network:  str = "",
    output_path:     Path,
) -> Path:
    """Write a PDF or Markdown report to *output_path* based on file extension."""
    now = datetime.now()
    ts  = now.strftime("%Y-%m-%d %H:%M")

    if output_path.suffix.lower() == ".md":
        return _generate_markdown(
            controllers=controllers, field_devices=field_devices,
            classifications=classifications, written=written,
            packet_count=packet_count, target_network=target_network,
            ts=ts, output_path=output_path,
        )

    output_path = output_path.with_suffix(".pdf")
    return _generate_pdf(
        controllers=controllers, field_devices=field_devices,
        classifications=classifications, written=written,
        packet_count=packet_count, target_network=target_network,
        ts=ts, output_path=output_path,
    )
