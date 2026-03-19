"""Summary stats and CSV/JSON export for pentest reports."""

import csv
import json
from pathlib import Path
from typing import Any, Dict, List

from modbuster.interpreter import summary


def export_json(records: List[Dict[str, Any]], path: str) -> None:
    """Write summary + optional record list to JSON."""
    data = summary(records)
    data["records"] = records
    path_obj = Path(path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    with open(path_obj, "w") as f:
        json.dump(data, f, indent=2)


def export_csv(records: List[Dict[str, Any]], path: str) -> None:
    """Write flattened records to CSV (protocol, direction, unit_id, op_name, addr, value, etc.)."""
    if not records:
        return
    path_obj = Path(path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    keys = set()
    for r in records:
        keys.update(k for k in r if isinstance(r.get(k), (str, int, float, type(None))))
    fieldnames = sorted(keys)
    with open(path_obj, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in records:
            row = {k: v for k, v in r.items() if isinstance(v, (str, int, float, type(None)))}
            # list/dict as string for CSV
            for k, v in list(row.items()):
                if isinstance(v, (list, dict)):
                    row[k] = json.dumps(v)
            w.writerow(row)


def export_summary_only(records: List[Dict[str, Any]], path: str) -> None:
    """Write only summary (no full record list) to JSON."""
    data = summary(records)
    path_obj = Path(path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    with open(path_obj, "w") as f:
        json.dump(data, f, indent=2)
