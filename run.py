"""Read-only validation runner. Frozen after setup.

Two modes:
  pre  <root> <changed_files_json> <proposed_dir>
  post <root>
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Dict, List

import core

PATH_RE = re.compile(r"^entries/([A-Za-z0-9][A-Za-z0-9._-]{0,127})\.json$")

FROZEN_PATHS = {"core.py", "run.py"}
FROZEN_PREFIXES = (".github/",)


def fail(reason: str) -> None:
    print(f"REJECTED: {reason}")
    sys.exit(1)


def is_frozen(path: str) -> bool:
    return path in FROZEN_PATHS or any(path.startswith(p) for p in FROZEN_PREFIXES)


def load_entries(entries_dir: Path) -> List[Dict[str, object]]:
    records: List[Dict[str, object]] = []
    if not entries_dir.is_dir():
        return records
    for p in sorted(entries_dir.glob("*.json")):
        raw = p.read_bytes()
        try:
            record = core.parse_canonical(raw)
        except core.ValidationError as exc:
            fail(f"existing entry {p.name} is invalid: {exc}")
            raise AssertionError("unreachable")
        try:
            core.validate_record(record)
        except core.ValidationError as exc:
            fail(f"existing entry {p.name} fails schema: {exc}")
            raise AssertionError("unreachable")
        records.append(record)
    return records


def run_pre(root: Path, changed_path: Path, proposed_dir: Path) -> None:
    entries_dir = root / "entries"
    changed = json.loads(changed_path.read_text(encoding="utf-8"))

    if len(changed) != 1:
        fail(f"proposed change touches {len(changed)} file(s); exactly one is required")

    item = changed[0]
    path = item["filename"]
    status = item["status"]

    if is_frozen(path):
        fail(f"{path!r} is a frozen setup path; it may never change after freeze")
    if status != "added":
        fail(f"{path!r} has status {status!r}; only a pure addition is permitted")

    match = PATH_RE.match(path)
    if not match:
        fail(f"{path!r} does not match the fixed grammar entries/<id>.json")
    path_id = match.group(1)

    proposed_file = proposed_dir / Path(path).name
    if not proposed_file.is_file():
        fail(f"proposed content for {path!r} was not fetched as data")

    raw = proposed_file.read_bytes()
    try:
        record = core.parse_canonical(raw)
    except core.ValidationError as exc:
        fail(f"proposed content is not canonical: {exc}")
        raise AssertionError("unreachable")

    try:
        core.validate_record(record)
    except core.ValidationError as exc:
        fail(f"proposed content fails schema: {exc}")

    if record.get("entry_id") != path_id:
        fail(f"path id {path_id!r} does not match record entry_id {record.get('entry_id')!r}")

    existing = load_entries(entries_dir)
    if record["entry_id"] in {r["entry_id"] for r in existing}:
        fail(f"entry_id {record['entry_id']!r} already exists")

    proposed = sorted(existing + [record], key=lambda r: r["sequence_number"])
    try:
        core.validate_chain(proposed)
    except core.ValidationError as exc:
        fail(f"proposed chain is invalid: {exc}")

    print(f"ACCEPTED: proposed chain of {len(proposed)} record(s) is valid")


def run_post(root: Path) -> None:
    entries_dir = root / "entries"
    existing = load_entries(entries_dir)
    if not existing:
        fail("no entries present")
    existing_sorted = sorted(existing, key=lambda r: r["sequence_number"])
    try:
        core.validate_chain(existing_sorted)
    except core.ValidationError as exc:
        fail(f"chain is invalid: {exc}")
    print(f"ACCEPTED: chain of {len(existing_sorted)} record(s) is valid")


def main() -> None:
    mode = sys.argv[1]
    root = Path(sys.argv[2])
    if mode == "pre":
        run_pre(root, Path(sys.argv[3]), Path(sys.argv[4]))
    elif mode == "post":
        run_post(root)
    else:
        fail(f"unknown mode {mode!r}")
    sys.exit(0)


if __name__ == "__main__":
    main()
