"""Convert `pdftotext -layout` output of the official 2025 calendar to JSON.

Usage: python tools/import_calendar.py calendar.txt data/namedays.sk.json
The downloaded PDF is not needed at runtime. See data/SOURCE.md.
"""
import json
import re
import sys
from datetime import date, timedelta
from pathlib import Path


def convert(text: str) -> dict[str, list[str]]:
    entries = {}
    for line in text.splitlines():
        match = re.fullmatch(r"\s*(\d{1,2})\.\s*(\d{1,2})\.\s+(.+?)\s*", line)
        if not match:
            continue
        day, month = int(match[1]), int(match[2])
        key = date(2024, month, day).strftime("%m-%d")
        if key in entries:
            raise ValueError(f"Duplicate day: {key}")
        entries[key] = [] if match[3] == "-" else re.split(r"\s{2,}", match[3])
    expected = {(date(2024, 1, 1) + timedelta(days=i)).strftime("%m-%d") for i in range(366)}
    if set(entries) != expected:
        raise ValueError(f"Calendar mismatch: missing={sorted(expected - set(entries))}")
    return dict(sorted(entries.items()))


if __name__ == "__main__":
    entries = convert(Path(sys.argv[1]).read_text(encoding="utf-8"))
    Path(sys.argv[2]).write_text(json.dumps(entries, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Imported {len(entries)} days")
