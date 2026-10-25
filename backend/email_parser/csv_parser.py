"""
csv_parser.py

Handles bulk tabular datasets (CSV files with columns like sender,
receiver, date, subject, body, label, urls — the kind you get from
Kaggle/academic phishing datasets).

IMPORTANT DIFFERENCE FROM eml_parser/msg_parser:
A .csv file is not ONE email, it's a TABLE of many emails. So this module
returns a LIST of ParsedEmail objects, not a single one. Everything else
downstream needs to handle that difference — loop over the list instead
of expecting a single object.

Design choice: rather than writing separate extraction logic for CSV rows,
we build a real RFC822-formatted email in memory from each row and run it
through the SAME eml_parser.parse_eml_bytes() function used for real .eml
files. This means there's exactly ONE place that defines "how do we turn
headers+body into a ParsedEmail" — no duplicate/diverging logic between
real files and CSV-derived ones.

Usage:
    from email_parser.csv_parser import parse_csv_dataset

    results = parse_csv_dataset("dataset.csv", sample=300)
    for parsed_email in results:
        print(parsed_email.to_dict())
"""

import csv
import re
from datetime import datetime, timezone
from email.utils import format_datetime
from typing import List, Optional

from .eml_parser import parse_eml_bytes
from .models import ParsedEmail


COLUMN_ALIASES = {
    "sender": ["sender", "from", "sender email", "from_email"],
    "receiver": ["receiver", "to", "receiver email", "to_email"],
    "date": ["date", "date time", "datetime"],
    "subject": ["subject"],
    "body": ["body", "text", "content"],
    "label": ["label", "class", "type"],
    "urls": ["urls", "url", "links"],
}


def _normalize_columns(fieldnames) -> dict:
    mapping = {}
    lowered = {f.lower().strip(): f for f in fieldnames}
    for canonical, variants in COLUMN_ALIASES.items():
        for v in variants:
            if v in lowered:
                mapping[canonical] = lowered[v]
                break
    return mapping


def _clean_header_value(v) -> str:
    return str(v or "").replace("\n", " ").replace("\r", " ").strip()


def _row_to_eml_bytes(row: dict, col: dict, idx: int) -> bytes:
    sender = _clean_header_value(row.get(col.get("sender", ""), "")) or f"unknown_sender_{idx}@example.com"
    receiver = _clean_header_value(row.get(col.get("receiver", ""), "")) or "unknown_receiver@example.com"
    subject = _clean_header_value(row.get(col.get("subject", ""), "")) or "(no subject)"
    body = row.get(col.get("body", ""), "") or ""
    label = row.get(col.get("label", ""), "") if "label" in col else ""
    urls = row.get(col.get("urls", ""), "") if "urls" in col else ""

    date_str = row.get(col.get("date", ""), "") if "date" in col else ""
    date_header = date_str if date_str else format_datetime(datetime.now(timezone.utc))

    lines = [
        f"From: {sender}",
        f"To: {receiver}",
        f"Subject: {subject}",
        f"Date: {date_header}",
        f"Message-ID: <csv-row-{idx}@dataset.local>",
    ]
    if label:
        # keeps the dataset's ground-truth label attached, in case the team
        # (or anyone) wants to cross-check parser output against known labels
        lines.append(f"X-Dataset-Label: {label}")
    if urls:
        lines.append(f"X-Extracted-URLs: {str(urls).replace(chr(10), ' ')}")

    lines.append('Content-Type: text/plain; charset="utf-8"')
    lines.append("MIME-Version: 1.0")
    lines.append("")
    lines.append(str(body))

    return "\n".join(lines).encode("utf-8", errors="replace")


def parse_csv_dataset(csv_path: str, sample: Optional[int] = None) -> List[ParsedEmail]:
    """
    Parse a bulk CSV dataset into a list of ParsedEmail objects.

    Args:
        csv_path: path to the CSV file
        sample: if given, only parse the first N rows (recommended for large
                 datasets — no need to process all 39k rows for a smoke test)

    Returns:
        List[ParsedEmail] — one entry per CSV row, same shape/fields as a
        parsed .eml/.msg file, so downstream code doesn't need to special-case it.
        Each entry's source_format will be "csv" instead of "eml"/"msg" so
        you can tell where it came from if needed.
    """
    results: List[ParsedEmail] = []

    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        col = _normalize_columns(reader.fieldnames or [])

        for i, row in enumerate(reader):
            if sample is not None and i >= sample:
                break

            eml_bytes = _row_to_eml_bytes(row, col, i)
            parsed = parse_eml_bytes(eml_bytes)
            parsed.source_format = "csv"  # override so downstream knows this came from a bulk dataset, not a real file
            results.append(parsed)

    return results
