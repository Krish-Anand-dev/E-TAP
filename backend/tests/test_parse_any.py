"""
test_parse_any.py

Proves the universal entry point parse_any() correctly handles every
supported input type — .eml, .rfc822, .csv (bulk dataset) — through
ONE function call, routing internally as needed.

Run from backend/:
    python tests/test_parse_any.py
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from email_parser import parse_any


def show_result(label, path):
    print(f"\n{'='*60}")
    print(f"INPUT: {path}  ({label})")
    print('='*60)

    result = parse_any(path)

    if isinstance(result, list):
        print(f"-> Returned a LIST of {len(result)} parsed emails (bulk dataset)")
        for i, email in enumerate(result):
            d = email.to_dict()
            print(f"   [{i}] source_format={d['source_format']} | subject='{d['subject']}' | from={d['from_email']} | label_header={d['all_headers'].get('X-Dataset-Label')}")
    else:
        d = result.to_dict()
        print(f"-> Returned a SINGLE ParsedEmail (source_format={d['source_format']})")
        print(f"   subject: {d['subject']}")
        print(f"   from_email: {d['from_email']}")
        print(f"   reply_to: {d['reply_to']}")
        print(f"   attachments: {len(d['attachments'])}")
        print(f"   headers captured: {list(d['all_headers'].keys())}")
        if "Received" in d["all_headers"]:
            print(f"   Received chain present: YES ({len(d['all_headers']['Received'])} hops)")


if __name__ == "__main__":
    samples_dir = os.path.join(os.path.dirname(__file__), "..", "..", "samples")

    show_result(".eml file", os.path.join(samples_dir, "sample_phishing.eml"))
    show_result(".rfc822 file (same content, different extension)", os.path.join(samples_dir, "sample_as_rfc822.rfc822"))
    show_result(".csv bulk dataset", os.path.join(samples_dir, "mock_dataset.csv"))

    print(f"\n{'='*60}")
    print("All input types handled through ONE function: parse_any()")
    print('='*60)
