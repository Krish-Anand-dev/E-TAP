"""Self-contained smoke test for the universal email parser entry point.

Exercises .eml, .rfc822 and .csv inputs without relying on ignored raw-email
fixtures or proprietary/corpus files being present in a fresh Git clone.

Run from backend/: python tests/test_parse_any.py
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from email_parser import parse_any


SAMPLE_EMAIL = (
    "From: security@example.test\r\n"
    "To: analyst@example.test\r\n"
    "Subject: Parser smoke-test message\r\n"
    "Date: Sat, 17 Oct 2026 12:00:00 +0000\r\n"
    "Message-ID: <parser-smoke@example.test>\r\n"
    "MIME-Version: 1.0\r\n"
    'Content-Type: text/plain; charset="utf-8"\r\n'
    "\r\n"
    "This is a synthetic parser fixture. Review the agenda at https://example.test/agenda.\r\n"
)


def show_result(label, path):
    print(f"\n{'=' * 60}")
    print(f"INPUT: {path}  ({label})")
    print("=" * 60)

    result = parse_any(path)

    if isinstance(result, list):
        print(f"-> Returned a LIST of {len(result)} parsed emails (bulk dataset)")
        for i, email in enumerate(result):
            d = email.to_dict()
            print(
                f"   [{i}] source_format={d['source_format']} | "
                f"subject='{d['subject']}' | from={d['from_email']} | "
                f"label_header={d['all_headers'].get('X-Dataset-Label')}"
            )
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
    return result


def main():
    with tempfile.TemporaryDirectory(prefix="etap-parse-any-") as temp_dir:
        eml_path = os.path.join(temp_dir, "synthetic_sample.eml")
        rfc822_path = os.path.join(temp_dir, "synthetic_sample.rfc822")
        csv_path = os.path.join(temp_dir, "synthetic_dataset.csv")

        with open(eml_path, "w", encoding="utf-8", newline="") as f:
            f.write(SAMPLE_EMAIL)
        with open(rfc822_path, "w", encoding="utf-8", newline="") as f:
            f.write(SAMPLE_EMAIL)
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            f.write(
                "sender,receiver,date,subject,body,label,urls\n"
                'security@example.test,analyst@example.test,"Sat, 17 Oct 2026 12:00:00 +0000",'
                '"CSV parser smoke test","Synthetic row body",benign,https://example.test/agenda\n'
                'alerts@example.test,analyst@example.test,"Sat, 17 Oct 2026 12:01:00 +0000",'
                '"Second CSV row","Another synthetic body",malicious,https://example.test/verify\n'
            )

        eml = show_result("synthetic .eml file", eml_path)
        rfc822 = show_result("synthetic .rfc822 file (same content, different extension)", rfc822_path)
        csv_rows = show_result("synthetic .csv bulk dataset", csv_path)

        assert eml.source_format == "eml"
        assert rfc822.source_format == "eml"
        assert isinstance(csv_rows, list) and len(csv_rows) == 2
        assert all(row.source_format == "csv" for row in csv_rows)
        assert csv_rows[0].all_headers.get("X-Dataset-Label") == ["benign"]

    print(f"\n{'=' * 60}")
    print("All supported parse_any input families handled using synthetic fixtures.")
    print("=" * 60)


if __name__ == "__main__":
    main()
