import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from email_parser import parse_any
from forensics import analyze_headers, analyze_attachments, extract_iocs


def main():
    if len(sys.argv) != 2:
        print("Usage: python tests/test_single_email.py <email.eml>")
        sys.exit(1)

    file_path = sys.argv[1]

    # Stage A — Parse / normalize email
    parsed = parse_any(file_path)
    parsed_dict = parsed.to_dict()

    # Stage B — Header forensics
    header_analysis = analyze_headers(parsed)

    # Stage B2 — Attachment forensics
    attachment_analysis = analyze_attachments(
        parsed_dict.get("attachments", [])
    )

    # Stage D — IOC extraction
    ioc_analysis = extract_iocs(
        all_headers=parsed_dict.get("all_headers", {}),
        body_text=parsed_dict.get("body_text"),
        body_html=parsed_dict.get("body_html"),
        attachment_analysis=attachment_analysis,
        header_analysis=header_analysis,
    )

    result = {
        "file": file_path,
        "subject": parsed_dict.get("subject"),
        "from_email": parsed_dict.get("from_email"),
        "header_analysis": header_analysis,
        "attachment_analysis": attachment_analysis,
        "ioc_analysis": ioc_analysis,
    }

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()