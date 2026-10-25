import sys
import os
import csv

# backend/tests -> backend -> project root
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

sys.path.insert(0, os.path.join(PROJECT_ROOT, "backend"))

from email_parser import parse_any
from forensics import analyze_headers, analyze_attachments, extract_iocs


CORPUS_DIR = os.path.join(PROJECT_ROOT, "samples", "EPVME_1")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "docs", "ioc_testing_csv")
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "EPVME_1_ioc_results.csv")


def main():

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    eml_files = []

    for root, _, files in os.walk(CORPUS_DIR):
        for file in files:
            if file.lower().endswith(".eml"):
                eml_files.append(os.path.join(root, file))

    eml_files.sort()
    eml_files = eml_files[:100]
    print(f"Corpus: {CORPUS_DIR}")
    print(f"Found {len(eml_files)} EML files")
    print(f"Output: {OUTPUT_CSV}")
    print()

    results = []

    for index, file_path in enumerate(eml_files, start=1):

        try:
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

            results.append({
                "file": os.path.relpath(file_path, PROJECT_ROOT),
                "filename": os.path.basename(file_path),
                "subject": parsed_dict.get("subject"),
                "from_email": parsed_dict.get("from_email"),

                "ip_count": len(ioc_analysis.get("ips", [])),
                "domain_count": len(ioc_analysis.get("domains", [])),
                "url_count": len(ioc_analysis.get("urls", [])),
                "hash_count": len(ioc_analysis.get("hashes", [])),

                "ips": "; ".join(ioc_analysis.get("ips", [])),
                "domains": "; ".join(ioc_analysis.get("domains", [])),
                "urls": "; ".join(ioc_analysis.get("urls", [])),
                "hashes": "; ".join(ioc_analysis.get("hashes", [])),

                "parse_status": "success",
                "error": "",
            })

        except Exception as e:

            results.append({
                "file": os.path.relpath(file_path, PROJECT_ROOT),
                "filename": os.path.basename(file_path),
                "subject": "",
                "from_email": "",

                "ip_count": 0,
                "domain_count": 0,
                "url_count": 0,
                "hash_count": 0,

                "ips": "",
                "domains": "",
                "urls": "",
                "hashes": "",

                "parse_status": "failed",
                "error": str(e),
            })

        if index % 100 == 0 or index == len(eml_files):
            print(f"Processed {index}/{len(eml_files)}")


    fieldnames = [
        "file",
        "filename",
        "subject",
        "from_email",
        "ip_count",
        "domain_count",
        "url_count",
        "hash_count",
        "ips",
        "domains",
        "urls",
        "hashes",
        "parse_status",
        "error",
    ]

    with open(
        OUTPUT_CSV,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    successful = sum(
        1 for r in results
        if r["parse_status"] == "success"
    )

    failed = len(results) - successful

    print()
    print("=== IOC BATCH TEST COMPLETE ===")
    print(f"Total emails : {len(results)}")
    print(f"Successful   : {successful}")
    print(f"Failed       : {failed}")
    print(f"CSV output   : {OUTPUT_CSV}")


if __name__ == "__main__":
    main()