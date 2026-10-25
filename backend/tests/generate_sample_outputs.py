"""
generate_sample_outputs.py

Walks a given root folder AND ALL ITS SUBFOLDERS, and saves a
representative sample of REAL parsed JSON outputs per subfolder to
docs/sample_outputs/ (mirroring the source folder structure).

This is what the rest of the team pulls from to see exactly what your
parser produces — real data, not synthetic examples.

We do NOT dump every single file in a folder (could be hundreds) — just
a representative sample (default 3 per subfolder) so docs/sample_outputs/
stays small and readable.

UNIVERSAL BY DESIGN (merged in from test_parse_any.py / run_batch_test.py):
Uses parse_any() instead of parse_email(), so it's not limited to single
.eml/.msg/.rfc822 files — .csv bulk datasets are picked up too. Since
parse_any() returns a LIST for bulk files, each one is sampled
(--per-category entries from inside it) and saved as its own subfolder
named after the csv file.

No more separate hardcoded extracted_root / fixtures_root — this walks
the ENTIRE root folder you give it, recursively, so any new subfolder
you add underneath it (fixtures, a new dataset, a new bulk csv,
wherever) gets picked up automatically without editing this script.

Usage (run from backend/):
    python tests/generate_sample_outputs.py
    python tests/generate_sample_outputs.py "../samples/dataset_for_parser"
    python tests/generate_sample_outputs.py "../samples/dataset_for_parser" --per-category 5
"""

import sys
import os
import json
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from email_parser import parse_any

SAMPLEABLE_EXT = (".eml", ".msg", ".rfc822", ".rfc822msg")
BULK_EXT = (".csv",)


def save_json(data, out_path):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument(
        "root_folder", nargs="?",
        default=None,
        help="Folder to walk recursively (default: samples/dataset_for_parser)"
    )
    arg_parser.add_argument("--per-category", type=int, default=3,
                             help="How many sample files/rows to save per subfolder (default 3)")
    args = arg_parser.parse_args()

    backend_dir = os.path.join(os.path.dirname(__file__), "..")
    default_root = os.path.join(backend_dir, "..", "samples", "dataset_for_parser")
    root_folder = args.root_folder or default_root
    output_dir = os.path.join(backend_dir, "..", "docs", "sample_outputs")

    os.makedirs(output_dir, exist_ok=True)

    if not os.path.isdir(root_folder):
        print(f"Error: '{root_folder}' is not a folder")
        sys.exit(1)

    total_saved = 0
    per_category_counts = {}

    for dirpath, _dirnames, filenames in os.walk(root_folder):
        rel = os.path.relpath(dirpath, root_folder)
        category = "." if rel == "." else rel

        eml_files = sorted(
            f for f in filenames if f.lower().endswith(SAMPLEABLE_EXT)
        )[: args.per_category]

        csv_files = sorted(f for f in filenames if f.lower().endswith(BULK_EXT))

        if not eml_files and not csv_files:
            continue

        saved_here = 0

        # ---- single-email files (.eml/.msg/.rfc822) ----
        for fname in eml_files:
            full_path = os.path.join(dirpath, fname)
            try:
                result = parse_any(full_path)
                data = result.to_dict()  # single files -> single ParsedEmail
                out_name = os.path.splitext(fname)[0] + ".json"
                out_path = os.path.join(output_dir, rel, out_name) if rel != "." else os.path.join(output_dir, out_name)
                save_json(data, out_path)
                saved_here += 1
                total_saved += 1
            except Exception as e:
                print(f"  [FAIL] {category}/{fname}  ->  {e}")

        # ---- bulk files (.csv) -> sample N rows out of the returned list ----
        for fname in csv_files:
            full_path = os.path.join(dirpath, fname)
            try:
                result = parse_any(full_path)
                emails = result if isinstance(result, list) else [result]
                sample = emails[: args.per_category]

                csv_out_subdir = os.path.splitext(fname)[0]
                for i, email in enumerate(sample):
                    data = email.to_dict()
                    out_name = f"{i:04d}.json"
                    out_path = os.path.join(output_dir, rel, csv_out_subdir, out_name) if rel != "." \
                        else os.path.join(output_dir, csv_out_subdir, out_name)
                    save_json(data, out_path)
                    saved_here += 1
                    total_saved += 1

                print(f"  [OK] {category}/{fname}: bulk dataset, {len(emails)} total rows, "
                      f"saved {len(sample)} sample(s)")
            except Exception as e:
                print(f"  [FAIL] {category}/{fname}  ->  {e}")

        if eml_files:
            print(f"  [OK] {category}: saved {len(eml_files)} sample(s)")

        per_category_counts[category] = saved_here

    if total_saved == 0:
        print(f"No sampleable files (.eml/.msg/.rfc822/.csv) found anywhere under {root_folder}")
        sys.exit(1)

    print(f"\nTotal sample JSON files saved: {total_saved}")
    print(f"Location: {output_dir}")
    print("Commit and push docs/sample_outputs/ so the team can use it.")


if __name__ == "__main__":
    main()
