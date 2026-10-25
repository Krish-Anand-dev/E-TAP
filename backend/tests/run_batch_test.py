"""
run_batch_test.py

Runs the parser against every file found in a folder AND ALL ITS
SUBFOLDERS. Built for exactly your situation: "extracted/" contains
9 category subfolders (20021010_easy_ham, 20030228_spam, etc.) — this
script walks all of them in one call instead of you running it 9 times.

UNIVERSAL BY DESIGN (merged in from test_parse_any.py):
This uses parse_any() instead of parse_email(), so it's not limited to
single .eml/.msg files anymore — it also picks up bulk datasets like
.csv files, which parse_any() returns as a LIST of parsed emails rather
than a single one. Each email inside a bulk file is tracked and counted
individually in the summaries below, same as a standalone file would be.
There's no hardcoded extension whitelist gating what gets attempted —
every file found gets handed to parse_any(), which decides internally
how (or whether) to handle it. Anything it can't handle is caught and
reported as a crash for that file, same as before.

Usage:
    python tests/run_batch_test.py "../samples/dataset_for_parser/extracted"

Prints a per-category summary AND an overall summary, and saves full
results (including headers) to tests/batch_test_results.json.
"""

import sys
import os
import json
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from email_parser import parse_any

# Files we should never try to hand to parse_any() — not email data,
# just repo/OS noise that might be sitting in these folders.
IGNORE_NAMES = {".DS_Store", ".gitkeep", "README.md", "README.txt"}
IGNORE_EXT = {".json", ".py", ".pyc"}


def find_all_candidate_files(root_folder: str):
    """Walk root_folder and all subfolders, return list of (subfolder_label, full_path).
    No extension whitelist — every file is a candidate, parse_any() decides."""
    found = []
    for dirpath, _dirnames, filenames in os.walk(root_folder):
        for fname in filenames:
            if fname in IGNORE_NAMES:
                continue
            if os.path.splitext(fname)[1].lower() in IGNORE_EXT:
                continue
            rel_folder = os.path.relpath(dirpath, root_folder)
            label = "." if rel_folder == "." else rel_folder
            found.append((label, os.path.join(dirpath, fname)))
    return found


def build_entry(label, fname, data, sub_index=None):
    """Build a result entry dict for a single parsed email's to_dict() output."""
    entry = {"category": label, "file": fname}
    if sub_index is not None:
        entry["bulk_index"] = sub_index
    entry["status"] = "OK"
    entry["source_format"] = data["source_format"]
    entry["subject"] = data["subject"]
    entry["from_email"] = data["from_email"]
    entry["attachments_found"] = len(data["attachments"])
    entry["headers_found"] = list(data["all_headers"].keys())
    entry["has_received_chain"] = "Received" in data["all_headers"]
    entry["warnings"] = data["parse_warnings"]
    return entry


def run_batch(root_folder: str):
    if not os.path.isdir(root_folder):
        print(f"Error: '{root_folder}' is not a folder")
        sys.exit(1)

    files = find_all_candidate_files(root_folder)

    if not files:
        print(f"No files found in '{root_folder}' or its subfolders")
        sys.exit(1)

    print(f"Found {len(files)} file(s) across all subfolders of '{root_folder}'\n")

    results = []
    per_category = {}  # label -> {"ok": n, "warn": n, "crash": n}

    for label, full_path in files:
        fname = os.path.basename(full_path)
        per_category.setdefault(label, {"ok": 0, "warn": 0, "crash": 0})

        try:
            result = parse_any(full_path)

            if isinstance(result, list):
                # Bulk dataset (e.g. .csv) -> one entry per parsed email inside it
                for i, email in enumerate(result):
                    data = email.to_dict()
                    entry = build_entry(label, fname, data, sub_index=i)
                    if data["parse_warnings"]:
                        per_category[label]["warn"] += 1
                    else:
                        per_category[label]["ok"] += 1
                    results.append(entry)
            else:
                data = result.to_dict()
                entry = build_entry(label, fname, data)
                if data["parse_warnings"]:
                    per_category[label]["warn"] += 1
                else:
                    per_category[label]["ok"] += 1
                results.append(entry)

        except Exception as e:
            per_category[label]["crash"] += 1
            entry = {
                "category": label,
                "file": fname,
                "status": "CRASHED",
                "error": str(e),
                "traceback": traceback.format_exc(),
            }
            results.append(entry)

    # ---- per-category summary ----
    print("--- PER-CATEGORY SUMMARY ---")
    for label in sorted(per_category.keys()):
        c = per_category[label]
        total = c["ok"] + c["warn"] + c["crash"]
        print(f"  {label:30s}  total={total:4d}  ok={c['ok']:4d}  warn={c['warn']:4d}  crash={c['crash']:4d}")

    # ---- overall summary ----
    total_ok = sum(c["ok"] for c in per_category.values())
    total_warn = sum(c["warn"] for c in per_category.values())
    total_crash = sum(c["crash"] for c in per_category.values())

    print("\n--- OVERALL SUMMARY ---")
    print(f"Total files walked:  {len(files)}")
    print(f"Total parsed emails: {total_ok + total_warn} (bulk files can contain multiple)")
    print(f"Clean parses:        {total_ok}")
    print(f"Parsed w/ warnings:  {total_warn}")
    print(f"Crashed files:       {total_crash}")

    # ---- print details for any crashes (these are the ones you actually need to look at) ----
    crashed_entries = [e for e in results if e["status"] == "CRASHED"]
    if crashed_entries:
        print("\n--- CRASH DETAILS ---")
        for e in crashed_entries[:20]:  # cap at 20 so it doesn't flood the terminal
            print(f"  [{e['category']}/{e['file']}]  {e['error']}")
        if len(crashed_entries) > 20:
            print(f"  ... and {len(crashed_entries) - 20} more (see batch_test_results.json)")

    # ---- save full results ----
    out_path = os.path.join(os.path.dirname(__file__), "batch_test_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\nFull results saved to: {out_path}")

    sys.exit(1 if total_crash > 0 else 0)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('Usage: python run_batch_test.py "<folder_to_walk_recursively>"')
        sys.exit(1)

    run_batch(sys.argv[1])
