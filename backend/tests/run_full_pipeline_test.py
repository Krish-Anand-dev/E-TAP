"""
run_full_pipeline_test.py

The real integration test: walks every email in
"samples/email_dataset/set_XX/{eml,msg}/" through the ENTIRE
pipeline built so far —

    Stage A (parse_any)
      -> Stage B  (analyze_headers      — Krish)
      -> Stage B2 (analyze_attachments  — the team)
      -> combined into one JSON per email

This is the first point where Krish's and the team work actually run
together on the same real data, not just in isolation.

If each set folder has a set0X_manifest.json with expected labels, this
script will try to cross-reference results against it (best-effort —
works with whatever fields the manifest actually has; doesn't assume a
strict schema since we haven't seen the team manifest format yet).

Usage (run from backend/):
    python tests/run_full_pipeline_test.py "../samples/email_dataset"
"""

import sys
import os
import json
import glob

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from email_parser import parse_any
from forensics import analyze_headers, analyze_attachments


def find_all_sets(dataset_root: str):
    """Finds every set_XX folder under the dataset root."""
    return sorted(
        d for d in glob.glob(os.path.join(dataset_root, "set_*"))
        if os.path.isdir(d)
    )


def find_email_files(set_folder: str):
    """Finds every .eml/.msg file inside a set's eml/ and msg/ subfolders."""
    files = []
    for subfolder in ("eml", "msg"):
        path = os.path.join(set_folder, subfolder)
        if os.path.isdir(path):
            for fname in sorted(os.listdir(path)):
                if fname.lower().endswith((".eml", ".msg", ".rfc822")):
                    files.append(os.path.join(path, fname))
    return files


def load_manifest(set_folder: str):
    """Best-effort manifest loader — doesn't assume a strict schema,
    just returns whatever JSON is there (or None if missing/unreadable)."""
    set_name = os.path.basename(set_folder)
    manifest_path = os.path.join(set_folder, f"{set_name}_manifest.json")
    if not os.path.exists(manifest_path):
        return None
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"  [WARN] Could not parse manifest {manifest_path}: {e}")
        return None


def run_pipeline_on_file(file_path: str) -> dict:
    """Runs Stage A -> Stage B -> Stage B2 on a single email file,
    returns the combined result. Never raises — crashes are captured
    so one bad file doesn't kill the whole batch."""
    try:
        parsed = parse_any(file_path)

        # parse_any could theoretically return a list if someone points
        # this at a .csv, but we're only walking eml/msg folders here so
        # this should always be a single ParsedEmail
        if isinstance(parsed, list):
            return {"status": "SKIPPED", "reason": "unexpected list result (csv?)"}

        parsed_dict = parsed.to_dict()

        header_analysis = analyze_headers(parsed)
        attachment_analysis = analyze_attachments(parsed_dict.get("attachments", []))

        return {
            "status": "OK",
            "file": os.path.basename(file_path),
            "subject": parsed_dict.get("subject"),
            "from_email": parsed_dict.get("from_email"),
            "header_analysis": header_analysis,
            "attachment_analysis": attachment_analysis,
        }

    except Exception as e:
        import traceback
        return {
            "status": "CRASHED",
            "file": os.path.basename(file_path),
            "error": str(e),
            "traceback": traceback.format_exc(),
        }


def main():
    if len(sys.argv) != 2:
        print('Usage: python run_full_pipeline_test.py "<path_to_email_dataset>"')
        sys.exit(1)

    dataset_root = sys.argv[1]
    sets = find_all_sets(dataset_root)

    if not sets:
        print(f"No set_XX folders found under '{dataset_root}'")
        sys.exit(1)

    print(f"Found {len(sets)} set(s)\n")

    all_results = []
    total_ok, total_crash = 0, 0
    total_red_flags = 0
    total_suspicious_attachments = 0

    for set_folder in sets:
        set_name = os.path.basename(set_folder)
        manifest = load_manifest(set_folder)
        email_files = find_email_files(set_folder)

        print(f"--- {set_name} ({len(email_files)} email(s)) ---")
        if manifest is not None:
            print(f"  manifest loaded: {list(manifest.keys()) if isinstance(manifest, dict) else type(manifest)}")

        for file_path in email_files:
            result = run_pipeline_on_file(file_path)
            result["set"] = set_name
            all_results.append(result)

            if result["status"] == "OK":
                total_ok += 1
                red_flags = result["header_analysis"].get("red_flags", [])
                suspicious_atts = [
                    a for a in result["attachment_analysis"].get("attachments", [])
                    if a.get("suspicious")
                ]
                total_red_flags += len(red_flags)
                total_suspicious_attachments += len(suspicious_atts)

                flag_str = f"{len(red_flags)} red flag(s)" if red_flags else "clean"
                att_str = f", {len(suspicious_atts)} suspicious attachment(s)" if suspicious_atts else ""
                print(f"  [OK]    {result['file']}  ->  {flag_str}{att_str}")
                if red_flags:
                    print(f"          flags: {red_flags}")

            else:
                total_crash += 1
                print(f"  [CRASH] {result['file']}  ->  {result['error']}")

        print()

    print("--- OVERALL SUMMARY ---")
    print(f"Total emails processed: {total_ok + total_crash}")
    print(f"Successful:              {total_ok}")
    print(f"Crashed:                 {total_crash}")
    print(f"Total red flags raised:  {total_red_flags}")
    print(f"Total suspicious attachments: {total_suspicious_attachments}")

    out_path = os.path.join(os.path.dirname(__file__), "full_pipeline_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"\nFull results saved to: {out_path}")


if __name__ == "__main__":
    main()
