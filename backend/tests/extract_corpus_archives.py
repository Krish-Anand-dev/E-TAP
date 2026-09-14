"""
extract_corpus_archives.py

Extracts .tar.bz2 archives (SpamAssassin Public Corpus format, and similar
tarball-based email corpora) into individual .eml files.

Why this is needed: these archives contain THOUSANDS of individual raw
email files, each with NO extension (just a hash-like filename like
"0001.7c53336b37003a9286aba55d2945844c"). Your parser routes by file
extension, so we rename each extracted file to end in .eml as part of
extraction — content is unchanged, it's genuinely RFC822/eml format already,
just needs the right extension so parse_any() picks the correct code path.

Usage:
    python extract_corpus_archives.py <folder_of_tar_bz2_files> <output_folder> [--limit N]

Example:
    python extract_corpus_archives.py "../samples/Email Dataset for Parser/raw_archives" "../samples/Email Dataset for Parser/extracted" --limit 100

--limit N: only extract the first N files PER ARCHIVE (default: all).
Recommended to use a limit — these archives can contain 3000+ files each,
you don't need all of them for structural testing.
"""

import argparse
import os
import sys
import tarfile


def extract_archive(archive_path: str, output_folder: str, limit: int = None) -> int:
    """Extract one .tar.bz2 archive, renaming each member to end in .eml."""
    base_name = os.path.splitext(os.path.splitext(os.path.basename(archive_path))[0])[0]
    # e.g. "20030228_easy_ham.tar.bz2" -> base_name "20030228_easy_ham"

    dest_dir = os.path.join(output_folder, base_name)
    os.makedirs(dest_dir, exist_ok=True)

    extracted_count = 0

    with tarfile.open(archive_path, "r:bz2") as tar:
        members = [m for m in tar.getmembers() if m.isfile()]

        for member in members:
            if limit is not None and extracted_count >= limit:
                break

            f = tar.extractfile(member)
            if f is None:
                continue

            content = f.read()

            # original filenames have no extension, e.g. "0001.7c53336b37..."
            # sanitize and force a .eml extension
            original_name = os.path.basename(member.name)
            safe_name = original_name.replace("/", "_").replace("\\", "_")
            out_name = f"{safe_name}.eml"
            out_path = os.path.join(dest_dir, out_name)

            with open(out_path, "wb") as out_f:
                out_f.write(content)

            extracted_count += 1

    return extracted_count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("archives_folder", help="Folder containing .tar.bz2 files")
    parser.add_argument("output_folder", help="Where to write extracted .eml files")
    parser.add_argument("--limit", type=int, default=None,
                         help="Max files to extract PER archive (default: extract all)")
    args = parser.parse_args()

    if not os.path.isdir(args.archives_folder):
        print(f"Not a folder: {args.archives_folder}")
        sys.exit(1)

    archives = [f for f in sorted(os.listdir(args.archives_folder)) if f.endswith(".tar.bz2")]

    if not archives:
        print(f"No .tar.bz2 files found in {args.archives_folder}")
        sys.exit(1)

    print(f"Found {len(archives)} archive(s) to extract\n")

    total = 0
    for archive_name in archives:
        archive_path = os.path.join(args.archives_folder, archive_name)
        try:
            count = extract_archive(archive_path, args.output_folder, limit=args.limit)
            print(f"  [OK]   {archive_name}  ->  extracted {count} file(s)")
            total += count
        except Exception as e:
            print(f"  [FAIL] {archive_name}  ->  {e}")

    print(f"\nTotal extracted: {total} files -> {args.output_folder}")
    print("Now run your batch test against that folder, e.g.:")
    print(f'  python tests/run_batch_test.py "{args.output_folder}/<subfolder_name>"')


if __name__ == "__main__":
    main()
