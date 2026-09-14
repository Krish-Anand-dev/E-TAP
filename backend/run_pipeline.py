"""Run the complete A -> B/B2 -> D -> E -> F -> G -> H pipeline."""

from __future__ import annotations

import json
import sys


def run(path: str) -> dict:
    from pipeline import analyze_email_file

    return analyze_email_file(path)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} path/to/email.eml", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(run(sys.argv[1]), indent=2, ensure_ascii=False))
