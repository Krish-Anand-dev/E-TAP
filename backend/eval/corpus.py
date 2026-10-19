"""
Load a labelled evaluation corpus.

Layout: any directory tree. A file's label comes from the name of the folder
it sits in (SpamAssassin naming):

    *ham*   -> label "benign"      (easy_ham, hard_ham, ...)
    *spam*  -> label "malicious"   (spam, spam_2, ...)

`category` is the folder name with any leading date stripped
(20030228_hard_ham -> hard_ham). Folders matching neither word are skipped
and reported, never guessed.

Accepted files: `.json` (a serialised ParsedEmail, as in docs/extracted/) and
`.eml`. Exact duplicates (same content) are dropped and listed, so one message
cannot be counted twice.

"malicious" here means "spam / unwanted" for the SpamAssassin data. That is
NOT the same as phishing; see the historical-baseline warning in CONTEXT.md (section 15) before quoting a number.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional

BENIGN = "benign"
MALICIOUS = "malicious"


@dataclass
class Sample:
    sample_id: str          # path relative to the corpus root
    path: str
    label: str              # BENIGN | MALICIOUS
    category: str           # e.g. easy_ham, hard_ham, spam
    kind: str               # "json" | "eml"
    content_hash: str
    parse_warnings: list = field(default_factory=list)


def _label_for_folder(name: str) -> Optional[str]:
    low = name.lower()
    has_ham, has_spam = "ham" in low, "spam" in low
    if has_ham == has_spam:  # neither, or ambiguous
        return None
    return BENIGN if has_ham else MALICIOUS


def _category(folder: str) -> str:
    return re.sub(r"^\d{8}_", "", folder)


def _hash_file(path: str, kind: str) -> str:
    with open(path, "rb") as fh:
        raw = fh.read()
    if kind == "json":
        try:  # key order / whitespace must not hide a duplicate
            raw = json.dumps(json.loads(raw), sort_keys=True).encode()
        except ValueError:
            pass
    return hashlib.sha256(raw).hexdigest()


def load_corpus(root: str):
    """Return (samples, skipped, duplicates). Deterministic order."""
    samples, skipped, duplicates, seen = [], [], [], {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        folder = os.path.basename(dirpath)
        for fname in sorted(filenames):
            kind = {".json": "json", ".eml": "eml"}.get(os.path.splitext(fname)[1].lower())
            if not kind:
                continue
            path = os.path.join(dirpath, fname)
            rel = os.path.relpath(path, root)
            label = _label_for_folder(folder)
            if label is None:
                skipped.append({"sample_id": rel, "reason": f"folder '{folder}' is neither ham nor spam"})
                continue
            digest = _hash_file(path, kind)
            if digest in seen:
                duplicates.append({"sample_id": rel, "duplicate_of": seen[digest]})
                continue
            seen[digest] = rel
            samples.append(Sample(rel, path, label, _category(folder), kind, digest))
    return samples, skipped, duplicates


def to_parsed_email(sample: Sample):
    """Build the ParsedEmail the pipeline expects."""
    from email_parser import parse_email
    from email_parser.models import Attachment, ParsedEmail

    if sample.kind == "eml":
        return parse_email(sample.path)
    with open(sample.path, encoding="utf-8") as fh:
        d = json.load(fh)
    d = dict(d)
    d["attachments"] = [Attachment(**a) for a in d.get("attachments") or []]
    known = set(ParsedEmail.__dataclass_fields__)
    return ParsedEmail(**{k: v for k, v in d.items() if k in known})
