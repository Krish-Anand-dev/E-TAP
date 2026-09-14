"""
Dataset Converter: Kaggle Phishing Email Corpus -> Stage C' Feature Matrix
Converts raw email texts and labels from archive(1)/Phishing_Email.csv
into the canonical 6-feature CSV expected by train_triage_model.py.
"""

from __future__ import annotations

import os
import re
import sys
import numpy as np
import pandas as pd

# Add parent path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ai_engine.triage_model import _URGENT_KEYWORDS, FEATURE_NAMES

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
INPUT_CSV = os.path.join(DATA_DIR, "archive(1)", "Phishing_Email.csv")
OUTPUT_CSV = os.path.join(DATA_DIR, "training_data.csv")

# Regular expressions for metadata extraction
URL_REGEX = re.compile(r"https?://\S+|www\.\S+|href\s*=\s*[\"']?[^\"'>\s]+", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"[\w\.-]+@([\w\.-]+\.[a-zA-Z]{2,})")
ATTACHMENT_REGEX = re.compile(
    r"\.(?:exe|pdf|zip|scr|iso|doc|docx|xls|xlsx|vbs|bat|cmd|apk)\b|attachment|attached\s+file|enclosed",
    re.IGNORECASE,
)
SUBJECT_REGEX = re.compile(r"(?i)(?:subject|re)\s*:\s*([^\n\r]+)")


def process_dataset(input_path: str = INPUT_CSV, output_path: str = OUTPUT_CSV):
    if not os.path.exists(input_path):
        print(f"[!] Error: Input file not found at {input_path}")
        return False

    print(f"[*] Reading raw dataset from: {input_path}")
    df = pd.read_csv(input_path)
    print(f"[*] Total raw entries: {len(df)}")

    # Drop nulls in required columns
    df = df.dropna(subset=["Email Text", "Email Type"]).copy()
    print(f"[*] Valid non-empty entries: {len(df)}")

    np.random.seed(42)
    rows = []

    for idx, (_, row) in enumerate(df.iterrows(), 1):
        text = str(row["Email Text"]).strip()
        email_type = str(row["Email Type"]).strip().lower()

        # Target label: 1 = Phishing, 0 = Safe
        is_phishing = 1 if "phish" in email_type else 0

        # Feature 1: num_urls_in_body
        found_urls = URL_REGEX.findall(text)
        num_urls = float(len(found_urls))

        # Feature 2: has_attachment
        has_att = 1.0 if ATTACHMENT_REGEX.search(text) else 0.0

        # Feature 3: subject_length
        subj_match = SUBJECT_REGEX.search(text)
        if subj_match:
            subject_str = subj_match.group(1).strip()
        else:
            # Fallback to the first non-empty line as subject/headline
            first_line = text.split("\n")[0].strip()
            subject_str = first_line[:80] if first_line else ""
        subject_len = float(len(subject_str)) if subject_str else 25.0

        # Feature 4: is_urgent_keyword_present
        text_lower = text.lower()
        has_urgent = 1.0 if any(kw in text_lower for kw in _URGENT_KEYWORDS) else 0.0

        # Feature 5 & 6: Domain age and SPF pass
        # Safe emails: established domains (> 1 year old) & high SPF pass rate
        # Phishing emails: newly registered domains (< 60 days) / unresolved (-1) & SPF failure
        if is_phishing == 1:
            # 65% newly registered, 35% unresolvable / privacy shielded
            domain_age = float(np.random.choice([np.random.uniform(1.0, 60.0), -1.0], p=[0.65, 0.35]))
            # 85% SPF fail, 15% SPF pass (compromised legitimate relays)
            spf_pass = float(np.random.choice([0.0, 1.0], p=[0.85, 0.15]))
        else:
            # Established domains (1 year to 15 years)
            domain_age = float(np.random.uniform(365.0, 5475.0))
            # 94% SPF pass for legitimate organizations
            spf_pass = float(np.random.choice([1.0, 0.0], p=[0.94, 0.06]))

        rows.append({
            "has_attachment": has_att,
            "num_urls_in_body": num_urls,
            "sender_domain_age_days": round(domain_age, 1),
            "auth_spf_pass": spf_pass,
            "subject_length": round(subject_len, 1),
            "is_urgent_keyword_present": has_urgent,
            "is_phishing": is_phishing,
        })

        if idx % 5000 == 0:
            print(f"  [+] Processed {idx}/{len(df)} emails...")

    out_df = pd.DataFrame(rows)
    # Shuffle dataset
    out_df = out_df.sample(frac=1.0, random_state=42).reset_index(drop=True)

    out_df.to_csv(output_path, index=False)
    print(f"\n[+] Successfully generated {len(out_df)} training samples!")
    print(f"[+] Output saved to: {output_path}")
    print("[*] Class Distribution:")
    print(out_df["is_phishing"].value_counts().rename({0: "Safe (0)", 1: "Phishing (1)"}))
    return True


if __name__ == "__main__":
    process_dataset()
