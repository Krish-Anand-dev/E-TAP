"""
Stage C' Training Script -- XGBoost Metadata Triage Model
Trains an XGBoost classifier on email metadata features to predict phishing vs. benign.

Features:
1. has_attachment (0 or 1)
2. num_urls_in_body (int)
3. sender_domain_age_days (int/float, -1 if unknown)
4. auth_spf_pass (0 or 1)
5. subject_length (int)
6. is_urgent_keyword_present (0 or 1)
Target: is_phishing (0 = Benign, 1 = Phishing)
"""

import os
import sys
import argparse
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from xgboost import XGBClassifier

from triage_model import FEATURE_NAMES

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_OUT_PATH = os.path.join(MODELS_DIR, "xgboost_phish_model.pkl")
RAW_DATA_DIR = os.path.join(os.path.dirname(__file__), "data", "raw")
CSV_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "training_data.csv")


def generate_synthetic_baseline(n_samples: int = 1200) -> pd.DataFrame:
    """
    Synthesizes a representative metadata dataset for immediate scaffolding
    and pipeline validation before downloading heavy external corpora.
    """
    np.random.seed(42)
    rows = []

    # 1. Benign samples (label = 0)
    n_benign = n_samples // 2
    for _ in range(n_benign):
        has_att = float(np.random.choice([0, 1], p=[0.75, 0.25]))
        num_urls = float(np.random.choice([0, 1, 2], p=[0.50, 0.40, 0.10]))
        # Benign domains are established (1 to 20 years old)
        domain_age = float(np.random.uniform(365, 7300))
        # High SPF pass rate on legitimate mail
        spf_pass = float(np.random.choice([1, 0], p=[0.92, 0.08]))
        subject_len = float(np.clip(np.random.normal(35, 12), 5, 80))
        urgent_kw = float(np.random.choice([0, 1], p=[0.95, 0.05]))
        rows.append({
            "has_attachment": has_att,
            "num_urls_in_body": num_urls,
            "sender_domain_age_days": domain_age,
            "auth_spf_pass": spf_pass,
            "subject_length": subject_len,
            "is_urgent_keyword_present": urgent_kw,
            "is_phishing": 0,
        })

    # 2. Phishing samples (label = 1)
    n_phish = n_samples // 2
    for _ in range(n_phish):
        has_att = float(np.random.choice([0, 1], p=[0.45, 0.55]))
        num_urls = float(np.random.choice([1, 2, 4, 8], p=[0.15, 0.35, 0.30, 0.20]))
        # Phishing domains are brand new (< 60 days) or unresolvable (-1)
        domain_age = float(np.random.choice([np.random.uniform(1, 60), -1.0], p=[0.60, 0.40]))
        # High SPF failure rate on spoofed mail
        spf_pass = float(np.random.choice([0, 1], p=[0.85, 0.15]))
        subject_len = float(np.clip(np.random.normal(48, 18), 8, 120))
        urgent_kw = float(np.random.choice([1, 0], p=[0.78, 0.22]))
        rows.append({
            "has_attachment": has_att,
            "num_urls_in_body": num_urls,
            "sender_domain_age_days": domain_age,
            "auth_spf_pass": spf_pass,
            "subject_length": subject_len,
            "is_urgent_keyword_present": urgent_kw,
            "is_phishing": 1,
        })

    df = pd.DataFrame(rows)
    return df.sample(frac=1.0, random_state=42).reset_index(drop=True)


def train():
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), "data"), exist_ok=True)

    is_synthetic = False
    if os.path.exists(CSV_DATA_PATH):
        print(f"[*] Loading training data from {CSV_DATA_PATH}...")
        df = pd.read_csv(CSV_DATA_PATH)
    else:
        print("[!] No custom CSV found. Generating synthetic baseline dataset for scaffolding...")
        is_synthetic = True
        df = generate_synthetic_baseline()
        df.to_csv(CSV_DATA_PATH, index=False)
        print(f"[*] Saved baseline dataset to {CSV_DATA_PATH}")

    X = df[FEATURE_NAMES]
    y = df["is_phishing"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"[*] Training XGBClassifier on {len(X_train)} samples (test split: {len(X_test)})...")
    clf = XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        eval_metric="logloss",
        random_state=42,
    )
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    acc = accuracy_score(y_test, preds)

    print("\n" + "=" * 55)
    print(f"  STAGE C' XGBOOST MODEL EVALUATION (Accuracy: {acc:.2%})")
    print("=" * 55)
    print(classification_report(y_test, preds, target_names=["Benign (0)", "Phishing (1)"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, preds))
    print("=" * 55)

    joblib.dump(clf, MODEL_OUT_PATH)
    print(f"\n[+] Saved model artifact to: {MODEL_OUT_PATH}")

    if is_synthetic:
        print("\n" + "!" * 68)
        print("  WARNING: A synthetic baseline model was trained for scaffolding.")
        print("  Calibrated TRIAGE_SAFE_THRESHOLD=0.90 should only be relied upon")
        print("  in production once real Enron/CEAS data has been ingested.")
        print("!" * 68 + "\n")


if __name__ == "__main__":
    train()
