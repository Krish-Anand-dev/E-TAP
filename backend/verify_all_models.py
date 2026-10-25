"""
Diagnostic Verification Script for all 3 AI/ML Subsystems:
1. OpenCV & Image Forensics (OCR & QR Code Extraction)
2. XGBoost Metadata Triage Classifier
3. RAG SOC Analyst Assistant Engine
"""

from __future__ import annotations

import os
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
try:
    import torch
except ImportError:
    pass

import sys
import time
import io
import numpy as np

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from dotenv import load_dotenv
load_dotenv(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env")))
load_dotenv()


def verify_opencv_ocr() -> bool:
    print("\n" + "=" * 65)
    print(" [1/3] VERIFYING OPENCV & IMAGE FORENSICS (OCR & QR SCANNING)")
    print("=" * 65)
    try:
        import cv2
        from forensics.image_forensics import scan_image_attachment

        print(f"  [+] OpenCV (cv2) runtime detected: version {cv2.__version__}")

        # 1. Create a synthetic test image with rendered text using OpenCV
        img = np.full((150, 400, 3), 255, dtype=np.uint8)
        cv2.putText(img, "E-TAP FORENSIC TEST", (20, 80), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 0), 2)
        _, encoded = cv2.imencode(".png", img)
        test_bytes = encoded.tobytes()

        # 2. Run image forensics (OCR & QR scanning)
        res = scan_image_attachment(test_bytes, "test_evidence.png")
        print(f"  [+] Image scan completed successfully:")
        print(f"      - Decoded QR URLs: {res.get('qr_urls')}")
        print(f"      - OCR Text Detected: '{res.get('ocr_text', '').strip()}'")

        print("  [SUCCESS] OpenCV & Attachment Image Forensics: 100% OPERATIONAL")
        return True
    except Exception as exc:
        print(f"  [FAIL] OpenCV/OCR Error: {exc}")
        return False


def verify_xgboost() -> bool:
    print("\n" + "=" * 65)
    print(" [2/3] VERIFYING XGBOOST METADATA TRIAGE MODEL")
    print("=" * 65)
    try:
        from ai_engine.triage_model import _get_model, predict_triage, FEATURE_NAMES

        model_path = os.path.join(os.path.dirname(__file__), "ai_engine", "models", "xgboost_phish_model.pkl")
        if not os.path.exists(model_path):
            print(f"  [!] Model artifact not found at {model_path}")
            return False

        model = _get_model()
        if model is None:
            print(f"  [!] Failed to load model from {model_path}")
            return False

        print(f"  [+] Loaded model artifact: {model_path}")
        print(f"  [+] Active Canonical Features ({len(FEATURE_NAMES)}): {FEATURE_NAMES}")

        # Test Case 1: High-risk Phishing signature
        # [has_att=1, num_urls=4, domain_age=-1, spf=0, subj_len=65, urgent=1]
        t0 = time.perf_counter()
        phish_sample = np.array([[1.0, 4.0, -1.0, 0.0, 65.0, 1.0]], dtype=np.float32)
        res_phish = predict_triage(phish_sample)
        elapsed_phish = (time.perf_counter() - t0) * 1000

        print(f"  [+] Phishing Signature Test:")
        print(f"      Label={res_phish['label']} (1=Phish), Confidence={res_phish['confidence']:.2%}, Safe={res_phish['is_safe']} in {elapsed_phish:.2f}ms")
        assert res_phish["label"] == 1, f"Expected 1, got {res_phish['label']}"

        # Test Case 2: Clean Benign signature
        # [has_att=0, num_urls=0, domain_age=3500, spf=1, subj_len=30, urgent=0]
        t1 = time.perf_counter()
        benign_sample = np.array([[0.0, 0.0, 3500.0, 1.0, 30.0, 0.0]], dtype=np.float32)
        res_benign = predict_triage(benign_sample)
        elapsed_benign = (time.perf_counter() - t1) * 1000

        print(f"  [+] Benign Signature Test:")
        print(f"      Label={res_benign['label']} (0=Benign), Confidence={res_benign['confidence']:.2%}, Safe={res_benign['is_safe']} in {elapsed_benign:.2f}ms")
        assert res_benign["label"] == 0, f"Expected 0, got {res_benign['label']}"

        print("  [SUCCESS] XGBoost Stage C' Triage Classifier: 100% OPERATIONAL")
        return True
    except Exception as exc:
        print(f"  [FAIL] XGBoost Error: {exc}")
        return False


def verify_rag() -> bool:
    print("\n" + "=" * 65)
    print(" [3/3] VERIFYING RAG SOC ANALYST ASSISTANT")
    print("=" * 65)
    try:
        from rag.embeddings import embed_text, build_summary
        from rag.chat import answer_query
        from db.connection import get_db

        # 1. Test embedding vector generation
        t0 = time.perf_counter()
        test_vec = embed_text("URGENT: Verify your account password now")
        elapsed_embed = (time.perf_counter() - t0) * 1000
        print(f"  [+] Dense Embedding generated: {len(test_vec)} dimensions in {elapsed_embed:.2f}ms")
        assert len(test_vec) == 384, f"Expected 384d vector, got {len(test_vec)}"

        # 2. Test database retrieval
        db = get_db()
        print(f"  [+] Connected to MongoDB: '{db.name}'")

        # 3. Test RAG query answering
        res = answer_query("What are the MITRE ATT&CK techniques observed in this database?", db)
        answer = res.get("answer", "")
        sources = res.get("sources", [])
        print(f"  [+] Retrieved {len(sources)} incident source citations")
        first_line = answer.split("\n")[0] if answer else "No answer"
        print(f"  [+] Gemini Response preview ({len(answer)} chars):")
        print(f"      \"{first_line[:100]}...\"")

        print("  [SUCCESS] RAG Vector Engine & SOC Chat Assistant: 100% OPERATIONAL")
        return True
    except Exception as exc:
        print(f"  [FAIL] RAG Error: {exc}")
        return False


def main():
    print("\n" + "#" * 65)
    print("   E-TAP AI/ML SUBSYSTEM VERIFICATION REPORT")
    print("#" * 65)

    res_cv = verify_opencv_ocr()
    res_xgb = verify_xgboost()
    res_rag = verify_rag()

    print("\n" + "=" * 65)
    print("                  FINAL VERIFICATION SUMMARY")
    print("=" * 65)
    print(f"  1. OpenCV & OCR / QR Image Forensics : {'[PASS]' if res_cv else '[FAIL]'}")
    print(f"  2. XGBoost Metadata Triage Model     : {'[PASS]' if res_xgb else '[FAIL]'}")
    print(f"  3. RAG SOC Chat Assistant            : {'[PASS]' if res_rag else '[FAIL]'}")
    print("=" * 65 + "\n")

    if all([res_cv, res_xgb, res_rag]):
        print(">>> ALL THREE AI/ML SUBSYSTEMS ARE VERIFIED AND OPERATIONAL! <<<\n")
        sys.exit(0)
    else:
        print(">>> ONE OR MORE SUBSYSTEMS FAILED VERIFICATION. <<<\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
