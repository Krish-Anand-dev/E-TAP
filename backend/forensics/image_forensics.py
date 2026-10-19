"""
Image Forensics -- QR Code Decoding & OCR Text Extraction
Stage B2 Enrichment for Image Attachments

Analyzes image payloads (PNG, JPEG, GIF, WebP, BMP, TIFF) to extract:
1. Concealed QR code URLs (pyzbar + OpenCV QRCodeDetector fallback)
2. Text embedded inside image screenshots (pytesseract OCR)

Designed with defensive fail-safes: any missing system dependency or corrupt
image payload returns empty results without disrupting the forensic pipeline.
"""

from __future__ import annotations

import io
import re
import logging
from typing import Any

logger = logging.getLogger("E-TAP.image_forensics")

_URL_PATTERN = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+', re.IGNORECASE)


def _extract_urls_from_text(text: str) -> list[str]:
    if not text:
        return []
    matches = _URL_PATTERN.findall(text)
    urls: list[str] = []
    for m in matches:
        clean = m.strip().rstrip('.,;:!?"\')]}')
        if clean and clean not in urls:
            urls.append(clean)
    return urls


def _decode_qr_pyzbar(img_pil_or_cv) -> list[str]:
    """Attempt QR detection using pyzbar if available."""
    try:
        from pyzbar import pyzbar
        decoded_objs = pyzbar.decode(img_pil_or_cv)
        extracted: list[str] = []
        for obj in decoded_objs:
            if obj.type == "QRCODE" or "QR" in str(obj.type).upper():
                data = obj.data.decode("utf-8", errors="replace").strip()
                if data:
                    extracted.append(data)
        return extracted
    except Exception as exc:
        logger.debug("pyzbar QR decoding unavailable or failed: %s", exc)
        return []


def _decode_qr_opencv(cv_img) -> list[str]:
    """Attempt QR detection using OpenCV QRCodeDetector."""
    try:
        import cv2
        detector = cv2.QRCodeDetector()
        # Try multi-detection first if available in OpenCV
        if hasattr(detector, "detectAndDecodeMulti"):
            retval, decoded_info, _, _ = detector.detectAndDecodeMulti(cv_img)
            if retval and decoded_info:
                return [info.strip() for info in decoded_info if info and info.strip()]

        # Fallback to single QR detector
        data, _, _ = detector.detectAndDecode(cv_img)
        if data and data.strip():
            return [data.strip()]
    except Exception as exc:
        logger.debug("OpenCV QR detection failed: %s", exc)
    return []


def available_qr_decoders() -> list[str]:
    """Names of QR decoders that can actually run in this environment."""
    found = []
    try:
        from pyzbar import pyzbar  # noqa: F401  (import fails without the zbar library)
        found.append("pyzbar")
    except Exception:
        pass
    try:
        import cv2
        cv2.QRCodeDetector()
        found.append("opencv")
    except Exception:
        pass
    return found


def _run_ocr(cv_img_or_pil) -> str:
    """Attempt OCR using pytesseract if tesseract binary is installed."""
    try:
        import pytesseract
        import os
        
        # Configure Tesseract path for Windows
        tesseract_path = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
        if os.path.exists(tesseract_path):
            pytesseract.pytesseract.tesseract_cmd = tesseract_path
            
        text = pytesseract.image_to_string(cv_img_or_pil)
        return text.strip() if text else ""
    except Exception as exc:
        # Expected if system tesseract-ocr package is not installed on host
        logger.debug("pytesseract OCR unavailable or failed: %s", exc)
        return ""


def scan_image_attachment(attachment_bytes: bytes, filename: str = "") -> dict[str, Any]:
    """
    Perform forensic decomposition on an image attachment.

    Returns
    -------
    dict
        {
            "ocr_text": str,
            "qr_urls": list[str],
            "has_qr": bool,
            "has_ocr_text": bool,
        }
    """
    result = {
        "ocr_text": "",
        "qr_urls": [],
        "qr_payloads": [],          # every decoded QR, URL or not
        "qr_status": "image_unreadable",
        "qr_decoders": [],
        "has_qr": False,
        "has_ocr_text": False,
    }

    if not attachment_bytes or len(attachment_bytes) < 8:
        return result

    cv_img = None
    pil_img = None

    # 1. Try decoding with OpenCV
    try:
        import cv2
        import numpy as np
        np_arr = np.frombuffer(attachment_bytes, dtype=np.uint8)
        cv_img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
    except Exception as exc:
        logger.debug("OpenCV image decode error on '%s': %s", filename, exc)

    # 2. Try decoding with PIL as fallback/companion
    try:
        from PIL import Image
        pil_img = Image.open(io.BytesIO(attachment_bytes))
    except Exception as exc:
        logger.debug("PIL image decode error on '%s': %s", filename, exc)

    if cv_img is None and pil_img is None:
        logger.debug("Could not decode image bytes for '%s'", filename)
        return result  # qr_status stays "image_unreadable"

    # 3. QR Code Scanning
    qr_payloads: list[str] = []

    # Try pyzbar first (via PIL or cv2)
    target_for_zbar = pil_img if pil_img is not None else cv_img
    if target_for_zbar is not None:
        qr_payloads.extend(_decode_qr_pyzbar(target_for_zbar))

    # Try OpenCV QRCodeDetector if pyzbar didn't find anything
    if not qr_payloads and cv_img is not None:
        qr_payloads.extend(_decode_qr_opencv(cv_img))

    decoders = available_qr_decoders()
    result["qr_decoders"] = decoders
    if qr_payloads:
        result["qr_status"] = "decoded"
    elif not decoders:
        result["qr_status"] = "decoder_unavailable"
    else:
        result["qr_status"] = "no_qr_found"
    result["qr_payloads"] = [
        {"kind": "url" if p.lower().startswith(("http://", "https://")) else "other",
         "text": p[:500]}
        for p in dict.fromkeys(qr_payloads)
    ]

    # Filter/extract valid URLs from QR payloads
    qr_urls: list[str] = []
    for payload in qr_payloads:
        # If payload itself is a URL
        if payload.lower().startswith(("http://", "https://")):
            clean_url = payload.strip()
            if clean_url not in qr_urls:
                qr_urls.append(clean_url)
        else:
            # Check if text inside QR contains URLs
            found = _extract_urls_from_text(payload)
            for u in found:
                if u not in qr_urls:
                    qr_urls.append(u)

    # 4. OCR Scanning
    ocr_text = ""
    # Use grayscale OpenCV image if available, else PIL
    if cv_img is not None:
        try:
            import cv2
            gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
            ocr_text = _run_ocr(gray)
        except Exception:
            ocr_text = _run_ocr(cv_img)
    elif pil_img is not None:
        try:
            gray = pil_img.convert("L")
            ocr_text = _run_ocr(gray)
        except Exception:
            ocr_text = _run_ocr(pil_img)

    result["ocr_text"] = ocr_text
    result["qr_urls"] = qr_urls
    result["has_qr"] = len(qr_urls) > 0
    result["has_ocr_text"] = bool(ocr_text and len(ocr_text.strip()) > 5)

    return result
