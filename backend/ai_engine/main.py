"""
main.py

Legacy Stage C content classification, now reused by Stage G.

Analyzes ONLY the textual content of an email (subject / body_text /
body_html) using Gemini, and classifies it against the fixed 30-category
threat taxonomy defined in prompts.py. See README.md for local setup
(Gemini API key) and full details.

Usage (this is what other stages should do):
    from ai_engine.main import analyze_email

    analysis = analyze_email(parsed_email_dict)  # dict w/ subject/body_text/body_html
    print(analysis.content_verdict, analysis.categories)

Importing this module does NOT run the local demo/test loop below --
that only executes when this file is run directly:
    cd backend
    python -m ai_engine.main
"""

import os
import json
import glob
import time

from .schemas import EmailAnalysis
from .prompts import SYSTEM_PROMPT

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional for import-only use
    load_dotenv = None

# Load environment variables from a local .env file when python-dotenv is
# installed. The file is git-ignored and never committed.
if load_dotenv is not None:
    load_dotenv()

DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"


def _get_gemini_client():
    """
    Build the Gemini client lazily.

    Importing this module should not break the backend/API when a local
    demo is running without Gemini configured. The actual Gemini-backed
    classifier still raises a clear error when called without a key.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not set. Add it to your local .env file to "
            "enable Gemini-backed content classification, or let Stage G use "
            "its explicit offline fallback for local pipeline demos."
        )

    timeout_ms = int(os.getenv("GEMINI_REQUEST_TIMEOUT_MS", "15000"))
    timeout_ms = max(1000, min(timeout_ms, 60000))
    try:
        from google import genai
        from google.genai import types
    except ImportError as exc:
        raise RuntimeError(
            "google-genai is not installed. Install backend dependencies from "
            "backend/requirements.txt to enable Gemini analysis."
        ) from exc

    return genai.Client(api_key=api_key, http_options=types.HttpOptions(timeout=timeout_ms))


def calculate_content_risk(categories):
    if not categories:
        return 0

    # Take the highest category weight as the base score
    base_score = max(category.weight for category in categories)

    return min(base_score, 100)


# Analyze email content
def analyze_email(data):
    subject = data.get("subject", "")
    body_text = data.get("body_text", "")
    body_html = data.get("body_html")

    email_content = f"""
Subject:
{subject}

Body Text:
{body_text}

Body HTML:
{body_html if body_html else "Not available"}
"""

    client = _get_gemini_client()
    model = os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)

    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model=model,
                contents=f"""
{SYSTEM_PROMPT}

Analyze the following email:

{email_content}
""",
                config={
                    "response_mime_type": "application/json",
                    "response_schema": EmailAnalysis,
                },
            )
            break

        except Exception as e:
            if attempt < 2:
                print(f"Gemini request failed. Retrying... ({attempt + 1}/3)")
                time.sleep(5)
            else:
                raise

    return EmailAnalysis.model_validate_json(response.text)


def _run_local_demo():
    """
    Local/manual test loop: analyzes every JSON file in ./emails/*.json
    (relative to the current working directory) and prints the Stage C
    result for each. Only runs when this file is executed directly --
    never on import, so other stages can safely do
    `from ai_engine.main import analyze_email`.
    """
    json_files = glob.glob("emails/*.json")

    for json_file in json_files:
        print(f"\n\n===== ANALYZING {json_file} =====")

        with open(json_file, "r", encoding="utf-8") as file:
            data = json.load(file)

        analysis = analyze_email(data)

        content_risk_score = calculate_content_risk(analysis.categories)

        result = {
            "verdict": analysis.content_verdict,
            "content_risk_score": content_risk_score,
            "confidence": analysis.confidence,
            "attack_type": analysis.attack_type,
            "categories": [
                {
                    "name": category.name,
                    "weight": category.weight
                }
                for category in analysis.categories
            ],
            "reasons": analysis.reasons,
            "suspicious_indicators": analysis.suspicious_indicators
        }

        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _run_local_demo()
