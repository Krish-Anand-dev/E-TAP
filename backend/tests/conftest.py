"""Tests must never use the real settings.

The app reads the project's .env when it is imported. On a computer set up for
hosting that file holds real database and service keys, so loading it is switched
off here, before any test imports the app, and anything already in the shell is
removed. Tests that need a setting set it themselves.
"""
import os

try:
    import dotenv
except ImportError:  # pragma: no cover
    dotenv = None

if dotenv is not None:
    dotenv.load_dotenv = lambda *args, **kwargs: False

_REAL = (
    "MONGODB_URI", "MONGO_URI", "MONGO_DB_NAME",
    "GEMINI_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY",
    "CLOUDINARY_URL", "CLOUDINARY_CLOUD_NAME", "CLOUDINARY_API_KEY", "CLOUDINARY_API_SECRET",
    "BREVO_API_KEY", "RESEND_API_KEY", "LOGIN_FROM_EMAIL", "AUTH_SECRET",
    "META_ACCESS_TOKEN", "META_APP_SECRET", "META_PHONE_NUMBER_ID", "META_VERIFY_TOKEN",
    "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN",
    "THREAT_INTEL_LIVE", "ALLOWED_ORIGINS", "PUBLIC_API_URL", "PUBLIC_FRONTEND_URL",
)
for _name in _REAL:
    os.environ.pop(_name, None)
