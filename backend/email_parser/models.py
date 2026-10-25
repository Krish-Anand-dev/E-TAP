"""
models.py

Defines the exact shape of data that Stage A hands off to everyone else
(Krish's header analysis, the team attachment forensics, the team AI
classifier). Every parser (.eml or .msg) MUST return an object matching
this structure. This is the contract — don't change field names without
telling the team, since the team API and everyone's downstream code
depends on these exact keys.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional


@dataclass
class Attachment:
    filename: str
    content_type: str          # what the email SAYS this file is, e.g. "application/pdf"
    size_bytes: int
    content_bytes_b64: str     # the actual file content, base64 encoded


@dataclass
class ParsedEmail:
    # --- core headers ---
    subject: Optional[str] = None
    from_raw: Optional[str] = None          # full "From" header as-is, e.g. "Bank Support <fake@evil.com>"
    from_display_name: Optional[str] = None # "Bank Support"
    from_email: Optional[str] = None        # "fake@evil.com"
    to: Optional[str] = None
    reply_to: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None

    # --- full header dump (for header-forensics stage to dig deeper) ---
    all_headers: Dict[str, List[str]] = field(default_factory=dict)
    # NOTE: value is a list because some headers (like "Received") appear
    # multiple times in one email — a dict with a single string would lose data.

    # --- body content ---
    body_text: Optional[str] = None
    body_html: Optional[str] = None

    # --- attachments ---
    attachments: List[Attachment] = field(default_factory=list)

    # --- metadata about the parse itself ---
    source_format: str = ""   # "eml" or "msg"
    parse_warnings: List[str] = field(default_factory=list)  # anything weird/malformed noted during parsing

    def to_dict(self) -> dict:
        """Convert to a plain dict (JSON-serializable) for handing off to the API layer."""
        return asdict(self)
