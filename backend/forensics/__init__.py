"""
forensics package — Stage B (Header Forensics, Krish) + Stage B2
(Attachment Forensics, the team) + Stage D (IOC Extraction) live together
here since these stages consume the normalized Stage A email data and
belong to the same forensics phase of the pipeline.
"""

# --- Stage B: Header Forensics (Krish) ---
from .header_forensics import analyze_headers, HeaderAnalysis
from .received_chain import find_originating_ip, get_received_chain_summary
from .auth_results import evaluate_authentication
from .domain_similarity import analyze_domain

# --- Stage B2: Attachment Forensics (the team) ---
from .attachment_forensics import analyze_attachment, analyze_attachments
from .file_signatures import detect_actual_type, types_conflict
from .macro_scan import has_macro, is_office_document

# --- Stage D: IOC Extraction ---
from .ioc_extraction import extract_iocs

__all__ = [
    # Stage B
    "analyze_headers",
    "HeaderAnalysis",
    "find_originating_ip",
    "get_received_chain_summary",
    "evaluate_authentication",
    "analyze_domain",

    # Stage B2
    "analyze_attachment",
    "analyze_attachments",
    "detect_actual_type",
    "types_conflict",
    "has_macro",
    "is_office_document",

    # Stage D
    "extract_iocs",
]