"""
ai_engine package.

The old Stage C content-only classifier is kept as reusable logic, but
final AI interpretation now lives in Stage G after the technical stages
have completed.
"""

from .main import analyze_email, calculate_content_risk
from .schemas import EmailAnalysis, CategoryScore, FinalAssessment
from .stage_g import analyze_with_stage_g, classify_email_content, interpret_evidence

__all__ = [
    "analyze_email",
    "calculate_content_risk",
    "EmailAnalysis",
    "CategoryScore",
    "FinalAssessment",
    "analyze_with_stage_g",
    "classify_email_content",
    "interpret_evidence",
]
