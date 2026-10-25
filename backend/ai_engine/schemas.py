from pydantic import BaseModel, Field


class CategoryScore(BaseModel):
    name: str
    weight: int = Field(ge=0, le=100)


class EmailAnalysis(BaseModel):

    content_verdict: str

    confidence: float = Field(ge=0, le=1)

    attack_type: str

    categories: list[CategoryScore]

    reasons: list[str]

    suspicious_indicators: list[str]


class EvidenceAssessment(BaseModel):
    source: str
    risk_score: int = Field(ge=0, le=100)
    summary: str
    evidence: list[str]


class MitreAttackMapping(BaseModel):
    technique: str
    name: str
    tactic: str
    confidence: float = Field(ge=0, le=1)
    evidence: list[str]


class AiFinding(BaseModel):
    """
    One interpretive statement by the model, tied to the evidence it rests on.

    `evidence_ids` must be ids from the `evidence_ledger` supplied in the
    prompt. Ids that do not exist are discarded server-side and the statement
    is shown as "not tied to specific evidence" rather than as grounded.
    """
    claim: str
    why_it_matters: str
    direction: str  # "raises_risk" | "lowers_risk" | "neutral"
    evidence_ids: list[str]


class FinalAssessment(BaseModel):
    verdict: str
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    explanation: str
    evidence_assessments: list[EvidenceAssessment]
    supporting_evidence: list[str]
    mitre_attack: list[MitreAttackMapping]
    recommended_actions: list[str]
    # Optional so older outputs / offline fallbacks still validate.
    ai_findings: list[AiFinding] = Field(default_factory=list)


class CombinedAssessment(BaseModel):
    """
    Merges EmailAnalysis (content-only classification) and FinalAssessment
    (full-evidence verdict) into a single structured output, so Stage G can
    get both in ONE Gemini call instead of two. See stage_g.py's
    analyze_with_stage_g() for why: this halves Gemini quota usage per
    email, which matters a lot on the free tier's 20-requests/day cap.
    """
    content_classification: EmailAnalysis
    final_assessment: FinalAssessment
