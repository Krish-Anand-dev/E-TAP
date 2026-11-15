"""Gemini chain: a busy (503) model is retried once, a dead model name is gone, a timeout moves on."""
import pytest

from ai_engine import stage_g


class Boom(Exception):
    def __init__(self, code, status):
        super().__init__("x")
        self.code, self.status = code, status


class FakeModels:
    def __init__(self, script):
        self.script, self.calls = script, []

    def generate_content(self, model, contents, config):
        self.calls.append(model)
        step = self.script.pop(0)
        if isinstance(step, Exception):
            raise step
        return step


class FakeClient:
    def __init__(self, script):
        self.models = FakeModels(script)


class Reply:
    text = ('{"content_classification": {"content_verdict": "Likely Legitimate", "categories": [], "reasons": [],'
            ' "suspicious_indicators": [], "confidence": 0.5, "attack_type": "x"},'
            ' "final_assessment": {"verdict": "LIKELY LEGITIMATE", "risk_score": 5, "confidence": 0.5,'
            ' "explanation": "x", "recommended_actions": [], "mitre_attack": []}}')


@pytest.fixture(autouse=True)
def quick(monkeypatch):
    from ai_engine import schemas
    monkeypatch.setattr(schemas.CombinedAssessment, "model_validate_json", classmethod(lambda cls, text: "parsed"))
    monkeypatch.setattr(stage_g.time, "sleep", lambda s: None)
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.5-flash-lite")


def run(monkeypatch, script):
    client = FakeClient(script)
    monkeypatch.setattr(stage_g, "_get_gemini_client", lambda: client)
    try:
        stage_g._gemini_combined_analysis({"email": {"subject": "s", "body_text": "b"}})
        outcome = "ok"
    except RuntimeError as exc:
        outcome = str(exc)
    return client.models.calls, outcome


def test_dead_model_name_is_not_in_the_chain():
    assert "gemini-flash-lite-latest" not in stage_g._candidate_models()


def test_a_busy_model_is_retried_once_on_the_same_model(monkeypatch):
    calls, outcome = run(monkeypatch, [Boom(503, "UNAVAILABLE"), Reply()])
    assert calls == ["gemini-3.5-flash-lite", "gemini-3.5-flash-lite"] and outcome == "ok"


def test_a_second_503_moves_to_the_next_model(monkeypatch):
    calls, outcome = run(monkeypatch, [Boom(503, "UNAVAILABLE"), Boom(503, "UNAVAILABLE"), Reply()])
    assert calls == ["gemini-3.5-flash-lite", "gemini-3.5-flash-lite", "gemini-3.1-flash-lite"] and outcome == "ok"


def test_a_timeout_is_not_retried(monkeypatch):
    calls, outcome = run(monkeypatch, [Boom(504, "DEADLINE_EXCEEDED"), Reply()])
    assert calls == ["gemini-3.5-flash-lite", "gemini-3.1-flash-lite"] and outcome == "ok"


def test_every_model_failing_ends_in_the_offline_fallback_reason(monkeypatch):
    script = [Boom(504, "DEADLINE_EXCEEDED")] * 3
    calls, outcome = run(monkeypatch, script)
    assert len(calls) == 3 and outcome.startswith("All Gemini models failed")
