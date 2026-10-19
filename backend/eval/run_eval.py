"""
B2 baseline: run the labelled corpus through the real pipeline and report
false positives / false negatives. Changes NO thresholds.

    cd backend
    python -m eval.run_eval ../docs/extracted            # prints a summary
    python -m eval.run_eval ../docs/extracted --out eval/results

By default it runs offline and deterministic: fake DB, no live threat intel,
no Gemini (GEMINI_API_KEY is removed). That is the *offline fallback*
configuration, not production. To measure the production configuration:

    GEMINI_API_KEY=... python -m eval.run_eval CORPUS --use-gemini --live-threat-intel

(needs xgboost installed for the Stage C' triage model; the report says
whether it was available). Gemini output is not deterministic, so repeat runs
can differ. Each message is analysed against a fresh database so campaign
correlation between corpus messages cannot leak into a score. The report
records which stages were live so a number cannot be mistaken for another
configuration.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter


def _configure_env(use_gemini: bool, live_threat_intel: bool) -> None:
    """Set before the pipeline runs. The fake DB is always used."""
    os.environ["USE_FAKE_DB"] = "1"
    os.environ["THREAT_INTEL_LIVE"] = "1" if live_threat_intel else "0"
    if not use_gemini:
        os.environ.pop("GEMINI_API_KEY", None)
        os.environ.pop("GOOGLE_API_KEY", None)


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from eval import metrics  # noqa: E402
from eval.corpus import load_corpus, to_parsed_email  # noqa: E402

# Operating points. These mirror verdicts.THRESHOLDS; they are read, not changed.
FLAG_BAND = "danger"           # LIKELY PHISHING / HIGH-RISK PHISHING (score >= 65)
REVIEW_BANDS = {"caution", "danger"}  # SUSPICIOUS or worse        (score >= 40)

POINTS = {
    "flagged (band=danger, score>=65)": lambda r: r["verdict_band"] == FLAG_BAND,
    "flagged-or-review (band>=caution, score>=40)": lambda r: r["verdict_band"] in REVIEW_BANDS,
    "evidence_state=high_risk_evidence": lambda r: r["evidence_state"] == "high_risk_evidence",
}


def analyse(samples):
    import pipeline
    from db.connection import reset_db

    rows = []
    for s in samples:
        row = {"sample_id": s.sample_id, "label": s.label, "category": s.category}
        try:
            reset_db()
            parsed = to_parsed_email(s)
            res = pipeline._run_parsed_pipeline(parsed)
        except Exception as exc:  # a crash is a result, not something to hide
            row.update(error=f"{type(exc).__name__}: {exc}"[:300])
            rows.append(row)
            continue
        er = res.get("evidence_report") or {}
        concl = er.get("conclusion") or {}
        prov = res.get("analysis_provenance") or {}
        hdr = res.get("headers") or {}
        content = (res.get("ai_analysis") or {}).get("content_classification") or {}
        row.update(
            risk_score=res.get("risk_score"),
            verdict=res.get("verdict"),
            verdict_band=res.get("verdict_band"),
            evidence_state=concl.get("evidence_state"),
            confidence_level=concl.get("confidence_level"),
            provider=prov.get("assessment_provider"),
            triage_available=(res.get("triage") or {}).get("available"),
            threat_intel_mode=prov.get("threat_intel_mode"),
            subject=(parsed.subject or "")[:70],
            body_chars=len((parsed.body_text or "")) + len((parsed.body_html or "")),
            parse_warnings=list(parsed.parse_warnings or []),
            header_red_flags=list(hdr.get("red_flags") or [])[:8],
            content_score=content.get("content_risk_score"),
            content_categories=[c.get("name") if isinstance(c, dict) else c
                                for c in (content.get("categories") or [])][:6],
            top_reasons=list(er.get("top_reasons") or []),
            n_urls=len((res.get("iocs") or {}).get("urls") or []),
        )
        rows.append(row)
    return rows


def summarise(rows):
    ok = [r for r in rows if "error" not in r]
    out = {"n_scored": len(ok), "n_errors": len(rows) - len(ok), "operating_points": {}}
    for name, fn in POINTS.items():
        out["operating_points"][name] = {
            **metrics.rates(*metrics.confusion(ok, fn)),
            "by_category": metrics.by_category(ok, fn),
            # false negatives where the parser delivered no body at all: a
            # parsing failure, not a detection miss
            "fn_with_empty_body": sum(
                1 for r in ok if r["label"] == "malicious" and not fn(r) and r["body_chars"] == 0),
        }
    out["threshold_sweep_risk_score"] = metrics.threshold_sweep(ok)
    out["verdict_counts_by_label"] = {
        lab: dict(Counter(r["verdict"] for r in ok if r["label"] == lab))
        for lab in ("benign", "malicious")
    }
    out["environment"] = {
        "providers": dict(Counter(r["provider"] for r in ok)),
        "xgboost_triage_available": dict(Counter(bool(r["triage_available"]) for r in ok)),
        "threat_intel_modes": dict(Counter(r["threat_intel_mode"] for r in ok)),
    }
    n_ben = sum(1 for r in ok if r["label"] == "benign")
    n_mal = len(ok) - n_ben
    out["sample_size_warning"] = (
        f"Only {n_ben} benign and {n_mal} malicious messages. The confidence intervals are the "
        "honest reading; do not quote these as detection rates."
        if min(n_ben, n_mal) < 100 else None)
    out["errors"] = [{"sample_id": r["sample_id"], "error": r["error"]} for r in rows if "error" in r]
    out["messages_with_empty_body"] = [r["sample_id"] for r in ok if r["body_chars"] == 0]
    return out


def _pct(x):
    return "n/a" if x is None else f"{x * 100:.0f}%"


def render_markdown(corpus_root, samples, skipped, dups, rows, summary):
    L = ["# B2 baseline: false positives / false negatives", ""]
    env = summary["environment"]
    L += [f"Corpus: `{corpus_root}`: {len(samples)} unique messages "
          f"({len(dups)} exact duplicate(s) dropped, {len(skipped)} skipped).", "",
          "**Configuration measured:** offline only. "
          f"Assessment provider: {env['providers']}; XGBoost triage available: {env['xgboost_triage_available']}; "
          f"threat intel: {env['threat_intel_modes']}.", "",
          "Positive class = spam (`malicious`). No thresholds were changed.", ""]
    if summary.get("sample_size_warning"):
        L += [f"> **Sample size:** {summary['sample_size_warning']}", ""]
    for name, op in summary["operating_points"].items():
        lo, hi = op["fpr_ci95"]; flo, fhi = op["fnr_ci95"]
        L += [f"## {name}", "",
              f"- False positives: **{op['fp']} / {op['n_benign']}** ham "
              f"(FPR {_pct(op['false_positive_rate'])}, 95% CI {_pct(lo)}-{_pct(hi)})",
              f"- False negatives: **{op['fn']} / {op['n_malicious']}** spam "
              f"(FNR {_pct(op['false_negative_rate'])}, 95% CI {_pct(flo)}-{_pct(fhi)})"
              + (f"; **{op['fn_with_empty_body']} of those had an empty body (parser failure)**"
                 if op["fn_with_empty_body"] else ""), "",
              "| category | label | n | flagged |", "|---|---|---|---|"]
        for cat, c in sorted(op["by_category"].items()):
            L.append(f"| {cat} | {c['label']} | {c['n']} | {c['flagged']} |")
        L.append("")
    L += ["## Per-message results", "",
          "| sample | label | score | verdict | evidence state | subject |", "|---|---|---|---|---|---|"]
    for r in rows:
        if "error" in r:
            L.append(f"| {r['sample_id']} | {r['label']} | ERROR | {r['error']} | | |")
        else:
            L.append(f"| {r['sample_id']} | {r['label']} | {r['risk_score']} | {r['verdict']} | "
                     f"{r['evidence_state']} | {r['subject'].replace('|', '/')} |")
    if summary["messages_with_empty_body"]:
        L += ["", "Messages that reached the pipeline with an empty body (parser could not decode): "
              + ", ".join(f"`{s}`" for s in summary["messages_with_empty_body"])]
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("--out", help="directory for results.json and report.md")
    ap.add_argument("--use-gemini", action="store_true", help="keep GEMINI_API_KEY (production-like Stage G)")
    ap.add_argument("--live-threat-intel", action="store_true", help="enable VirusTotal/AbuseIPDB/WHOIS lookups")
    args = ap.parse_args(argv)
    _configure_env(args.use_gemini, args.live_threat_intel)

    samples, skipped, dups = load_corpus(args.corpus)
    if not samples:
        print("No labelled samples found.", file=sys.stderr)
        return 2
    rows = analyse(samples)
    summary = summarise(rows)
    md = render_markdown(args.corpus, samples, skipped, dups, rows, summary)
    print(md)
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "results.json"), "w", encoding="utf-8") as fh:
            json.dump({"summary": summary, "rows": rows, "skipped": skipped, "duplicates": dups},
                      fh, indent=2, ensure_ascii=False)
        with open(os.path.join(args.out, "report.md"), "w", encoding="utf-8") as fh:
            fh.write(md)
    return 1 if summary["n_errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
