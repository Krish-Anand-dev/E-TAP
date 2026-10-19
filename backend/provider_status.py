"""Normalize external/model provider health for an individual investigation.

Provider status is separate from the threat verdict: an unavailable provider is
missing evidence, not evidence that an email is benign or malicious.
"""
from __future__ import annotations

import os
from collections import Counter
from typing import Any

_SKIP_STATES = {
    "skipped_privacy", "skipped_for_privacy", "skipped_limit", "skipped_non_public",
    "private_or_reserved", "not_checked", "disabled", "skipped_by_triage",
    "skipped_by_policy", "policy_skipped",
}
_CONFIG_STATES = {"not_configured", "missing_key", "not_installed"}
_FAILURE_STATES = {
    "error", "timeout", "network_error", "provider_error", "invalid_response",
    "rate_limited", "rate_limited_internal", "unavailable", "failed", "dns_error",
}


def _lookup_state(value: Any) -> str:
    if not isinstance(value, dict):
        return "unavailable"
    status = str(value.get("status") or "").strip().lower()
    if status in _SKIP_STATES:
        return "skipped"
    if status in _CONFIG_STATES:
        return "not_configured"
    if status in _FAILURE_STATES or value.get("error"):
        return "failed"
    if status in {"not previously scanned by virustotal", "not_found", "unknown_no_record"}:
        # A successful provider response saying it has no record is an answer,
        # but not a clean verdict.
        return "success_unknown"
    if value.get("malicious") is not None or any(k in value for k in ("age_days", "registrar", "lat", "lon", "country")):
        return "success"
    if status in {"available", "ok", "success"}:
        return "success"
    # Old persisted values may not have a status but contain a known result.
    if status:
        return "success_unknown" if "not previously scanned" in status else "failed"
    return "unavailable"


def _provider_from_lookups(name: str, lookups: dict[str, Any], *, enabled: bool = True,
                           no_items_status: str = "not_needed", policy_label: str = "some lookups were skipped") -> dict:
    entries = list((lookups or {}).values())
    base = {"name": name, "attempted": 0, "succeeded": 0, "failed": 0, "skipped": 0,
            "not_configured": 0, "timed_out": 0, "rate_limited": 0, "summary": ""}
    if not entries:
        base.update(status=no_items_status, summary="No indicators required this provider.")
        return base
    if not enabled:
        base.update(status="disabled", skipped=len(entries), summary="External lookups are disabled by configuration.")
        return base

    states = [_lookup_state(entry) for entry in entries]
    counts = Counter(states)
    # `attempted` means an outbound lookup was actually attempted. Missing
    # configuration is a coverage gap, but not a network request or failure.
    base["attempted"] = counts["success"] + counts["success_unknown"] + counts["failed"]
    base["succeeded"] = counts["success"] + counts["success_unknown"]
    base["failed"] = counts["failed"]
    base["not_configured"] = counts["not_configured"]
    base["skipped"] = counts["skipped"]
    base["timed_out"] = sum(1 for entry in entries if isinstance(entry, dict) and str(entry.get("status", "")).lower() == "timeout")
    base["rate_limited"] = sum(1 for entry in entries if isinstance(entry, dict) and "rate_limited" in str(entry.get("status", "")).lower())

    if base["succeeded"] and (base["failed"] or base["skipped"] or base["not_configured"]):
        base["status"] = "partial"
        parts = [f"{base['succeeded']} lookup(s) answered"]
        if base["failed"]:
            parts.append(f"{base['failed']} failed")
        if base["not_configured"]:
            parts.append(f"{base['not_configured']} not configured")
        if base["skipped"]:
            parts.append(f"{base['skipped']} skipped by policy/limits")
        base["summary"] = "; ".join(parts) + "."
    elif base["succeeded"]:
        base["status"] = "available"
        base["summary"] = f"Provider returned {base['succeeded']} result(s); unknown results are not clean verdicts."
    elif counts["not_configured"] and not counts["failed"]:
        base["status"] = "not_configured"
        base["summary"] = "Provider credentials or required configuration are missing."
    elif base["failed"]:
        if base["timed_out"] == base["failed"]:
            base["status"] = "timeout"
            base["summary"] = "Provider request(s) timed out; no usable result was returned."
        elif base["rate_limited"] == base["failed"]:
            base["status"] = "rate_limited"
            base["summary"] = "Provider rate limits prevented the requested lookups."
        else:
            base["status"] = "unavailable"
            base["summary"] = "Provider request(s) failed; no usable result was returned."
    elif base["skipped"]:
        skip_statuses = {str((e or {}).get("status", "")).lower() for e in entries if isinstance(e, dict)}
        base["status"] = "skipped_for_privacy" if skip_statuses == {"skipped_privacy"} else "skipped_by_policy"
        base["summary"] = policy_label + "; no external result was used."
    else:
        base["status"] = "unavailable"
        base["summary"] = "Provider status could not be determined from the returned results."
    return base


def _gemini_status(final_assessment: dict, *, gemini_skipped: bool) -> dict:
    requested = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
    used_provider = str((final_assessment or {}).get("provider") or "unknown").lower()
    used_model = (final_assessment or {}).get("model")
    out = {"name": "Google Gemini", "requested_model": requested, "model_used": used_model,
           "attempted": 0, "succeeded": 0, "failed": 0, "skipped": 0,
           "timed_out": 0, "rate_limited": 0}
    if gemini_skipped or used_provider == "xgboost_triage":
        out.update(status="skipped_by_triage", skipped=1,
                   summary="The metadata triage path skipped Gemini for this message.")
    elif used_provider == "gemini":
        fallback = bool(used_model and used_model != requested)
        out.update(status="fallback_model_used" if fallback else "available", attempted=1, succeeded=1,
                   summary=(f"Used fallback model {used_model}; requested model was {requested}." if fallback
                            else f"Gemini analysis completed with {used_model or requested}."))
    elif not os.getenv("GEMINI_API_KEY"):
        out.update(status="not_configured", not_configured=1,
                   summary="GEMINI_API_KEY is not configured; the deterministic offline fallback was used.")
    elif used_provider == "offline_fallback":
        raw_reason = str((final_assessment or {}).get("fallback_reason") or "").lower()
        if "404" in raw_reason or "not_found" in raw_reason or "not found" in raw_reason:
            out.update(status="unavailable", attempted=1, failed=1,
                       summary="Configured Gemini model name was not found for this key; the deterministic offline fallback was used.")
        elif "timeout" in raw_reason or "timed out" in raw_reason or "deadline" in raw_reason:
            out.update(status="timeout", attempted=1, failed=1, timed_out=1,
                       summary="Gemini requests timed out; the deterministic offline fallback was used.")
        elif "429" in raw_reason or "quota" in raw_reason or "rate limit" in raw_reason or "resource_exhausted" in raw_reason:
            out.update(status="rate_limited", attempted=1, failed=1, rate_limited=1,
                       summary="Gemini rate or quota limits prevented analysis; the deterministic offline fallback was used.")
        else:
            out.update(status="unavailable", attempted=1, failed=1,
                       summary="Configured Gemini model attempts failed; the deterministic offline fallback was used.")
    else:
        out.update(status="unknown", summary="The selected assessment provider could not be identified.")
    return out


def build_provider_status(*, threat_intel: dict, iocs: dict, threat_intel_live: bool,
                          final_assessment: dict, gemini_skipped: bool) -> dict:
    """Build one safe, UI-ready provider status object for a completed analysis."""
    ti = threat_intel or {}
    ioc = iocs or {}
    providers = {
        "gemini": _gemini_status(final_assessment, gemini_skipped=gemini_skipped),
        "virustotal": _provider_from_lookups(
            "VirusTotal", {**(ti.get("url_reputation") or {}), **(ti.get("hash_reputation") or {})},
            enabled=threat_intel_live, no_items_status="not_needed",
            policy_label="VirusTotal indicators were skipped by privacy or lookup policy"),
        "abuseipdb": _provider_from_lookups(
            "AbuseIPDB", ti.get("ip_reputation") or {}, enabled=threat_intel_live,
            no_items_status="not_needed", policy_label="IP lookups were skipped by policy"),
        "whois": _provider_from_lookups(
            "WHOIS", ti.get("domain_info") or {}, enabled=threat_intel_live,
            no_items_status="not_needed", policy_label="Domain lookups were skipped by policy"),
        "ip_geolocation": _provider_from_lookups(
            "IP geolocation", ti.get("geo_lookup") or {}, enabled=threat_intel_live,
            no_items_status="not_needed", policy_label="Geolocation was skipped for non-public IPs or policy limits"),
    }
    unavailable_statuses = {"unavailable", "not_configured", "timeout", "rate_limited", "failed"}
    partial_statuses = {"partial", "unknown"}
    intentional_gap_statuses = {"disabled", "skipped_for_privacy", "skipped_by_policy"}
    unavailable_count = sum(1 for p in providers.values() if p.get("status") in unavailable_statuses)
    partial_count = sum(1 for p in providers.values() if p.get("status") in partial_statuses)
    unknown_count = sum(1 for p in providers.values() if p.get("status") == "unknown")
    intentionally_skipped_count = sum(1 for p in providers.values() if p.get("status") in intentional_gap_statuses)

    # "Coverage complete" must not mean "all providers answered" when live
    # lookups were disabled or policy/privacy intentionally withheld indicators.
    # Intentional skips are not outages and are not counted as unavailable, but
    # they are still missing external evidence and are surfaced separately.
    coverage_gap_count = unavailable_count + partial_count + intentionally_skipped_count
    coverage_status = "partial" if coverage_gap_count else "complete"
    if unavailable_count:
        noun = "provider" if unavailable_count == 1 else "providers"
        summary = f"Analysis completed; {unavailable_count} {noun} unavailable."
        if partial_count:
            summary += f" {partial_count} additional provider(s) had partial results."
        if intentionally_skipped_count:
            summary += f" {intentionally_skipped_count} provider(s) were intentionally skipped."
    elif unknown_count:
        noun = "provider" if unknown_count == 1 else "providers"
        summary = f"Analysis completed; status for {unknown_count} {noun} is unknown, so coverage is incomplete."
    elif partial_count:
        summary = "Analysis completed with partial provider coverage."
    elif intentionally_skipped_count:
        if any(p.get("status") == "disabled" for p in providers.values()):
            summary = "Analysis completed; live threat-intelligence was disabled by configuration or some checks were intentionally skipped. External evidence coverage is incomplete."
        else:
            summary = "Analysis completed; some provider checks were intentionally skipped for privacy or policy/limits. External evidence coverage is incomplete."
    else:
        summary = "Analysis completed; all applicable provider checks finished or were not needed."
    return {
        "schema_version": 1,
        "analysis_status": "completed",
        "coverage_status": coverage_status,
        "summary": summary,
        "unavailable_count": unavailable_count,
        "partial_count": partial_count,
        "unknown_count": unknown_count,
        "intentionally_skipped_count": intentionally_skipped_count,
        "coverage_gap_count": coverage_gap_count,
        "providers": providers,
    }
