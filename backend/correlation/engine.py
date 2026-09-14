"""
Stage F -- Correlation Engine

Stage F has two responsibilities:
    1. Correlate the current email against previously analyzed emails.
    2. Persist the current email's analysis so it becomes part of the
       historical dataset used by future correlation runs.

Input:
    - Stage D's ioc_analysis for the current email.
    - Optional metadata / earlier-stage outputs to persist alongside it.

Matching:
    - IPs, URLs, hashes: exact value equality.
    - Domains: exact equality plus fuzzy similarity using the existing
      Stage B domain helpers, so observed typosquat variants can still
      be associated with a campaign.

Campaign assignment:
    - No historical match -> create a new campaign.
    - Matches belong to one campaign -> join that campaign.
    - Matches span multiple campaigns -> merge those campaigns; the
      lowest campaign id survives.

Persistence:
    - The current email is stored even when there are no historical matches.
    - A repeated message_id is updated in place rather than duplicated.
    - Re-processing an existing message does not count the record itself
      as a historical match.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from db import connection, repository
from forensics.brand_domains import get_brand_root
from forensics.domain_similarity import similarity_ratio

DEFAULT_FUZZY_DOMAIN_THRESHOLD = 0.82
_MIN_ROOT_LENGTH_FOR_FUZZY_MATCH = 4
IOC_TYPES = ("ips", "urls", "hashes", "domains")


def _domains_are_related(a: str, b: str, threshold: float) -> bool:
    """Return True when two observed domains are sufficiently similar."""
    if a == b:
        return True

    root_a, root_b = get_brand_root(a), get_brand_root(b)

    if root_a == root_b:
        return True

    if (
        len(root_a) < _MIN_ROOT_LENGTH_FOR_FUZZY_MATCH
        or len(root_b) < _MIN_ROOT_LENGTH_FOR_FUZZY_MATCH
    ):
        return False

    return similarity_ratio(root_a, root_b) >= threshold


def _collect_exact_matches(
    db: Any,
    ioc_analysis: dict,
    excluded_email_id: Optional[str] = None,
) -> tuple[dict[str, dict], set[str]]:
    """Find historical emails with exact IOC overlap."""
    matched_docs: dict[str, dict] = {}
    matched_infra: set[str] = set()

    for ioc_type in IOC_TYPES:
        values = ioc_analysis.get(ioc_type) or []
        if not values:
            continue

        value_set = set(values)
        for hit in repository.find_by_ioc_exact(db, ioc_type, values):
            hit_id = str(hit["_id"])
            if excluded_email_id is not None and hit_id == excluded_email_id:
                continue

            hit_values = set(hit.get("ioc_analysis", {}).get(ioc_type, []))
            overlap = hit_values & value_set
            if not overlap:
                continue

            matched_docs[hit_id] = hit
            matched_infra.update(overlap)

    return matched_docs, matched_infra


def _collect_fuzzy_domain_matches(
    db: Any,
    domains: list[str],
    threshold: float,
    excluded_email_id: Optional[str] = None,
) -> tuple[dict[str, dict], set[str]]:
    """Find historical emails whose domains are fuzzy matches."""
    matched_docs: dict[str, dict] = {}
    matched_infra: set[str] = set()

    if not domains:
        return matched_docs, matched_infra

    current_domains = set(domains)
    # Filter out None/empty here rather than relying solely on
    # get_brand_root()'s own None-guard -- MongoDB's distinct() (see
    # repository.get_all_domains) includes null as a distinct value if
    # any stored document has a missing/empty ioc_analysis.domains field,
    # so this list can legitimately contain junk entries from older/
    # partial pipeline runs.
    historical_domains = [d for d in repository.get_all_domains(db) if d]

    for historical_domain in historical_domains:
        if historical_domain in current_domains:
            continue

        if not any(
            _domains_are_related(domain, historical_domain, threshold)
            for domain in domains
        ):
            continue

        hits = repository.find_by_ioc_exact(db, "domains", [historical_domain])
        for hit in hits:
            hit_id = str(hit["_id"])
            if excluded_email_id is not None and hit_id == excluded_email_id:
                continue
            matched_docs[hit_id] = hit
            matched_infra.add(historical_domain)

    return matched_docs, matched_infra


def correlate_and_store(
    ioc_analysis: dict,
    *,
    db: Optional[Any] = None,
    message_id: Optional[str] = None,
    subject: Optional[str] = None,
    from_email: Optional[str] = None,
    to_email: Optional[str] = None,
    email_date: Optional[str] = None,
    source_format: Optional[str] = None,
    analyzed_at: Optional[datetime] = None,
    header_analysis: Optional[dict] = None,
    attachment_analysis: Optional[dict] = None,
    threat_intel_analysis: Optional[dict] = None,
    content_analysis: Optional[dict] = None,
    fuzzy_domain_threshold: float = DEFAULT_FUZZY_DOMAIN_THRESHOLD,
) -> dict:
    """
    Correlate one email against history, assign/merge its campaign, and
    store the current analysis record.

    The optional metadata fields let Stage A/B/B2/E results be persisted
    without making Stage F responsible for producing those results.
    """
    db = db if db is not None else connection.get_db()
    analyzed_at = analyzed_at or datetime.now(timezone.utc)

    # If this message was analyzed before, its existing record must not be
    # treated as a historical match against itself.
    existing = None
    existing_email_id: Optional[str] = None
    previous_campaign_id: Optional[str] = None
    if message_id:
        existing = repository.find_analysis_by_message_id(db, message_id)
        if existing:
            existing_email_id = str(existing["_id"])
            previous_campaign_id = existing.get("campaign_id")

    exact_docs, exact_infra = _collect_exact_matches(
        db, ioc_analysis, excluded_email_id=existing_email_id
    )
    fuzzy_docs, fuzzy_infra = _collect_fuzzy_domain_matches(
        db,
        ioc_analysis.get("domains") or [],
        fuzzy_domain_threshold,
        excluded_email_id=existing_email_id,
    )

    matched_docs = {**exact_docs, **fuzzy_docs}
    matched_infra = exact_infra | fuzzy_infra

    related_campaign_ids = sorted(
        {
            doc.get("campaign_id")
            for doc in matched_docs.values()
            if doc.get("campaign_id")
        }
    )

    merged_campaigns: list[str] = []

    if related_campaign_ids:
        campaign_id = related_campaign_ids[0]
        if len(related_campaign_ids) > 1:
            merged_campaigns = related_campaign_ids[1:]
            repository.merge_campaigns(db, campaign_id, merged_campaigns)
        is_new_campaign = False
    elif previous_campaign_id:
        # Idempotent re-analysis with no external matches: keep the email in
        # its existing campaign rather than creating a duplicate campaign.
        campaign_id = previous_campaign_id
        is_new_campaign = False
    else:
        campaign_id = repository.next_campaign_id(db)
        repository.create_campaign(db, campaign_id)
        is_new_campaign = True

    doc = {
        "subject": subject,
        "from_email": from_email,
        "to_email": to_email,
        "email_date": email_date,
        "source_format": source_format,
        "analyzed_at": analyzed_at,
        "header_analysis": header_analysis,
        "attachment_analysis": attachment_analysis,
        "threat_intel_analysis": threat_intel_analysis,
        "content_analysis": content_analysis,
        "ioc_analysis": ioc_analysis,
        "campaign_id": campaign_id,
    }

    if message_id:
        doc["message_id"] = message_id

    email_id = repository.insert_analysis(db, doc)

    # If an existing message moves from one campaign to another, keep the
    # campaign membership lists consistent as well as the email document.
    if previous_campaign_id and previous_campaign_id != campaign_id:
        repository.remove_member_from_campaign(db, previous_campaign_id, email_id)

    repository.add_member_to_campaign(
        db, campaign_id, email_id, sorted(matched_infra)
    )

    related_emails = sorted(
        eid for eid in matched_docs.keys() if eid != email_id
    )

    from .historical_stats import compute_historical_stats
    historical_stats = compute_historical_stats(
        db,
        ioc_analysis,
        current_email_id=existing_email_id,
        campaign_id=campaign_id,
        now=analyzed_at,
    )

    # Invalidate precomputed adjacency cache upon new correlation writes
    try:
        from ai_engine.graph_diffusion import invalidate_graph_cache
        invalidate_graph_cache()
    except Exception:
        pass

    return {
        "email_id": email_id,
        "campaign_id": campaign_id,
        "is_new_campaign": is_new_campaign,
        "category_status": historical_stats["category_status"],
        "category_badge": historical_stats["category_badge"],
        "is_new_category": historical_stats["is_new_category"],
        "historical_stats": historical_stats,
        "merged_campaigns": merged_campaigns,
        "related_emails": related_emails,
        "shared_infrastructure": sorted(matched_infra),
    }