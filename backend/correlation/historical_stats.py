"""
correlation.historical_stats -- Real-time IOC repetition and historical database comparison.

Compares incoming email indicators (IPs, domains, attachment hashes, URLs) against
all previously analyzed emails stored in MongoDB to:
  1. Determine repetition counts: Seen This Week (last 7 days), Seen This Month (last 30 days), and All-Time.
  2. Categorize the threat:
       - "NEW_THREAT_CLUSTER" (New Category): Zero historical overlap in database.
       - "RECURRING_ADVERSARY_ACTIVITY": Matches observed in prior incidents.
  3. Generate executive threat summaries and incident correlation links.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from db import repository
from db.schema import ANALYSES_COLLECTION


def _parse_timestamp(val: Any) -> Optional[datetime]:
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=timezone.utc)
        return val
    if isinstance(val, str) and val.strip():
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None
    return None


def compute_historical_stats(
    db: Any,
    ioc_analysis: dict,
    *,
    current_email_id: Optional[str] = None,
    campaign_id: Optional[str] = None,
    now: Optional[datetime] = None,
) -> dict:
    """
    Query database for past emails sharing any IOC with the current email.
    Computes weekly/monthly repetition metrics and classifies as new category vs recurring threat.
    """
    now = now or datetime.now(timezone.utc)
    one_week_ago = now - timedelta(days=7)
    one_month_ago = now - timedelta(days=30)

    ioc_mappings = [
        ("ips", "ip"),
        ("domains", "domain"),
        ("hashes", "hash"),
        ("urls", "url"),
    ]

    indicator_reports: list[dict] = []
    all_matched_incidents: dict[str, dict] = {}
    total_overlapping_iocs = 0
    max_week = 0
    max_month = 0

    repeated_ips: list[tuple[str, int, int]] = []
    repeated_domains: list[tuple[str, int, int]] = []
    repeated_hashes: list[tuple[str, int, int]] = []
    repeated_urls: list[tuple[str, int, int]] = []

    for ioc_field, type_label in ioc_mappings:
        raw_values = ioc_analysis.get(ioc_field) or []
        for val in raw_values:
            if not val or not isinstance(val, str):
                continue
            val_str = val.strip()
            if not val_str:
                continue

            # Query database for all past documents with this exact IOC
            hits = repository.find_by_ioc_exact(db, ioc_field, [val_str])
            
            # Filter out current email itself if it was already saved
            valid_hits = [
                h for h in hits
                if current_email_id is None or str(h.get("_id")) != str(current_email_id)
            ]

            this_week_count = 0
            this_month_count = 0
            all_time_count = len(valid_hits)
            first_seen_dt: Optional[datetime] = None
            last_seen_dt: Optional[datetime] = None
            associated_campaigns: set[str] = set()
            prior_incidents: list[dict] = []

            for hit in valid_hits:
                hit_id = str(hit.get("_id"))
                hit_dt = _parse_timestamp(hit.get("analyzed_at"))

                if hit_dt:
                    if hit_dt >= one_week_ago:
                        this_week_count += 1
                    if hit_dt >= one_month_ago:
                        this_month_count += 1

                    if first_seen_dt is None or hit_dt < first_seen_dt:
                        first_seen_dt = hit_dt
                    if last_seen_dt is None or hit_dt > last_seen_dt:
                        last_seen_dt = hit_dt

                c_id = hit.get("campaign_id")
                if c_id:
                    associated_campaigns.add(c_id)

                incident_summary = {
                    "id": hit_id,
                    "message_id": hit.get("message_id"),
                    "subject": hit.get("subject") or "No Subject",
                    "from_email": hit.get("from_email") or "Unknown Sender",
                    "analyzed_at": hit_dt.isoformat() if hit_dt else None,
                    "campaign_id": c_id,
                    "verdict": hit.get("verdict") or "UNASSESSED",
                    "risk_score": hit.get("risk_score"),
                }
                prior_incidents.append(incident_summary)
                all_matched_incidents[hit_id] = incident_summary

            is_new = (all_time_count == 0)

            if not is_new:
                total_overlapping_iocs += 1
                if this_week_count > max_week:
                    max_week = this_week_count
                if this_month_count > max_month:
                    max_month = this_month_count

                if type_label == "ip":
                    repeated_ips.append((val_str, this_week_count, this_month_count))
                elif type_label == "domain":
                    repeated_domains.append((val_str, this_week_count, this_month_count))
                elif type_label == "hash":
                    repeated_hashes.append((val_str, this_week_count, this_month_count))
                elif type_label == "url":
                    repeated_urls.append((val_str, this_week_count, this_month_count))

            indicator_reports.append({
                "type": type_label,
                "value": val_str,
                "this_week": this_week_count,
                "this_month": this_month_count,
                "all_time": all_time_count,
                "is_new": is_new,
                "first_seen": first_seen_dt.isoformat() if first_seen_dt else None,
                "last_seen": last_seen_dt.isoformat() if last_seen_dt else None,
                "associated_campaigns": sorted(associated_campaigns),
                "prior_incidents": prior_incidents[:10], # Top 10 most relevant
            })

    is_new_category = (total_overlapping_iocs == 0)
    assigned_campaign = campaign_id or "campaign_new"

    # Build executive narrative and category classification
    if is_new_category:
        category_status = "NEW_THREAT_CLUSTER"
        category_badge = "NEW THREAT CATEGORY"
        executive_summary = (
            f"New Threat Cluster Identified. Zero prior occurrences of these indicators were found in the database. "
            f"A new threat category has been initialized ({assigned_campaign})."
        )
    else:
        category_status = "RECURRING_ADVERSARY_ACTIVITY"
        repetition_fragments: list[str] = []

        for ip, w, m in repeated_ips[:2]:
            w_text = f"{w} times this week" if w > 0 else "0 times this week"
            m_text = f"{m} times this month" if m > 0 else "0 times this month"
            repetition_fragments.append(f"Originating IP {ip} was detected in {w_text} ({m_text})")

        for dom, w, m in repeated_domains[:2]:
            repetition_fragments.append(f"Domain '{dom}' previously observed across {m or 1} incident(s)")

        for h, w, m in repeated_hashes[:1]:
            short_h = h[:16] + "..." if len(h) > 16 else h
            repetition_fragments.append(f"Attachment payload ({short_h}) matches prior analyzed malware")

        if not repetition_fragments and repeated_urls:
            repetition_fragments.append(f"Referenced URL seen across prior incident records")

        summary_body = ". ".join(repetition_fragments)
        category_badge = f"RECURRING THREAT ({max_week}x THIS WEEK)" if max_week > 0 else f"RECURRING THREAT ({max_month}x THIS MONTH)"
        executive_summary = (
            f"Recurring adversary activity detected. {summary_body}. "
            f"Correlated with {len(all_matched_incidents)} prior incident(s) in category {assigned_campaign}."
        )

    return {
        "category_status": category_status,
        "category_badge": category_badge,
        "is_new_category": is_new_category,
        "assigned_campaign_id": assigned_campaign,
        "executive_summary": executive_summary,
        "metrics_summary": {
            "total_overlapping_iocs": total_overlapping_iocs,
            "total_prior_incidents": len(all_matched_incidents),
            "max_repetition_this_week": max_week,
            "max_repetition_this_month": max_month,
            "has_repeated_ip": len(repeated_ips) > 0,
            "has_repeated_domain": len(repeated_domains) > 0,
            "has_repeated_hash": len(repeated_hashes) > 0,
            "has_repeated_url": len(repeated_urls) > 0,
        },
        "indicators": indicator_reports,
        "prior_incidents": list(all_matched_incidents.values())[:15],
    }
