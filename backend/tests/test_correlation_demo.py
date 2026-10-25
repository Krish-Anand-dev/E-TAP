"""
Demo/regression script for Stage F.

Run with:
    USE_FAKE_DB=1 PYTHONPATH=. python3 tests/test_correlation_demo.py

Walks through a sequence of emails that should exercise:
    1. a brand new campaign (no history yet)
    2. a second, unrelated new campaign
    3. an EXACT ip match joining an existing campaign
    4. a FUZZY domain (typosquat) match joining an existing campaign,
       with no exact IOC overlap at all
    5. a bridging email that shares infrastructure with two previously
       SEPARATE campaigns -> those two campaigns should get merged
    6. the read-only query API (recent, by-ioc, campaign detail)
"""

import json
import sys

sys.path.insert(0, ".")

from db import connection
from correlation import correlate_and_store, queries


def header(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def show(result):
    print(json.dumps(result, indent=2, default=str))


def main():
    connection.reset_db()
    import os
    os.environ["USE_FAKE_DB"] = "1"

    # 1. First email ever processed: cyberpeace.net newsletter-ish IOCs.
    header("1) First email -- expect a brand new campaign")
    r1 = correlate_and_store(
        ioc_analysis={
            "ips": ["198.2.131.94"],
            "domains": ["cyberpeace.net", "mcusercontent.com"],
            "urls": [],
            "hashes": [],
        },
        subject="Get Ready for the Hunt!",
        from_email="cyberquest@cyberpeace.net",
        message_id="<msg1@cyberpeace.net>",
    )
    show(r1)
    assert r1["is_new_campaign"] is True
    assert r1["related_emails"] == []

    # 2. Second email: totally unrelated phishing attempt.
    header("2) Second email -- unrelated phishing, expect ANOTHER new campaign")
    r2 = correlate_and_store(
        ioc_analysis={
            "ips": ["45.33.32.156"],
            "domains": ["paypa1-verify.com"],
            "urls": ["https://paypa1-verify.com/login"],
            "hashes": [],
        },
        subject="Your account has been suspended",
        from_email="security@paypa1-verify.com",
        message_id="<msg2@paypa1-verify.com>",
    )
    show(r2)
    assert r2["is_new_campaign"] is True
    assert r2["campaign_id"] != r1["campaign_id"]

    # 3. Third email: EXACT ip match with email #2's infrastructure,
    #    completely different domain.
    header("3) Third email -- shares email #2's IP exactly, different domain")
    r3 = correlate_and_store(
        ioc_analysis={
            "ips": ["45.33.32.156"],
            "domains": ["totally-different-brand-page.com"],
            "urls": [],
            "hashes": [],
        },
        subject="Urgent: verify your billing details",
        from_email="billing@totally-different-brand-page.com",
        message_id="<msg3@example.com>",
    )
    show(r3)
    assert r3["is_new_campaign"] is False
    assert r3["campaign_id"] == r2["campaign_id"], "should join email #2's campaign via shared IP"
    assert "45.33.32.156" in r3["shared_infrastructure"]

    # 4. Fourth email: NO exact overlap with anything, but its domain is
    #    a typosquat variant of email #2's domain -> should still join
    #    email #2's (now-merged-with-#3) campaign via fuzzy matching.
    header("4) Fourth email -- typosquat variant of email #2's domain, no exact overlap")
    r4 = correlate_and_store(
        ioc_analysis={
            "ips": ["91.203.5.19"],
            "domains": ["paypal-verify1.com"],
            "urls": [],
            "hashes": [],
        },
        subject="Confirm your identity",
        from_email="noreply@paypal-verify1.com",
        message_id="<msg4@example.com>",
    )
    show(r4)
    assert r4["is_new_campaign"] is False
    assert r4["campaign_id"] == r2["campaign_id"], "should join via fuzzy domain match, not exact"

    # 5. Fifth email: a BRIDGE. Shares an IP with campaign #1 (yes, we're
    #    pretending the newsletter's mail server got compromised/reused --
    #    purely to exercise the merge path) and shares a domain with
    #    campaign #2/#3/#4. Two previously separate campaigns should merge.
    header("5) Fifth email -- bridges campaign #1 and campaign #2/3/4 -> expect a MERGE")
    r5 = correlate_and_store(
        ioc_analysis={
            "ips": ["198.2.131.94"],
            "domains": ["paypa1-verify.com"],
            "urls": [],
            "hashes": [],
        },
        subject="bridge test",
        from_email="bridge@example.com",
        message_id="<msg5@example.com>",
    )
    show(r5)
    assert r5["merged_campaigns"], "expected a merge to have happened"
    assert r5["campaign_id"] == min(r1["campaign_id"], r2["campaign_id"])

    # 5b) Re-processing the same message_id should update the existing
    #     record rather than create another document/campaign.
    header("5b) Re-process email #5 -- expect idempotent update")
    r5b = correlate_and_store(
        ioc_analysis={
            "ips": ["198.2.131.94"],
            "domains": ["paypa1-verify.com"],
            "urls": [],
            "hashes": [],
        },
        subject="bridge test updated",
        from_email="bridge@example.com",
        message_id="<msg5@example.com>",
    )
    show(r5b)
    assert r5b["email_id"] == r5["email_id"]
    assert r5b["campaign_id"] == r5["campaign_id"]
    assert len(queries.recent_analyses(limit=100)) == 5

    # 5c) A completely IOC-free email is still persisted. It receives a
    #     campaign container under the current Stage F policy, but F does
    #     not require a match in order to save the analysis.
    header("5c) IOC-free email -- expect storage even without matches")
    r5c = correlate_and_store(
        ioc_analysis={"ips": [], "domains": [], "urls": [], "hashes": []},
        subject="no IOC message",
        from_email="user@example.com",
        message_id="<msg6@example.com>",
    )
    show(r5c)
    assert r5c["is_new_campaign"] is True
    assert len(queries.recent_analyses(limit=100)) == 6

    # -- read-only query API ------------------------------------------
    header("6) queries.recent_analyses(limit=3)")
    show(queries.recent_analyses(limit=3))

    header("7) queries.analyses_by_ioc('ips', '45.33.32.156')")
    hits = queries.analyses_by_ioc("ips", "45.33.32.156")
    print(f"{len(hits)} email(s) matched")
    for h in hits:
        print(" -", h["subject"], "|", h["campaign_id"])

    header("8) queries.list_campaigns()")
    campaigns = queries.list_campaigns()
    for c in campaigns:
        print(f" - {c['campaign_id']}: members={c['members']} infra={c['shared_infrastructure']}")

    header("9) queries.campaign_detail(merged campaign id)")
    detail = queries.campaign_detail(r5["campaign_id"])
    print(f"campaign_id={detail['campaign_id']}")
    print(f"members={detail['members']}")
    print(f"shared_infrastructure={detail['shared_infrastructure']}")
    print(f"member_analyses subjects={[m['subject'] for m in detail['member_analyses']]}")

    print("\n\nALL ASSERTIONS PASSED")


if __name__ == "__main__":
    main()
