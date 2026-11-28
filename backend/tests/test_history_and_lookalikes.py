"""What counts as "seen before", and which domains count as imitations (fixes of 2026-11-28)."""
import pytest

from correlation import correlate_and_store
from correlation.common_providers import is_common_provider
from db import repository
from db.fake_mongo import FakeDatabase
from forensics.domain_similarity import analyze_domain, find_lookalike_brand

ATTACHMENT = "a" * 64


def iocs(domains=(), hashes=(), urls=()):
    return {"ips": [], "domains": list(domains), "urls": list(urls), "hashes": list(hashes)}


def store(db, mid, found, **extra):
    result = correlate_and_store(found, db=db, message_id=f"<{mid}@x>", subject=mid, **extra)
    return result, result["historical_stats"]


def test_a_new_email_is_not_its_own_history():
    result, stats = store(FakeDatabase(), "first", iocs(["evil-site.test"], [ATTACHMENT]))
    assert stats["is_new_category"] and stats["metrics_summary"]["total_prior_incidents"] == 0
    assert result["related_emails"] == [] and result["category_status"] == "NEW_THREAT_CLUSTER"


def test_the_second_email_counts_exactly_one_earlier_one():
    db = FakeDatabase()
    store(db, "first", iocs(["evil-site.test"]))
    _, stats = store(db, "second", iocs(["evil-site.test"]))
    assert stats["metrics_summary"]["total_prior_incidents"] == 1
    assert "seen in 1 earlier email." in stats["executive_summary"]


def test_shared_mail_providers_do_not_link_emails():
    db = FakeDatabase()
    first, _ = store(db, "first", iocs(["gmail.com", "mail.gmail.com"]))
    second, stats = store(db, "second", iocs(["gmail.com", "mail.gmail.com"]))
    assert second["related_emails"] == [] and second["campaign_id"] != first["campaign_id"]
    assert stats["is_new_category"] and all(i["common_provider"] for i in stats["indicators"])


@pytest.mark.parametrize("domain,expected", [
    ("gmail.com", True), ("mail.gmail.com", True), ("outlook.com", True),
    ("gmail.com.evil.test", False), ("notgmail.com", False), ("evil-site.test", False),
])
def test_which_domains_are_common_providers(domain, expected):
    assert is_common_provider(domain) is expected


def test_a_repeated_harmless_file_is_not_called_malware_or_adversary_activity():
    db = FakeDatabase()
    store(db, "first", iocs(hashes=[ATTACHMENT]))
    _, stats = store(db, "second", iocs(hashes=[ATTACHMENT]))
    text = (stats["executive_summary"] + stats["category_badge"]).lower()
    assert "malware" not in text and "malicious" not in text and "adversary" not in text
    assert stats["category_badge"].startswith("SEEN BEFORE")


def test_repeats_of_flagged_or_risky_emails_say_so():
    db = FakeDatabase()
    flagged = {"hash_reputation": {ATTACHMENT: {"malicious": True}}}
    first, _ = store(db, "first", iocs(hashes=[ATTACHMENT]), threat_intel_analysis=flagged)
    repository.update_analysis_fields(db, first["email_id"], {"risk_score": 90})
    _, stats = store(db, "second", iocs(hashes=[ATTACHMENT]))
    assert "reputation services flag it as malicious" in stats["executive_summary"]
    assert stats["category_badge"].startswith("RECURRING THREAT")


@pytest.mark.parametrize("domain", ["facebookmail.com", "amazonses.com", "bounce.amazonses.com",
                                    "googlemail.com", "facebook.com"])
def test_a_companys_own_domains_are_not_imitations(domain):
    assert find_lookalike_brand(domain) is None


@pytest.mark.parametrize("domain,brand", [
    ("faceb00k.com", "facebook.com"), ("paypa1.com", "paypal.com"), ("g00gle.com", "google.com"),
])
def test_imitations_with_swapped_digits_are_caught(domain, brand):
    found = find_lookalike_brand(domain)
    assert found and found["brand"] == brand
    assert f"lookalike_of_{brand}" in analyze_domain(domain)["flags"]
