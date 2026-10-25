"""Origin / hop resolution: provider relays must never be shown as the sender."""
from forensics.received_chain import (
    parse_hops, build_origin_analysis, find_originating_ip, resolve_origin, extract_ips_from_text,
)

# newest first, like real headers
GMAIL_RELAY = {"Received": [
    "from mx.victim.com (mx.victim.com [10.0.0.5]) by inbox.victim.com with LMTP; Mon, 14 Sep 2026 15:30:10 +0000",
    "from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) by mx.victim.com with ESMTPS; Mon, 14 Sep 2026 15:30:05 +0000",
    "from [192.168.1.7] by smtp.gmail.com with ESMTPSA id abc; Mon, 14 Sep 2026 15:30:01 +0000",
]}

GMAIL_SMTP_CLIENT = {"Received": [
    "from mx.victim.com (mx.victim.com [10.0.0.5]) by inbox.victim.com; Mon, 14 Sep 2026 15:30:10 +0000",
    "from [192.168.1.7] ([103.21.58.9]) by smtp.gmail.com with ESMTPSA id q1; Mon, 14 Sep 2026 15:30:01 +0000",
]}

TOR_DIRECT = {"Received": [
    "from mail.evil.test ([185.220.101.46]) by mx.victim.com with ESMTP id 1; Mon, 14 Sep 2026 15:30:00 -0000",
]}

IPV6_GOOGLE = {"Received": [
    "from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com [2a00:1450:4864:20::32e]) by mx.victim.com; Mon, 14 Sep 2026 15:30:05 +0000",
]}

XORIG = {"Received": [
    "from relay.sender-corp.test (relay.sender-corp.test [45.33.32.20]) by mx.victim.com; Mon, 14 Sep 2026 15:30:05 +0000",
], "X-Originating-IP": ["[91.198.174.77]"]}


def test_gmail_relay_is_not_reported_as_origin():
    o = build_origin_analysis(GMAIL_RELAY)["origin"]
    assert o["origin_kind"] == "provider_relay_only"
    assert o["true_origin_ip"] is None
    assert o["origin_provider"] == "Google"
    assert o["first_public_hop_ip"] == "209.85.220.41"   # still available for SPF


def test_spf_ip_contract_unchanged():
    assert find_originating_ip(GMAIL_RELAY) == "209.85.220.41"


def test_client_ip_on_submission_hop_is_found():
    o = build_origin_analysis(GMAIL_SMTP_CLIENT)["origin"]
    assert o["true_origin_ip"] == "103.21.58.9"
    assert o["origin_kind"] == "sender_client"


def test_by_clause_ip_is_ignored():
    hops = parse_hops({"Received": ["from a.test ([45.33.32.1]) by b.test ([91.198.174.9]); Mon, 14 Sep 2026 15:30:00 +0000"]})
    assert hops[0]["ip"] == "45.33.32.1"


def test_compressed_ipv6():
    assert extract_ips_from_text("[2a00:1450:4864:20::32e]") == ["2a00:1450:4864:20::32e"]
    o = build_origin_analysis(IPV6_GOOGLE)["origin"]
    assert o["origin_kind"] == "provider_relay_only"


def test_x_originating_ip_wins_over_unknown_relay():
    o = build_origin_analysis(XORIG)["origin"]
    assert o["true_origin_ip"] == "91.198.174.77" and o["origin_source"] == "header:X-Originating-IP"


def test_unknown_direct_relay_is_origin():
    o = build_origin_analysis(TOR_DIRECT)["origin"]
    assert o["true_origin_ip"] == "185.220.101.46" and o["origin_kind"] == "sender_client"


def test_anonymizer_flag_downgrades_origin():
    hops = parse_hops(TOR_DIRECT)
    hops[0]["anonymizer"] = True
    hops[0]["kind"] = "anonymizer"
    o = resolve_origin(hops)
    assert o["origin_kind"] == "anonymizer_exit" and o["confidence"] == "low"


def test_hop_order_and_delay():
    hops = parse_hops(GMAIL_RELAY)
    assert [h["index"] for h in hops] == [0, 1, 2]
    assert hops[1]["delay_s"] == 4 and hops[0]["kind"] == "private"


def test_no_received_headers():
    o = build_origin_analysis({})["origin"]
    assert o["origin_kind"] == "none" and o["true_origin_ip"] is None
