"""Hop geolocation must reach provider coverage, without claiming sender attribution."""
import unittest
from unittest.mock import patch

from forensics.received_chain import build_origin_analysis
from provider_status import build_provider_status
from threat_intel.hop_geo import attach_hop_geo


def headers(ip="209.85.220.41", host="mail-sor-f41.google.com"):
    parsed = build_origin_analysis({"Received": [
        f"from {host} ([{ip}]) by mx.example.test; Mon, 14 Sep 2026 15:30:05 +0000"
    ]})
    return {"hops": parsed["hops"], "origin_analysis": parsed["origin"]}


def coverage(intel, live=True):
    return build_provider_status(
        threat_intel=intel, iocs={}, threat_intel_live=live,
        final_assessment={"provider": "xgboost_triage"}, gemini_skipped=True,
    )["providers"]["ip_geolocation"]


class HopGeoTests(unittest.TestCase):
    def test_hop_answer_is_counted_and_google_relay_is_not_the_sender(self):
        message, intel = headers(), {}
        answer = {"status": "available", "lat": 37.4, "lon": -122.1, "country": "US", "org": "Google LLC"}
        with patch("threat_intel.hop_geo.get_ip_geolocation", return_value={"209.85.220.41": answer}):
            attach_hop_geo(message, intel, live=True)
        self.assertEqual(message["hops"][0]["geo"]["lat"], 37.4)
        self.assertEqual(message["origin_analysis"]["origin_kind"], "provider_relay_only")
        self.assertIsNone(message["origin_analysis"]["true_origin_ip"])
        self.assertEqual(intel["geo_lookup"]["209.85.220.41"], answer)
        self.assertEqual(coverage(intel)["status"], "available")
        self.assertEqual(coverage(intel)["succeeded"], 1)

    def test_failed_hop_lookup_is_not_reported_as_not_needed(self):
        message, intel = headers(), {}
        with patch("threat_intel.hop_geo.get_ip_geolocation", return_value={"209.85.220.41": {"status": "timeout"}}):
            attach_hop_geo(message, intel, live=True)
        self.assertIsNone(message["hops"][0]["geo"])
        self.assertEqual(coverage(intel)["status"], "timeout")
        self.assertEqual(coverage(intel)["failed"], 1)

    def test_existing_answer_is_reused_without_another_request(self):
        message = headers()
        intel = {"geo_lookup": {"209.85.220.41": {"status": "available", "lat": 37.4, "lon": -122.1}}}
        with patch("threat_intel.hop_geo.get_ip_geolocation") as lookup:
            attach_hop_geo(message, intel, live=True)
        lookup.assert_not_called()
        self.assertEqual(coverage(intel)["succeeded"], 1)

    def test_live_off_never_sends_a_lookup_and_keeps_disabled_coverage(self):
        message, intel = headers(), {}
        with patch("threat_intel.hop_geo.get_ip_geolocation") as lookup:
            attach_hop_geo(message, intel, live=False)
        lookup.assert_not_called()
        self.assertIsNone(message["hops"][0]["geo"])
        self.assertEqual(coverage(intel, live=False)["status"], "disabled")

    def test_private_hops_never_need_an_external_lookup(self):
        message, intel = headers("10.0.0.1", "internal.example.test"), {}
        with patch("threat_intel.hop_geo.get_ip_geolocation") as lookup:
            attach_hop_geo(message, intel, live=True)
        lookup.assert_not_called()
        self.assertIsNone(message["hops"][0]["geo"])
        self.assertEqual(coverage(intel)["status"], "not_needed")


if __name__ == "__main__":
    unittest.main()
