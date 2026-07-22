import unittest
from unittest.mock import Mock, patch

import requests
from protection_report.breach import check_breach
from protection_report.models import Account
from protection_report.report import RiskAnalyzer
from protection_report.parsers import (
    detect_source_and_parse,
    detect_source_from_filename,
)


class ParserTests(unittest.TestCase):
    def test_detects_and_parses_supported_sources(self):
        cases = [
            ("report_user_simple.json", {"GitHub": {"status": {"status": "Claimed"}}}, "maigret"),
            ("sherlock_user.json", {"GitLab": {"status": "Claimed"}}, "sherlock"),
            ("blackbird_user.json", [{"site": "Forum", "username": "user"}], "blackbird"),
            ("naminter_user.json", {"Blog": {"status": "Claimed"}}, "naminter"),
        ]
        for filename, payload, source in cases:
            self.assertEqual(detect_source_from_filename(filename), source)
            accounts = detect_source_and_parse(payload, source)
            self.assertEqual(len(accounts), 1)
            self.assertIsInstance(accounts[0], Account)

    def test_breach_http_failure_is_not_clean(self):
        response = Mock(status_code=503)
        with patch("protection_report.breach.requests.get", return_value=response):
            result = check_breach("user@example.test")
        self.assertFalse(result.found)
        self.assertIsNotNone(result.error)
        self.assertIn("HTTP 503", result.error)

    def test_breach_request_failure_is_not_clean(self):
        with patch("protection_report.breach.requests.get", side_effect=requests.RequestException("offline")):
            result = check_breach("user@example.test")
        self.assertFalse(result.found)
        self.assertIsNotNone(result.error)
        self.assertIn("offline", result.error)

    def test_deduplicate_before_risk_analysis(self):
        duplicate = Account(site="GitHub", url="https://example.test/u", username="u")
        unique = Account(site="GitLab", url="https://example.test/v", username="u")
        accounts = RiskAnalyzer.deduplicate([duplicate, duplicate, unique])
        analyzer = RiskAnalyzer(accounts)
        self.assertEqual(len(accounts), 2)
        self.assertEqual(len(analyzer.cluster()["unclustered"]), 2)

    def test_parses_supported_payload_with_generic_filename_hint(self):
        payload = [{"title": "GitHub", "url": "https://github.com/user", "found": True}]
        hint = detect_source_from_filename("input.json")
        self.assertEqual(hint, "unknown")
        self.assertEqual(len(detect_source_and_parse(payload, hint)), 1)

    def test_parses_enola_json(self):
        payload = [
            {"title": "GitHub", "url": "https://github.com/user", "found": True},
            {"title": "GitLab", "url": "https://gitlab.com/user", "found": False},
        ]
        self.assertEqual(detect_source_from_filename("enola_user.json"), "enola")
        accounts = detect_source_and_parse(payload, "enola")
        self.assertEqual([(a.site, a.url) for a in accounts], [("GitHub", "https://github.com/user")])

    def test_parses_vesper_json(self):
        payload = {"usernames": [{"username": "user", "results": [
            {"site": "GitHub", "link": "https://github.com/user", "exist": True, "status": "CONFIRMED"},
            {"site": "GitLab", "link": "", "exist": False, "status": "NOT_FOUND"},
        ]}]}
        self.assertEqual(detect_source_from_filename("vesper_user.json"), "vesper")
        accounts = detect_source_and_parse(payload, "vesper")
        self.assertEqual([(a.site, a.url) for a in accounts], [("GitHub", "https://github.com/user")])


if __name__ == "__main__":
    unittest.main()
