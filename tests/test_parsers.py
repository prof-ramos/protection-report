import unittest

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

    def test_deduplicate_before_risk_analysis(self):
        duplicate = Account(site="GitHub", url="https://example.test/u", username="u")
        unique = Account(site="GitLab", url="https://example.test/v", username="u")
        accounts = RiskAnalyzer.deduplicate([duplicate, duplicate, unique])
        analyzer = RiskAnalyzer(accounts)
        self.assertEqual(len(accounts), 2)
        self.assertEqual(len(analyzer.cluster()["unclustered"]), 2)


if __name__ == "__main__":
    unittest.main()
