import unittest

from protection_report.models import Account
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


if __name__ == "__main__":
    unittest.main()
