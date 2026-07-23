"""Test suite for protection-report parsers, models, and CLI."""

import json
import os
import subprocess
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests
from protection_report.breach import check_breach
from protection_report.models import Account, normalize_url, ParseResult
from protection_report.report import RiskAnalyzer
from protection_report.parsers import (
    detect_source_and_parse,
    detect_source_from_filename,
    ParserFormatError,
)


FIXTURES = Path(__file__).parent / "fixtures"


class ParserTests(unittest.TestCase):
    maxDiff = None

    def _load_fixture(self, name: str):
        """Load a fixture JSON file."""
        path = FIXTURES / name
        with open(path) as f:
            return json.load(f)

    def assert_parse_result(self, result: ParseResult, expected_count: int,
                            source: str = "", error: bool = False):
        """Assert a ParseResult has the expected shape."""
        self.assertIsInstance(result, ParseResult)
        self.assertEqual(len(result.accounts), expected_count,
                         f"expected {expected_count} accounts, got {len(result.accounts)}: "
                         f"{result.error or 'ok'}")
        if error:
            self.assertIsNotNone(result.error)
        else:
            self.assertIsNone(result.error, f"unexpected error: {result.error}")
        if source:
            self.assertEqual(result.source, source)
        if result.accounts:
            for a in result.accounts:
                self.assertIsInstance(a, Account)

    # --- detect_source_from_filename ---

    def test_detects_maigret_by_filename(self):
        self.assertEqual(detect_source_from_filename("report_user_simple.json"), "maigret")

    def test_detects_sherlock_by_filename(self):
        self.assertEqual(detect_source_from_filename("sherlock_user.json"), "sherlock")

    def test_detects_blackbird_by_filename(self):
        self.assertEqual(detect_source_from_filename("blackbird_user.json"), "blackbird")

    def test_detects_naminter_by_filename(self):
        self.assertEqual(detect_source_from_filename("naminter_user.json"), "naminter")

    def test_detects_enola_by_filename(self):
        self.assertEqual(detect_source_from_filename("enola_user.json"), "enola")

    def test_detects_vesper_by_filename(self):
        self.assertEqual(detect_source_from_filename("vesper_user.json"), "vesper")

    def test_generic_filename_returns_unknown(self):
        self.assertEqual(detect_source_from_filename("input.json"), "unknown")

    def test_vesper_detection_precedes_generic_maigret_pattern(self):
        self.assertEqual(detect_source_from_filename("report_vesper_user.json"), "vesper")

    # --- parse — maigret ---

    def test_parse_maigret_with_fixture(self):
        data = self._load_fixture("maigret_positive.json")
        result = detect_source_and_parse(data, "maigret")
        self.assert_parse_result(result, 1, "maigret")
        self.assertEqual(result.accounts[0].site, "GitHub")

    def test_parse_maigret_no_results(self):
        data = {"GitHub": {"status": {"status": "Not Found"}}}
        result = detect_source_and_parse(data, "maigret")
        self.assert_parse_result(result, 0, "maigret")

    def test_parse_maigret_wrong_type(self):
        result = detect_source_and_parse([], "maigret")
        self.assert_parse_result(result, 0, "maigret", error=True)

    # --- parse — sherlock ---

    def test_parse_sherlock_with_fixture(self):
        data = self._load_fixture("sherlock_positive.json")
        result = detect_source_and_parse(data, "sherlock")
        self.assert_parse_result(result, 2, "sherlock")
        sites = {a.site for a in result.accounts}
        self.assertIn("GitHub", sites)

    def test_parse_sherlock_no_results(self):
        data = {"GitHub": {"status": "Not Found"}}
        result = detect_source_and_parse(data, "sherlock")
        self.assert_parse_result(result, 0, "sherlock")

    # --- parse — blackbird ---

    def test_parse_blackbird_with_fixture(self):
        data = self._load_fixture("blackbird_positive.json")
        result = detect_source_and_parse(data, "blackbird")
        self.assert_parse_result(result, 2, "blackbird")
        self.assertEqual(result.accounts[0].site, "Forum")

    def test_parse_blackbird_wrong_type(self):
        result = detect_source_and_parse({}, "blackbird")
        self.assert_parse_result(result, 0, "blackbird", error=True)

    # --- parse — naminter ---

    def test_parse_naminter_with_fixture(self):
        data = self._load_fixture("naminter_positive.json")
        result = detect_source_and_parse(data, "naminter")
        self.assert_parse_result(result, 1, "naminter")
        self.assertEqual(result.accounts[0].site, "Blog")

    # --- parse — enola ---

    def test_parse_enola_with_fixture(self):
        data = self._load_fixture("enola_positive.json")
        result = detect_source_and_parse(data, "enola")
        self.assert_parse_result(result, 1, "enola")
        self.assertEqual(result.accounts[0].site, "GitHub")

    def test_parse_enola_wrong_type(self):
        result = detect_source_and_parse({}, "enola")
        self.assert_parse_result(result, 0, "enola", error=True)

    # --- parse — vesper ---

    def test_parse_vesper_with_fixture(self):
        data = self._load_fixture("vesper_positive.json")
        result = detect_source_and_parse(data, "vesper")
        self.assert_parse_result(result, 1, "vesper")
        self.assertEqual(result.accounts[0].site, "GitHub")

    def test_parse_vesper_wrong_type(self):
        result = detect_source_and_parse([], "vesper")
        self.assert_parse_result(result, 0, "vesper", error=True)

    # --- payload-based fallback (generic filename) ---

    def test_parse_by_payload_when_filename_generic(self):
        data = [{"title": "GitHub", "url": "https://github.com/user", "found": True}]
        result = detect_source_and_parse(data, "")
        self.assert_parse_result(result, 1)

    def test_parse_by_payload_maigret_auto_detected(self):
        data = {"GitHub": {"status": {"status": "Claimed"}}}
        result = detect_source_and_parse(data, "")
        self.assert_parse_result(result, 1)

    def test_parse_by_payload_vesper_auto_detected(self):
        data = {"usernames": [{"username": "user", "results": [
            {"site": "GitHub", "link": "https://github.com/user", "exist": True},
        ]}]}
        result = detect_source_and_parse(data, "")
        self.assert_parse_result(result, 1)

    # --- parse — empty / edge cases ---

    def test_parse_empty_dict_returns_no_error(self):
        result = detect_source_and_parse({}, "")
        # Empty dict matches no parser — maigret iterates, finds nothing
        self.assert_parse_result(result, 0)

    def test_parse_malformed_json_returns_error(self):
        result = detect_source_and_parse("not a dict" , "")
        self.assert_parse_result(result, 0, error=True)

    # --- dedup ---

    def test_deduplicate_by_composite_key(self):
        a1 = Account(site="GitHub", url="https://github.com/user", username="user", source="maigret")
        a2 = Account(site="GitHub", url="https://github.com/user", username="user", source="sherlock")
        deduped = RiskAnalyzer.deduplicate([a1, a2])
        self.assertEqual(len(deduped), 1)
        self.assertIn("maigret", deduped[0].sources)
        self.assertIn("sherlock", deduped[0].sources)

    def test_deduplicate_url_normalization(self):
        a1 = Account(site="GitHub", url="https://github.com/user/", username="user")
        a2 = Account(site="GitHub", url="https://github.com/user", username="user")
        deduped = RiskAnalyzer.deduplicate([a1, a2])
        self.assertEqual(len(deduped), 1)

    def test_deduplicate_case_different_sites(self):
        a1 = Account(site="GitHub", url="https://github.com/A", username="A")
        a2 = Account(site="GitLab", url="https://gitlab.com/B", username="B")
        deduped = RiskAnalyzer.deduplicate([a1, a2])
        self.assertEqual(len(deduped), 2)

    def test_deduplicate_order_independent(self):
        a1 = Account(site="X", url="https://x.com/u", username="u", source="maigret")
        a2 = Account(site="X", url="https://x.com/u", username="u", source="sherlock")
        forward = RiskAnalyzer.deduplicate([a1, a2])
        backward = RiskAnalyzer.deduplicate([a2, a1])
        self.assertEqual(len(forward), 1)
        self.assertEqual(len(backward), 1)
        self.assertEqual(set(forward[0].sources), set(backward[0].sources))

    # --- breach ---

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

    # --- cluster ---

    def test_cluster_groups_by_fullname(self):
        a1 = Account(site="GitHub", url="x", username="u", fullname="John Doe")
        a2 = Account(site="GitLab", url="y", username="u", fullname="John Doe")
        a3 = Account(site="Twitter", url="z", username="v")
        analyzer = RiskAnalyzer([a1, a2, a3])
        clusters = analyzer.cluster()
        self.assertIn("cluster_0", clusters)
        self.assertEqual(len(clusters["cluster_0"]), 2)
        self.assertIn("unclustered", clusters)
        self.assertEqual(len(clusters["unclustered"]), 1)


class NormalizeURLTests(unittest.TestCase):
    def test_trailing_slash_stripped(self):
        self.assertEqual(normalize_url("https://x.com/u/"), "https://x.com/u")

    def test_lowercases_scheme(self):
        self.assertEqual(normalize_url("HTTP://X.COM/U"), "http://x.com/U")

    def test_drops_fragment(self):
        self.assertEqual(normalize_url("https://x.com/u#ref"), "https://x.com/u")

    def test_empty_returns_empty(self):
        self.assertEqual(normalize_url(""), "")

    def test_none_returns_empty(self):
        self.assertEqual(normalize_url(None), "")


class CLITests(unittest.TestCase):
    def setUp(self):
        self.fixture_dir = Path(__file__).parent / "fixtures"

    def test_success_exits_0(self):
        r = subprocess.run(
            ["python3", "-m", "protection_report",
             str(self.fixture_dir / "maigret_positive.json"), "-q"],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0)

    def test_no_files_exits_1(self):
        r = subprocess.run(
            ["python3", "-m", "protection_report"],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 1)
        self.assertIn("No JSON files provided", r.stderr)

    def test_bad_json_exits_2(self):
        bad = Path("/tmp/_bad_parse.json")
        bad.write_text("{invalid json")
        try:
            r = subprocess.run(
                ["python3", "-m", "protection_report", str(bad), "-q"],
                capture_output=True, text=True,
            )
            self.assertEqual(r.returncode, 2)
        finally:
            bad.unlink()

    def test_output_dir_flag(self):
        outdir = Path("/tmp/_cli_test_out")
        r = subprocess.run(
            ["python3", "-m", "protection_report",
             str(self.fixture_dir / "maigret_positive.json"),
             "-o", str(outdir), "-q"],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0)
        self.assertTrue((outdir / "protection_maigret_positive.md").exists())

    def test_username_flag(self):
        r = subprocess.run(
            ["python3", "-m", "protection_report",
             str(self.fixture_dir / "maigret_positive.json"),
             "--username", "testuser", "-q"],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0)
        self.assertTrue(Path("/tmp/reports/protection_testuser.md").exists())

    def test_json_format(self):
        r = subprocess.run(
            ["python3", "-m", "protection_report",
             str(self.fixture_dir / "maigret_positive.json"),
             "--format", "json", "--stdout"],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0)
        data = json.loads(r.stdout)
        self.assertEqual(data["username"], "maigret_positive")
        self.assertEqual(len(data["accounts"]), 1)
        self.assertEqual(data["accounts"][0]["site"], "GitHub")

    def test_stdout_flag(self):
        r = subprocess.run(
            ["python3", "-m", "protection_report",
             str(self.fixture_dir / "maigret_positive.json"),
             "--stdout"],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("# 🛡 Relatório de Proteção", r.stdout)

    def test_quiet_suppresses_stdout(self):
        r = subprocess.run(
            ["python3", "-m", "protection_report",
             str(self.fixture_dir / "maigret_positive.json"), "-q"],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0)
        # stdout should be empty with --quiet
        self.assertEqual(r.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
