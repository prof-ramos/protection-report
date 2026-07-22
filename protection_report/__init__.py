"""Protection Report Generator — multi-source account exposure analysis."""

VERSION = "0.2.0"

from .models import Account, Cluster, Risk, BreachResult, Report
from .breach import check_breach
from .parsers import (
    parse_maigret_json,
    parse_sherlock_json,
    parse_blackbird_json,
    parse_naminter_json,
    detect_source_and_parse,
    detect_source_from_filename,
)
from .report import generate_report, RiskAnalyzer
