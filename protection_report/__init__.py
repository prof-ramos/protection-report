"""Protection Report Generator — multi-source account exposure analysis."""

VERSION = "1.0.0"

from .models import Account, Cluster, Risk, BreachResult, Report, ParseResult, normalize_url
from .breach import check_breach
from .parsers import (
    parse_maigret_json,
    parse_sherlock_json,
    parse_blackbird_json,
    parse_naminter_json,
    parse_enola_json,
    parse_vesper_json,
    detect_source_and_parse,
    detect_source_from_filename,
    ParserError,
    ParserFormatError,
    ParserInternalError,
    register_parser,
    get_parser,
    list_parsers,
    ParserMeta,
)
from .report import generate_report, generate_html, RiskAnalyzer
