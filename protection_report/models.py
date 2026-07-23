"""Data models for protection report system."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlunparse


def normalize_url(url: str) -> str:
    """Normalize URL for dedup comparison.

    Strips trailing slash, lowercases scheme+netloc, drops fragments.
    Returns empty string for falsy input.
    """
    if not url:
        return ""
    parsed = urlparse(url)
    return urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path.rstrip("/") or "/",
        parsed.params,
        parsed.query,
        "",  # drop fragment
    ))


@dataclass
class Account:
    """A discovered account on a platform."""
    site: str
    url: str
    username: str
    fullname: str = ""
    bio: str = ""
    image: str = ""
    created_at: str = ""
    tags: List[str] = field(default_factory=list)
    ids: Dict[str, str] = field(default_factory=dict)
    source: str = ""
    sources: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Auto-populate sources from source if empty."""
        if not self.sources and self.source:
            self.sources = [self.source]

    @property
    def dedup_key(self) -> tuple:
        """Composite key: canonical URL, site, username, all lowercased."""
        return (
            normalize_url(self.url),
            self.site.lower().strip(),
            self.username.lower().strip(),
        )

    @property
    def unique_key(self) -> str:
        """Legacy dedup key — kept for backward compat."""
        return self.url or self.site


@dataclass
class ParseResult:
    """Result of parsing a single OSINT tool JSON file."""
    source: str
    parser_used: str
    accounts: List[Account]
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class Cluster:
    """Group of accounts sharing identity data."""
    name: str
    accounts: List[Account]
    primary: bool = False

    @property
    def size(self) -> int:
        return len(self.accounts)

    @property
    def site_names(self) -> List[str]:
        return [a.site for a in self.accounts]


@dataclass
class Risk:
    """Identified risk/vulnerability."""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    affected: List[str] = field(default_factory=list)


@dataclass
class BreachResult:
    """Result from breach database check."""
    found: bool = False
    count: int = 0
    breaches: List[str] = field(default_factory=list)
    risk_score: int = 0
    error: Optional[str] = None


@dataclass
class Report:
    """Complete protection report."""
    username: str
    accounts: List[Account]
    clusters: Dict[str, List[Account]]
    risks: List[Risk]
    recommendations: List[str]
    risk_score: int
    source_count: Dict[str, int]
    breach_data: Optional[BreachResult] = None
    generated_at: str = ""
