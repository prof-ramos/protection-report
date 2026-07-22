"""Data models for protection report system."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional


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

    @property
    def unique_key(self) -> str:
        """Deduplication key."""
        return self.url or self.site


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
