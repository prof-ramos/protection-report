"""Format-specific parsers for each OSINT tool JSON output."""

from typing import Dict, List, Any
from .models import Account


def parse_maigret_json(data: Dict) -> List[Account]:
    """Parse Maigret JSON output.

    Format:
    {
      "SiteName": {
        "status": { "status": "Claimed", "ids": { ... } }
      }
    }
    """
    accounts = []
    for site_name, site_data in data.items():
        if not isinstance(site_data, dict) or "status" not in site_data:
            continue
        s = site_data["status"]
        if s.get("status") != "Claimed":
            continue
        ids = s.get("ids", {})
        accounts.append(Account(
            site=site_name,
            url=s.get("url", ""),
            username=s.get("username", ""),
            fullname=ids.get("fullname", ""),
            bio=ids.get("bio", ""),
            image=ids.get("image", ""),
            created_at=str(ids.get("created_at", "")),
            tags=s.get("tags", []),
            ids=ids,
            source="maigret",
        ))
    return accounts


def parse_sherlock_json(data: Dict) -> List[Account]:
    """Parse Sherlock JSON output.

    Format:
    {
      "SiteName": { "url_user": "...", "status": "..." }
    }
    """
    accounts = []
    for site_name, site_data in data.items():
        if not isinstance(site_data, dict):
            continue
        status = site_data.get("status")
        if status not in ("Claimed", "Detected"):
            continue
        accounts.append(Account(
            site=site_name,
            url=site_data.get("url_user", ""),
            username=site_data.get("username", ""),
            tags=site_data.get("tags", []),
            source="sherlock",
        ))
    return accounts


def parse_blackbird_json(data: Dict) -> List[Account]:
    """Parse Blackbird JSON output."""
    accounts = []
    for entry in data if isinstance(data, list) else [data]:
        if isinstance(entry, dict):
            accounts.append(Account(
                site=entry.get("site", ""),
                url=entry.get("url", ""),
                username=entry.get("username", ""),
                fullname=entry.get("fullname", ""),
                source="blackbird",
            ))
    return accounts


def parse_naminter_json(data: Dict) -> List[Account]:
    """Parse Naminter JSON output."""
    accounts = []
    for site_name, fields in data.items() if isinstance(data, dict) else []:
        if isinstance(fields, dict) and fields.get("status") == "Claimed":
            accounts.append(Account(
                site=site_name,
                url=fields.get("url", ""),
                username=fields.get("username", ""),
                source="naminter",
            ))
    return accounts


PARSERS = {
    "maigret": parse_maigret_json,
    "sherlock": parse_sherlock_json,
    "blackbird": parse_blackbird_json,
    "naminter": parse_naminter_json,
}


def detect_source_from_filename(filename: str) -> str:
    """Detect source tool from filename patterns."""
    name = filename.lower()
    if "maigret" in name or name.startswith("report_") or "_simple" in name:
        return "maigret"
    if "sherlock" in name:
        return "sherlock"
    if "blackbird" in name:
        return "blackbird"
    if "naminter" in name:
        return "naminter"
    return "unknown"


def detect_source_and_parse(data: Dict, source_hint: str = "") -> List[Account]:
    """Auto-detect format and parse accordingly."""
    # Try each parser, return first that yields results
    for name, parser in PARSERS.items():
        if source_hint and name != source_hint:
            continue
        try:
            result = parser(data)
            if result:
                return result
        except Exception:
            continue
    return []
