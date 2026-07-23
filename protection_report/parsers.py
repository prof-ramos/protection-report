"""Format-specific parsers for each OSINT tool JSON output."""

from typing import Dict, List, Any
from .models import Account, ParseResult


class ParserError(Exception):
    """Base parser error."""


class ParserFormatError(ParserError):
    """Payload doesn't match the expected format for this parser."""


class ParserInternalError(ParserError):
    """Unexpected error during parsing."""


def parse_maigret_json(data: Dict) -> List[Account]:
    """Parse Maigret JSON output.

    Format:
    {
      "SiteName": {
        "status": { "status": "Claimed", "ids": { ... } }
      }
    }
    """
    if not isinstance(data, dict):
        raise ParserFormatError("maigret expects a dict, got %s" % type(data).__name__)
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
    if not isinstance(data, dict):
        raise ParserFormatError("sherlock expects a dict, got %s" % type(data).__name__)
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


def parse_blackbird_json(data: Any) -> List[Account]:
    """Parse Blackbird JSON output."""
    if not isinstance(data, list):
        raise ParserFormatError("blackbird expects a list, got %s" % type(data).__name__)
    accounts = []
    for entry in data:
        if not isinstance(entry, dict) or not entry.get("site") or not (entry.get("url") or entry.get("username")):
            continue
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
    if not isinstance(data, dict):
        raise ParserFormatError("naminter expects a dict, got %s" % type(data).__name__)
    accounts = []
    for site_name, fields in data.items():
        if isinstance(fields, dict) and fields.get("status") == "Claimed":
            accounts.append(Account(
                site=site_name,
                url=fields.get("url", ""),
                username=fields.get("username", ""),
                source="naminter",
            ))
    return accounts


def parse_enola_json(data: Any) -> List[Account]:
    """Parse Enola's list of site results."""
    if not isinstance(data, list):
        raise ParserFormatError("enola expects a list, got %s" % type(data).__name__)
    return [Account(
        site=str(entry.get("title", "")),
        url=str(entry.get("url", "")),
        username="",
        source="enola",
    ) for entry in data if isinstance(entry, dict) and entry.get("found") is True and entry.get("url")]


def parse_vesper_json(data: Any) -> List[Account]:
    """Parse Vesper's nested JSON report, keeping only positive results."""
    if not isinstance(data, dict):
        raise ParserFormatError("vesper expects a dict, got %s" % type(data).__name__)
    accounts = []
    for scan in data.get("usernames", []):
        if not isinstance(scan, dict):
            continue
        username = str(scan.get("username", ""))
        for result in scan.get("results", []):
            if not isinstance(result, dict) or result.get("exist") is not True or not result.get("link"):
                continue
            accounts.append(Account(
                site=str(result.get("site", "")),
                url=str(result["link"]),
                username=username,
                source="vesper",
            ))
    return accounts


PARSERS = {
    "maigret": parse_maigret_json,
    "sherlock": parse_sherlock_json,
    "enola": parse_enola_json,
    "blackbird": parse_blackbird_json,
    "naminter": parse_naminter_json,
    "vesper": parse_vesper_json,
}


def detect_source_from_filename(filename: str) -> str:
    """Detect source tool from filename patterns."""
    name = filename.lower()
    if "enola" in name:
        return "enola"
    if "vesper" in name:
        return "vesper"
    if "maigret" in name or name.startswith("report_") or "_simple" in name:
        return "maigret"
    if "sherlock" in name:
        return "sherlock"
    if "blackbird" in name:
        return "blackbird"
    if "naminter" in name:
        return "naminter"
    return "unknown"


def detect_source_and_parse(data: Dict, source_hint: str = "") -> ParseResult:
    """Auto-detect format and parse accordingly.

    Returns a ParseResult with accounts, parser used, and optional error.
    """
    if source_hint == "unknown":
        source_hint = ""

    errors = []
    last_good_parser = None

    for name, parser in PARSERS.items():
        if source_hint and name != source_hint:
            continue
        try:
            result = parser(data)
        except ParserFormatError:
            if source_hint:
                return ParseResult(
                    source=source_hint,
                    parser_used=name,
                    accounts=[],
                    error="Payload format not recognized by %s parser" % name,
                )
            errors.append("%s: format mismatch" % name)
            continue
        except ParserError:
            errors.append("%s: internal error" % name)
            continue
        except Exception as e:
            errors.append("%s: %s" % (name, e))
            continue

        last_good_parser = name

        # Explicit source: return immediately even if empty
        if source_hint:
            return ParseResult(source=source_hint, parser_used=name, accounts=result)

        # Auto-detect: only return non-empty
        if result:
            return ParseResult(source=name, parser_used=name, accounts=result)

    # Nothing found
    if last_good_parser:
        return ParseResult(
            source=source_hint or last_good_parser,
            parser_used=last_good_parser,
            accounts=[],
        )

    return ParseResult(
        source=source_hint or "unknown",
        parser_used=source_hint or errors[0].split(":")[0] if errors else "none",
        accounts=[],
        error="; ".join(errors) if errors else "No parser matched payload",
    )
