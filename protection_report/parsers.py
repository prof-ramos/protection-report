"""Format-specific parsers for each OSINT tool JSON output."""

from typing import Dict, List, Any, Callable, Optional
from .models import Account, ParseResult


class ParserError(Exception):
    """Base parser error."""


class ParserFormatError(ParserError):
    """Payload doesn't match the expected format for this parser."""


class ParserInternalError(ParserError):
    """Unexpected error during parsing."""


# ponytail: metadata on each parser function, no Protocol class needed
class ParserMeta:
    """Minimal metadata for a registered parser."""
    def __init__(self, name: str, parse_fn: Callable, version: str = "0.1.0",
                 priority: int = 0, formats: Optional[List[str]] = None):
        self.name = name
        self.parse_fn = parse_fn
        self.version = version
        self.priority = priority
        self.formats = formats or []

    def parse(self, data: Any) -> List[Account]:
        return self.parse_fn(data)

    def matches_filename(self, filename: str) -> bool:
        """Check if filename hints at this parser. Override per parser."""
        return False


# ── Registry ──────────────────────────────────────────────────────────

_registry: Dict[str, ParserMeta] = {}


def register_parser(meta: ParserMeta) -> None:
    _registry[meta.name] = meta


def get_parser(name: str) -> Optional[ParserMeta]:
    return _registry.get(name)


def list_parsers() -> List[ParserMeta]:
    return list(_registry.values())


# ── Parsers ───────────────────────────────────────────────────────────

def _parse_maigret(data: Dict) -> List[Account]:
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


def _parse_sherlock(data: Dict) -> List[Account]:
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


def _parse_blackbird(data: Any) -> List[Account]:
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


def _parse_naminter(data: Dict) -> List[Account]:
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


def _parse_enola(data: Any) -> List[Account]:
    if not isinstance(data, list):
        raise ParserFormatError("enola expects a list, got %s" % type(data).__name__)
    return [Account(
        site=str(entry.get("title", "")),
        url=str(entry.get("url", "")),
        username="",
        source="enola",
    ) for entry in data if isinstance(entry, dict) and entry.get("found") is True and entry.get("url")]


def _parse_vesper(data: Any) -> List[Account]:
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


# ── Register builtins ─────────────────────────────────────────────────

register_parser(ParserMeta("maigret", _parse_maigret, "0.1.0", priority=10,
    formats=["maigret_json"]))
register_parser(ParserMeta("sherlock", _parse_sherlock, "0.1.0", priority=10,
    formats=["sherlock_json"]))
register_parser(ParserMeta("blackbird", _parse_blackbird, "0.1.0", priority=10,
    formats=["blackbird_json"]))
register_parser(ParserMeta("naminter", _parse_naminter, "0.1.0", priority=10,
    formats=["naminter_json"]))
register_parser(ParserMeta("enola", _parse_enola, "0.1.0", priority=10,
    formats=["enola_json"]))
register_parser(ParserMeta("vesper", _parse_vesper, "0.1.0", priority=10,
    formats=["vesper_json"]))

# Backward-compat aliases — tests and external code import these directly
parse_maigret_json = _parse_maigret
parse_sherlock_json = _parse_sherlock
parse_blackbird_json = _parse_blackbird
parse_naminter_json = _parse_naminter
parse_enola_json = _parse_enola
parse_vesper_json = _parse_vesper


# ── Filename detection ────────────────────────────────────────────────

def detect_source_from_filename(filename: str) -> str:
    name = filename.lower()
    for name_key in ("enola", "vesper", "maigret", "sherlock", "blackbird", "naminter"):
        if name_key in name or (name_key == "maigret" and (name.startswith("report_") or "_simple" in name)):
            return name_key
    return "unknown"


# ── Auto-detect + parse ───────────────────────────────────────────────

def detect_source_and_parse(data: Dict, source_hint: str = "") -> ParseResult:
    if source_hint == "unknown":
        source_hint = ""

    # Sort by priority (descending)
    parsers = sorted(_registry.values(), key=lambda p: -p.priority)

    errors = []
    last_good_parser = None

    for pm in parsers:
        if source_hint and pm.name != source_hint:
            continue
        try:
            result = pm.parse(data)
        except ParserFormatError:
            if source_hint:
                return ParseResult(
                    source=source_hint,
                    parser_used=pm.name,
                    accounts=[],
                    error="Payload format not recognized by %s parser" % pm.name,
                )
            errors.append("%s: format mismatch" % pm.name)
            continue
        except ParserError:
            errors.append("%s: internal error" % pm.name)
            continue
        except Exception as e:
            errors.append("%s: %s" % (pm.name, e))
            continue

        last_good_parser = pm.name

        if source_hint:
            return ParseResult(source=source_hint, parser_used=pm.name, accounts=result)
        if result:
            return ParseResult(source=pm.name, parser_used=pm.name, accounts=result)

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
