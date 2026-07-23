#!/usr/bin/env python3
"""Protection Report Generator CLI.

Usage:
    protection-report <files...> [--email EMAIL] [--username NAME]
                                  [--output-dir DIR] [--format md|json]
                                  [--stdout] [--quiet]

Exit codes:
    0  Report generated (may include warnings)
    1  Usage error (no files, bad args)
    2  Parse error in one or more files (report still generated)
    3  No accounts found after parsing
"""

import argparse
import json
import sys
import tempfile
from pathlib import Path

from protection_report.models import Risk
from protection_report.breach import check_breach
from protection_report.parsers import detect_source_and_parse, detect_source_from_filename
from protection_report.report import RiskAnalyzer, generate_report


def safe_report_name(value: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in value).strip("._") or "unknown"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="protection-report",
        description="Generate OSINT identity exposure reports from JSON files.",
    )
    p.add_argument("files", nargs="*", metavar="FILE", help="JSON files from OSINT tools")
    p.add_argument("--email", help="Check email against XposedOrNot breach DB")
    p.add_argument("--username", help="Username label for the report (auto-detected if omitted)")
    p.add_argument("--output-dir", "-o", default=None,
                   help="Output directory (default: system temp dir + reports)")
    p.add_argument("--format", "-f", choices=["md", "json"], default="md",
                   help="Output format (default: md)")
    p.add_argument("--stdout", action="store_true",
                   help="Print report to stdout instead of writing file")
    p.add_argument("--quiet", "-q", action="store_true",
                   help="Suppress stdout report, write file only")
    return p


def main() -> int:
    args = build_parser().parse_args()

    # Discover JSON files
    json_paths = list(args.files)
    username = args.username

    if not json_paths and username:
        name = safe_report_name(username)
        p = Path(tempfile.gettempdir()) / "reports" / f"report_{name}_simple.json"
        if p.exists():
            json_paths.append(str(p))

    if not json_paths:
        print("No JSON files provided. Use --help for usage.", file=sys.stderr)
        return 1

    if not username:
        username = Path(json_paths[0]).stem.replace("report_", "").replace("_simple", "")
    username = safe_report_name(username)

    # Parse
    all_accounts = []
    source_count = {}
    parse_errors = []

    for jp in json_paths:
        try:
            data = json.loads(Path(jp).read_text())
        except (json.JSONDecodeError, OSError) as e:
            parse_errors.append((str(jp), str(e)))
            source_count[Path(jp).stem] = 0
            continue

        source_hint = detect_source_from_filename(Path(jp).name)
        result = detect_source_and_parse(data, source_hint=source_hint)

        label = Path(jp).stem
        if result.error:
            parse_errors.append((str(jp), result.error))
            source_count[label] = 0
        else:
            all_accounts.extend(result.accounts)
            source_count[label] = len(result.accounts)

    for path, err in parse_errors:
        print(f"⚠️  {path}: {err}", file=sys.stderr)

    accounts = RiskAnalyzer.deduplicate(all_accounts)
    analyzer = RiskAnalyzer(accounts)

    total_raw = sum(source_count.values())
    sources_str = " | ".join(f"{k}: {v}" for k, v in source_count.items())
    print(f"📡 Fontes: {sources_str}", file=sys.stderr)
    print(f"📊 Total: {len(accounts)} contas únicas (de {total_raw} brutas)", file=sys.stderr)

    clusters = analyzer.cluster()
    risk_score = analyzer.risk_score(clusters)
    risks = analyzer.identify_risks(clusters)

    breach_data = None
    if args.email:
        print(f"🔍 Verificando vazamentos para {args.email}...", file=sys.stderr)
        breach_data = check_breach(args.email)
        if breach_data.found:
            print(f"⚠️  Encontrado em {breach_data.count} vazamentos!", file=sys.stderr)
            risks.append(Risk(
                severity="CRITICAL",
                title=f"E-mail em {breach_data.count} vazamentos",
                description=f"Top: {', '.join(breach_data.breaches[:5])}",
                affected=breach_data.breaches,
            ))
            risk_score = 10
        else:
            if breach_data.error:
                print(f"⚠️  Consulta de vazamentos inconclusiva: {breach_data.error}", file=sys.stderr)
            else:
                print("✅ Nenhum vazamento encontrado", file=sys.stderr)

    recommendations = analyzer.recommendations(risks)

    # Generate output
    if args.format == "json":
        output = json.dumps({
            "username": username,
            "accounts": [
                {
                    "site": a.site, "url": a.url, "username": a.username,
                    "fullname": a.fullname, "bio": a.bio, "source": a.source,
                    "sources": a.sources,
                }
                for a in accounts
            ],
            "clusters": [
                {"label": label, "accounts": [a.site for a in accts]}
                for label, accts in clusters.items()
            ],
            "risks": [
                {"severity": r.severity, "title": r.title,
                 "description": r.description, "affected": r.affected}
                for r in risks
            ],
            "risk_score": risk_score,
            "source_count": source_count,
            "breaches": {
                "found": breach_data.found,
                "count": breach_data.count,
                "top": breach_data.breaches[:10],
            } if breach_data else None,
        }, ensure_ascii=False, indent=2)
    else:
        output = generate_report(
            username, accounts, clusters, risks, recommendations,
            risk_score, source_count, breach_data,
        )

    # Write or print
    if args.stdout:
        print(output)
    else:
        out_dir = Path(args.output_dir) if args.output_dir else Path(tempfile.gettempdir()) / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        ext = ".json" if args.format == "json" else ".md"
        out = out_dir / f"protection_{username}{ext}"
        out.write_text(output)
        if not args.quiet:
            print(f"✅ Report: {out}", file=sys.stderr)
            if args.format == "md":
                print("\n" + "=" * 60, file=sys.stderr)
                print(output, file=sys.stderr)

    if parse_errors and not all_accounts:
        return 2
    if not all_accounts and not parse_errors:
        return 3
    if parse_errors:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
