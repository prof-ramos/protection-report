#!/usr/bin/env python3
"""Protection Report Generator CLI entrypoint.

Usage:
    protection_report.py <maigret_json> [--email <email>]
    protection_report.py --username <username> [--email <email>]
    protection_report.py --merge <f1.json> <f2.json> [--email <email>]
"""

import sys
import json
from pathlib import Path

from protection_report.models import Account, Risk
from protection_report.breach import check_breach
from protection_report.parsers import detect_source_and_parse, detect_source_from_filename
from protection_report.report import RiskAnalyzer, generate_report


def safe_report_name(value: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in value).strip("._") or "unknown"


def load_json(path: str) -> dict:
    """Load and parse JSON file."""
    with open(path) as f:
        return json.load(f)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    email = None
    json_paths = []
    username = None

    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == "--email" and i + 1 < len(sys.argv):
            email = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--username" and i + 1 < len(sys.argv):
            username = sys.argv[i + 1]
            i += 2
        elif sys.argv[i].startswith("--"):
            i += 1
        else:
            json_paths.append(sys.argv[i])
            i += 1

    if not json_paths and username:
        username = safe_report_name(username)
        p = f"/tmp/reports/report_{username}_simple.json"
        if Path(p).exists():
            json_paths.append(p)

    if not json_paths:
        print("No JSON files provided.")
        sys.exit(1)

    if not username:
        username = Path(json_paths[0]).stem.replace("report_", "").replace("_simple", "")
    username = safe_report_name(username)

    # Parse all JSON files
    all_accounts = []
    source_count = {}
    for jp in json_paths:
        data = load_json(jp)
        source_hint = detect_source_from_filename(Path(jp).name)
        accs = detect_source_and_parse(data, source_hint=source_hint)
        all_accounts.extend(accs)
        source = Path(jp).stem.replace("report_", "").replace("_simple", "")
        source_count[source] = len(accs)

    # Deduplicate
    accounts = RiskAnalyzer.deduplicate(all_accounts)
    analyzer = RiskAnalyzer(accounts)

    print(f"📡 Fontes: {' | '.join(f'{k}: {v}' for k, v in source_count.items())}")
    print(f"📊 Total: {len(accounts)} contas únicas (de {len(all_accounts)} brutas)")

    # Analyze
    clusters = analyzer.cluster()
    risk_score = analyzer.risk_score(clusters)
    risks = analyzer.identify_risks(clusters)

    # Breach check
    breach_data = None
    if email:
        print(f"🔍 Verificando vazamentos para {email}...")
        breach_data = check_breach(email)
        if breach_data.found:
            print(f"⚠️  Encontrado em {breach_data.count} vazamentos!")
            risks.append(Risk(
                severity="CRITICAL",
                title=f"E-mail em {breach_data.count} vazamentos",
                description=f"Top: {', '.join(breach_data.breaches[:5])}",
                affected=breach_data.breaches,
            ))
            risk_score = 10
        else:
            print("✅ Nenhum vazamento encontrado")

    recommendations = analyzer.recommendations(risks)
    report = generate_report(
        username, accounts, clusters, risks, recommendations,
        risk_score, source_count, breach_data,
    )

    out = f"/tmp/reports/protection_{username}.md"
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        f.write(report)
    print(f"✅ Report: {out}")
    print("\n" + "=" * 60)
    print(report)


if __name__ == "__main__":
    main()
