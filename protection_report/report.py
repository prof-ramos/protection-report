"""Risk analysis and report generation."""

import re
import html
import unicodedata
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional
from .models import Account, Cluster, Risk, BreachResult, Report


def normalize_name(name: str) -> str:
    """Normalize name: deaccent, strip punct, collapse whitespace."""
    if not name:
        return ""
    nfkd = unicodedata.normalize('NFKD', name)
    ascii_ = nfkd.encode('ascii', 'ignore').decode('ascii')
    cleaned = re.sub(r'[^\w\s]', '', ascii_)
    return cleaned.strip().lower()


# ponytail: single dict, caller overrides via RiskAnalyzer(risk_config={...})
SCORE_RULES = {
    "accounts_10plus": 3,
    "accounts_5to9": 2,
    "accounts_base": 1,
    "multiple_names": 2,
    "cluster_3plus": 2,
    "finance_tag": 1,
    "social_3plus": 1,
    # thresholds
    "high_threshold": 7,
    "medium_threshold": 4,
}


class RiskAnalyzer:
    """Analyzes accounts and generates risk assessment."""

    def __init__(self, accounts: List[Account], risk_config: Optional[dict] = None):
        self.accounts = accounts
        self.config = {**SCORE_RULES, **(risk_config or {})}
        self._breakdown: List[dict] = []
        self._score: Optional[int] = None

    def cluster(self) -> Dict[str, List[Account]]:
        """Group accounts by normalized fullname with basic fuzzy matching."""
        clusters = {}
        assigned = set()

        # Normalize all names once
        normed = []
        for i, acc in enumerate(self.accounts):
            n = normalize_name(acc.fullname)
            if n:
                # ponytail: sorted words and substring for basic fuzzy
                tokens = sorted(n.split())
                normed.append((i, acc, n, tokens))
            else:
                normed.append((i, acc, n, []))

        # Group by exact normalized match first
        groups = []
        used = set()
        for i, acc, n, tokens in normed:
            if not n or i in used:
                continue
            group = [i]
            used.add(i)
            # Same normalized name
            for j, acc2, n2, tokens2 in normed:
                if j not in used and n == n2:
                    group.append(j)
                    used.add(j)
            # ponytail: also match if one token set is subset of the other
            for j, acc2, n2, tokens2 in normed:
                if j not in used and tokens and tokens2:
                    if set(tokens).issubset(set(tokens2)) or set(tokens2).issubset(set(tokens)):
                        group.append(j)
                        used.add(j)
            groups.append(group)

        for idx, group in enumerate(groups):
            label = f"cluster_{idx}"
            accounts_in = [self.accounts[i] for i in group]
            clusters[label] = accounts_in

        clusters["unclustered"] = [
            a for i, a in enumerate(self.accounts)
            if i not in {gi for g in groups for gi in g}
        ]
        return clusters

    def risk_score(self, clusters: Dict[str, List[Account]]) -> int:
        """Calculate risk score 0-10 using configured weights."""
        c = self.config
        self._breakdown = []
        score = 0
        total = len(self.accounts)

        # Account count tiers
        if total >= 10:
            score += c["accounts_10plus"]
            self._breakdown.append({"rule": "accounts_10plus", "points": c["accounts_10plus"], "evidence": f"{total} contas"})
        elif total >= 5:
            score += c["accounts_5to9"]
            self._breakdown.append({"rule": "accounts_5to9", "points": c["accounts_5to9"], "evidence": f"{total} contas"})
        else:
            score += c["accounts_base"]
            self._breakdown.append({"rule": "accounts_base", "points": c["accounts_base"], "evidence": f"{total} contas"})

        # Multiple distinct names
        names = {normalize_name(a.fullname) for a in self.accounts if len(normalize_name(a.fullname)) > 1}
        if len(names) > 1:
            score += c["multiple_names"]
            self._breakdown.append({"rule": "multiple_names", "points": c["multiple_names"], "evidence": f"{len(names)} nomes distintos"})

        # Cluster size
        for cid, accs in clusters.items():
            if cid != "unclustered" and len(accs) >= 3:
                score += c["cluster_3plus"]
                self._breakdown.append({"rule": "cluster_3plus", "points": c["cluster_3plus"], "evidence": f"{cid}: {len(accs)} contas"})

        # Tags
        if any("finance" in a.tags or "fintech" in a.tags for a in self.accounts):
            score += c["finance_tag"]
            self._breakdown.append({"rule": "finance_tag", "points": c["finance_tag"], "evidence": "contas financeiras"})
        if sum(1 for a in self.accounts if "social" in a.tags) >= 3:
            score += c["social_3plus"]
            self._breakdown.append({"rule": "social_3plus", "points": c["social_3plus"], "evidence": "3+ contas sociais"})

        self._score = min(score, 10)
        return self._score

    @property
    def score_breakdown(self) -> List[dict]:
        """Return score breakdown after risk_score() was called."""
        return self._breakdown

    def identify_risks(self, clusters: Dict[str, List[Account]]) -> List[Risk]:
        """Identify all risks with categories and confidence."""
        risks = []

        # ponytail: name exposure is informational, not critical
        names = {a.fullname.strip() for a in self.accounts if len(a.fullname.strip()) > 3}
        if names:
            risks.append(Risk(
                severity="HIGH",
                title="Nome real publicamente disponível",
                description=f"Nome(s): {', '.join(list(names)[:3])}",
                affected=[a.site for a in self.accounts if a.fullname.strip()],
                category="informational",
                confidence="confirmed",
            ))

        # Financial accounts
        fin = [a for a in self.accounts if any(t in {"finance", "fintech", "business"} for t in a.tags)]
        if fin:
            risks.append(Risk(
                severity="HIGH",
                title="Contas financeiras expostas",
                description=f"{len(fin)} contas com dados financeiros",
                affected=[a.site for a in fin],
                category="actionable",
                confidence="confirmed",
            ))

        # Linked accounts (clusters)
        for cid, accs in clusters.items():
            if cid != "unclustered" and len(accs) >= 3:
                risks.append(Risk(
                    severity="MEDIUM",
                    title=f"Contas vinculadas ({len(accs)} plataformas)",
                    description="Dados coincidentes fundem contas em perfil único",
                    affected=[a.site for a in accs],
                    category="actionable",
                    confidence="high",
                ))

        return risks

    @staticmethod
    def recommendations(risks: List[Risk]) -> List[str]:
        """Generate prioritized recommendations."""
        recs = set()
        for r in risks:
            if r.severity == "CRITICAL":
                recs.add("Remover dados sensíveis imediatamente")
            elif r.severity == "HIGH" and r.category == "actionable":
                recs.add("Verificar privacidade em contas financeiras")
            elif r.severity == "MEDIUM":
                recs.add("Revisar dados públicos em contas vinculadas")
        if any(r.category == "informational" for r in risks):
            recs.add("Remover nome real de perfis onde não é necessário")
        recs.add("Verificar e-mail em vazamentos (XposedOrNot)")
        recs.add("Usar pseudônimos em plataformas de entretenimento")
        return list(recs)

    @staticmethod
    def deduplicate(accounts: List[Account]) -> List[Account]:
        """Remove duplicates by composite dedup_key, merging sources."""
        seen = {}
        for a in accounts:
            key = a.dedup_key
            if key in seen:
                existing = seen[key]
                for s in a.sources:
                    if s not in existing.sources:
                        existing.sources.append(s)
                existing.tags = list(set(existing.tags + a.tags))
                continue
            seen[key] = a
        return list(seen.values())


def generate_report(
    username: str,
    accounts: List[Account],
    clusters: Dict[str, List[Account]],
    risks: List[Risk],
    recommendations: List[str],
    risk_score: int,
    source_count: Dict[str, int],
    breach_data: Optional[BreachResult] = None,
    score_breakdown: Optional[List[dict]] = None,
) -> str:
    """Generate a complete protection report in markdown."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    level = (
        "Alto" if risk_score >= 7 else
        "Moderado" if risk_score >= 4 else
        "Baixo"
    )

    r = f"# 🛡 Relatório de Proteção: {username}\n\n"
    r += f"**Data:** {now}\n"
    r += f"**Contas encontradas:** {len(accounts)}\n"
    r += f"**Nível de risco:** {risk_score}/10 ({level})\n"
    r += f"**Modelo de risco:** v0.5.0\n"

    if source_count:
        r += "**Fontes:** " + " | ".join(f"{k}: {v}" for k, v in source_count.items()) + "\n"

    # Score breakdown
    if score_breakdown:
        r += "\n**Decomposição do score:**\n"
        for b in score_breakdown:
            r += f"- {b['rule']}: +{b['points']} ({b['evidence']})\n"

    # Risks
    r += "\n---\n\n## 🔴 Riscos Identificados\n\n"
    for risk in risks:
        emoji = {"CRITICAL": "🔴", "HIGH": "🟡", "MEDIUM": "🟠", "LOW": "⚪", "INFO": "ℹ️"}.get(risk.severity, "⚪")
        r += f"### {emoji} {risk.severity} — {risk.title}\n{risk.description}\n"
        r += f"**Categoria:** {risk.category} | **Confiança:** {risk.confidence}\n"
        r += f"Afetados: {', '.join(risk.affected[:5])}\n\n"

    # Clusters
    r += "---\n## 📊 Análise de Clusters\n\n"
    for cid, accs in clusters.items():
        if cid == "unclustered":
            continue
        r += f"### {cid} ({len(accs)} contas)\n"
        for a in accs:
            r += f"- {a.site}: {a.fullname or 'N/A'}\n"
        r += "\n"

    unclustered = clusters.get("unclustered", [])
    if unclustered and len(unclustered) <= 10:
        r += f"### Sem cluster ({len(unclustered)} contas)\n"
        for a in unclustered:
            r += f"- {a.site}\n"
        r += "\n"

    # Recommendations
    r += "---\n## 🛡 Recomendações\n\n"
    for i, rec in enumerate(recommendations, 1):
        r += f"{i}. {rec}\n"
    r += "\n"

    # Breach data
    if breach_data and breach_data.found:
        r += "---\n## 🔴 Vazamentos de Dados\n\n"
        r += f"**E-mail em {breach_data.count} vazamentos** (score: {breach_data.risk_score}/100)\n\n"
        r += "**Top:**\n"
        for b in breach_data.breaches[:10]:
            r += f"- {b}\n"
        r += "\n"
    elif breach_data and breach_data.error:
        r += "---\n## ⚠️ Consulta de Vazamentos Inconclusiva\n\n"
        r += f"Não foi possível confirmar a ausência de vazamentos: {breach_data.error}\n\n"

    # Account inventory
    r += "---\n## 📋 Contas Encontradas\n\n"
    for a in accounts:
        r += f"### {a.site}\n- **URL:** {a.url}\n- **User:** {a.username}\n"
        if a.fullname:
            r += f"- **Nome:** {a.fullname}\n"
        if a.bio:
            r += f"- **Bio:** {a.bio[:100]}...\n"
        r += f"- **Tags:** {', '.join(a.tags)}\n\n"

    r += "---\n*Gerado automaticamente de dados públicos.*\n"
    return r


def generate_html(
    username: str,
    accounts: List[Account],
    clusters: Dict[str, List[Account]],
    risks: List[Risk],
    recommendations: List[str],
    risk_score: int,
    source_count: Dict[str, int],
    breach_data: Optional[BreachResult] = None,
    score_breakdown: Optional[List[dict]] = None,
    redact: bool = False,
) -> str:
    """Generate a self-contained HTML report. Escapes all user content."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    level = "Alto" if risk_score >= 7 else "Moderado" if risk_score >= 4 else "Baixo"
    severity_colors = {"CRITICAL": "#dc2626", "HIGH": "#f59e0b", "MEDIUM": "#f97316",
                       "LOW": "#9ca3af", "INFO": "#3b82f6"}

    def esc(s):
        return html.escape(str(s)) if s else ""

    parts = [
        "<!DOCTYPE html><html lang='pt-BR'><head><meta charset='UTF-8'>",
        f"<title>Proteção: {esc(username)}</title>",
        "<style>body{font-family:system-ui,sans-serif;max-width:800px;margin:0 auto;padding:2rem;line-height:1.6}",
        "table{border-collapse:collapse;width:100%;margin:1rem 0}",
        "th,td{border:1px solid #e5e7eb;padding:.5rem;text-align:left}",
        "th{background:#f9fafb} .tag{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.75rem;margin:2px}",
        ".critical{color:#dc2626}.high{color:#f59e0b}.medium{color:#f97316}.low{color:#9ca3af}",
        "</style></head><body>",
        f"<h1>🛡 Relatório de Proteção: {esc(username)}</h1>",
        f"<p><strong>Data:</strong> {now}</p>",
        f"<p><strong>Contas:</strong> {len(accounts)}</p>",
        f"<p><strong>Risco:</strong> {risk_score}/10 ({level})</p>",
        f"<p><strong>Versão:</strong> 0.6.0</p>",
    ]

    # Score breakdown
    if score_breakdown:
        parts.append("<h2>Decomposição do Score</h2><ul>")
        for b in score_breakdown:
            parts.append(f"<li><strong>{esc(b['rule'])}</strong>: +{b['points']} — {esc(b['evidence'])}</li>")
        parts.append("</ul>")

    # Risks
    parts.append("<h2>Riscos Identificados</h2>")
    for risk in risks:
        cls = risk.severity.lower()
        parts.append(f"<div class='risk {cls}'>")
        parts.append(f"<h3><span class='tag {cls}'>{esc(risk.severity)}</span> {esc(risk.title)}</h3>")
        parts.append(f"<p>{esc(risk.description)}</p>")
        parts.append(f"<p><em>{esc(risk.category)} · {esc(risk.confidence)}</em></p>")
        parts.append(f"<p>Afetados: {', '.join(esc(a) for a in risk.affected[:5])}</p></div>")

    # Clusters
    parts.append("<h2>Clusters</h2>")
    for cid, accs in clusters.items():
        if cid == "unclustered":
            continue
        parts.append(f"<h3>{esc(cid)} ({len(accs)} contas)</h3><ul>")
        for a in accs:
            parts.append(f"<li>{esc(a.site)}: {esc(a.fullname) or 'N/A'}</li>")
        parts.append("</ul>")

    # Breach
    if breach_data and breach_data.found:
        parts.append(f"<h2>Vazamentos</h2><p>{esc(breach_data.count)} vazamentos (score {breach_data.risk_score}/100)</p>")

    # Account table
    parts.append("<h2>Contas</h2><table><tr><th>Site</th><th>URL</th><th>User</th><th>Nome</th></tr>")
    for a in accounts:
        u = esc(a.url) if not redact else "[REDACTED]"
        un = esc(a.username) if not redact else esc(a.username[0]) + "***"
        fn = esc(a.fullname) if not redact else esc(a.fullname[0]) + ". ***" if a.fullname else ""
        parts.append(f"<tr><td>{esc(a.site)}</td><td>{u}</td><td>{un}</td><td>{fn}</td></tr>")
    parts.append("</table>")

    parts.append("<hr><p><em>Gerado automaticamente de dados públicos.</em></p>")
    parts.append("</body></html>")
    return "\n".join(parts)
