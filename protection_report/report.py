"""Risk analysis and report generation."""

from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional
from .models import Account, Cluster, Risk, BreachResult, Report


class RiskAnalyzer:
    """Analyzes accounts and generates risk assessment."""

    def __init__(self, accounts: List[Account]):
        self.accounts = accounts

    def cluster(self) -> Dict[str, List[Account]]:
        """Group accounts by shared fullname similarity."""
        clusters = defaultdict(list)
        name_map = defaultdict(list)

        for acc in self.accounts:
            fn = acc.fullname.strip().lower()
            if fn:
                name_map[fn].append(acc)

        used = set()
        for i, (name, accs) in enumerate(name_map.items()):
            if name not in used:
                clusters[f"cluster_{i}"] = accs
                used.add(name)

        clusters["unclustered"] = [
            a for a in self.accounts if not a.fullname.strip()
        ]
        return dict(clusters)

    def risk_score(self, clusters: Dict[str, List[Account]]) -> int:
        """Calculate risk score 0-10."""
        score = 0
        total = len(self.accounts)

        if total >= 10: score += 3
        elif total >= 5: score += 2
        else: score += 1

        names = {a.fullname.strip().lower() for a in self.accounts if len(a.fullname.strip()) > 3}
        if len(names) > 1: score += 2

        for cid, accs in clusters.items():
            if cid != "unclustered" and len(accs) >= 3:
                score += 2

        if any("finance" in a.tags or "fintech" in a.tags for a in self.accounts):
            score += 1
        if sum(1 for a in self.accounts if "social" in a.tags) >= 3:
            score += 1

        return min(score, 10)

    def identify_risks(self, clusters: Dict[str, List[Account]]) -> List[Risk]:
        """Identify all risks from accounts and clusters."""
        risks = []

        # Name exposure
        names = {a.fullname.strip() for a in self.accounts if len(a.fullname.strip()) > 3}
        if names:
            risks.append(Risk(
                severity="CRITICAL",
                title="Nome real publicamente disponível",
                description=f"Nome(s): {', '.join(list(names)[:3])}",
                affected=[a.site for a in self.accounts if a.fullname.strip()],
            ))

        # Financial accounts
        fin = [a for a in self.accounts if any(t in {"finance", "fintech", "business"} for t in a.tags)]
        if fin:
            risks.append(Risk(
                severity="HIGH",
                title="Contas financeiras expostas",
                description=f"{len(fin)} contas com dados financeiros",
                affected=[a.site for a in fin],
            ))

        # Linked accounts
        for cid, accs in clusters.items():
            if cid != "unclustered" and len(accs) >= 3:
                risks.append(Risk(
                    severity="MEDIUM",
                    title=f"Contas vinculadas ({len(accs)} plataformas)",
                    description="Dados coincidentes fundem contas em perfil único",
                    affected=[a.site for a in accs],
                ))

        return risks

    @staticmethod
    def recommendations(risks: List[Risk]) -> List[str]:
        """Generate prioritized recommendations."""
        recs = set()
        for r in risks:
            if r.severity == "CRITICAL":
                recs.add("Remover nome real de perfis onde não é necessário")
            elif r.severity == "HIGH":
                recs.add("Verificar privacidade em contas financeiras")
            elif r.severity == "MEDIUM":
                recs.add("Revisar dados públicos em contas vinculadas")
        recs.add("Verificar e-mail em vazamentos (XposedOrNot)")
        recs.add("Usar pseudônimos em plataformas de entretenimento")
        return list(recs)

    @staticmethod
    def deduplicate(accounts: List[Account]) -> List[Account]:
        """Remove duplicate accounts by URL."""
        seen = set()
        result = []
        for a in accounts:
            if a.unique_key not in seen:
                seen.add(a.unique_key)
                result.append(a)
        return result


def generate_report(
    username: str,
    accounts: List[Account],
    clusters: Dict[str, List[Account]],
    risks: List[Risk],
    recommendations: List[str],
    risk_score: int,
    source_count: Dict[str, int],
    breach_data: Optional[BreachResult] = None,
) -> str:
    """Generate a complete protection report in markdown.

    Args:
        username: Target username.
        accounts: All discovered accounts.
        clusters: Clustered account groups.
        risks: Identified risks.
        recommendations: Generated recommendations.
        risk_score: Numerical risk score (0-10).
        source_count: Per-source account counts.
        breach_data: Optional breach check results.

    Returns:
        Markdown formatted report string.
    """
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

    if source_count:
        r += "**Fontes:** " + " | ".join(f"{k}: {v}" for k, v in source_count.items()) + "\n"

    # --- Risks ---
    r += "\n---\n\n## 🔴 Riscos Identificados\n\n"
    for risk in risks:
        emoji = {"CRITICAL": "🔴", "HIGH": "🟡", "MEDIUM": "🟠"}.get(risk.severity, "⚪")
        r += f"### {emoji} {risk.severity}\n**{risk.title}**\n{risk.description}\n"
        r += f"Afetados: {', '.join(risk.affected[:5])}\n\n"

    # --- Clusters ---
    r += "---\n## 📊 Análise de Clusters\n\n"
    for cid, accs in clusters.items():
        if cid == "unclustered":
            continue
        r += f"### Cluster {cid[-1]} ({len(accs)} contas)\n"
        for a in accs:
            r += f"- {a.site}: {a.fullname or 'N/A'}\n"
        r += "\n"

    unclustered = clusters.get("unclustered", [])
    if unclustered and len(unclustered) <= 10:
        r += f"### Sem cluster ({len(unclustered)} contas)\n"
        for a in unclustered:
            r += f"- {a.site}\n"
        r += "\n"

    # --- Recommendations ---
    r += "---\n## 🛡 Recomendações\n\n"
    for i, rec in enumerate(recommendations, 1):
        r += f"{i}. {rec}\n"
    r += "\n"

    # --- Breach data ---
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

    # --- Account inventory ---
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
