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
                affected=list(dict.fromkeys([a.site for a in self.accounts if a.fullname.strip()])),
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
                affected=list(dict.fromkeys([a.site for a in fin])),
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
                    affected=list(dict.fromkeys([a.site for a in accs])),
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
    redact: bool = False,
) -> str:
    """Generate a complete protection report in markdown."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    level = (
        "Alto" if risk_score >= 7 else
        "Moderado" if risk_score >= 4 else
        "Baixo"
    )

    disp_username = username[0] + "***" if (redact and username) else username

    r = f"# 🛡 Relatório de Proteção: {disp_username}\n\n"
    r += f"**Data:** {now}\n"
    r += f"**Contas encontradas:** {len(accounts)}\n"
    r += f"**Nível de risco:** {risk_score}/10 ({level})\n"
    r += f"**Modelo de risco:** v1.0.0\n"

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
        c_lbl = "conta" if len(accs) == 1 else "contas"
        r += f"### {cid} ({len(accs)} {c_lbl})\n"
        for a in accs:
            fn = (a.fullname[0] + ". ***") if (redact and a.fullname) else (a.fullname or 'N/A')
            r += f"- {a.site}: {fn}\n"
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
        u = "[REDACTED]" if redact else a.url
        un = (a.username[0] + "***") if (redact and a.username) else a.username
        fn = (a.fullname[0] + ". ***") if (redact and a.fullname) else a.fullname
        r += f"### {a.site}\n- **URL:** {u}\n- **User:** {un}\n"
        if fn:
            r += f"- **Nome:** {fn}\n"
        if a.bio and not redact:
            r += f"- **Bio:** {a.bio[:100]}...\n"
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
    """Generate a self-contained, high-end dark cyber security HTML report with Iconify icons."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    level = "Alto" if risk_score >= 7 else "Moderado" if risk_score >= 4 else "Baixo"
    level_color = "#ef4444" if risk_score >= 7 else "#f59e0b" if risk_score >= 4 else "#10b981"
    dial_deg = str(risk_score * 36)

    def esc(s):
        return html.escape(str(s)) if s else ""

    disp_username = (esc(username[0]) + "***") if (redact and username) else esc(username)

    css_content = f"""
        :root {{
            --bg: #0b0f19;
            --surface: #131b2e;
            --surface-card: rgba(23, 32, 54, 0.7);
            --border: rgba(255, 255, 255, 0.08);
            --border-hover: rgba(6, 182, 212, 0.3);
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --text-muted: #6b7280;
            --cyan: #06b6d4;
            --emerald: #10b981;
            --critical: #ef4444;
            --high: #f59e0b;
            --medium: #f97316;
            --low: #64748b;
            --info: #3b82f6;
            --radius-lg: 16px;
            --radius-md: 10px;
            --radius-sm: 6px;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            background-color: var(--bg);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem 1rem;
            min-height: 100vh;
        }}
        .container {{ max-width: 960px; margin: 0 auto; }}
        h1, h2, h3, .heading-font {{ font-family: 'Space Grotesk', sans-serif; }}
        
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 2rem;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        .brand {{ display: flex; align-items: center; gap: 0.75rem; }}
        .brand-icon {{
            width: 44px; height: 44px;
            background: linear-gradient(135deg, rgba(6, 182, 212, 0.2), rgba(16, 185, 129, 0.2));
            border: 1px solid var(--cyan);
            border-radius: var(--radius-md);
            display: flex; align-items: center; justify-content: center;
            font-size: 1.5rem;
            color: var(--cyan);
        }}
        .brand-title {{ font-size: 1.35rem; font-weight: 700; color: #fff; letter-spacing: -0.02em; }}
        .meta-pill {{
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid var(--border);
            padding: 0.35rem 0.85rem;
            border-radius: 99px;
            font-size: 0.825rem;
            color: var(--text-secondary);
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
        }}

        .hero-grid {{
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        @media (max-width: 768px) {{ .hero-grid {{ grid-template-columns: 1fr; }} }}
        
        .card {{
            background: var(--surface-card);
            backdrop-filter: blur(16px);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 1.5rem;
            transition: border-color 0.25s ease, transform 0.25s ease, box-shadow 0.25s ease;
        }}
        .card:hover {{
            border-color: var(--border-hover);
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(6, 182, 212, 0.08);
        }}

        .score-card {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}
        .score-dial {{
            position: relative;
            width: 130px; height: 130px;
            border-radius: 50%;
            background: conic-gradient({level_color} {dial_deg}deg, rgba(255, 255, 255, 0.06) 0deg);
            display: flex; align-items: center; justify-content: center;
            margin: 1rem 0;
        }}
        .score-inner {{
            width: 106px; height: 106px;
            background: var(--surface);
            border-radius: 50%;
            display: flex; flex-direction: column;
            align-items: center; justify-content: center;
        }}
        .score-val {{ font-size: 2.2rem; font-weight: 700; color: #fff; line-height: 1; }}
        .score-max {{ font-size: 0.75rem; color: var(--text-muted); }}
        .score-label {{
            font-size: 0.875rem;
            font-weight: 600;
            padding: 0.25rem 0.75rem;
            border-radius: 99px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            background: {level_color}22; color: {level_color}; border: 1px solid {level_color}44;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 1rem;
        }}
        .stat-box {{
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 1rem;
        }}
        .stat-num {{ font-size: 1.75rem; font-weight: 700; color: #fff; font-family: 'Space Grotesk', sans-serif; }}
        .stat-lbl {{ font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; display: flex; align-items: center; gap: 0.25rem; }}

        .section-header {{
            display: flex; align-items: center; gap: 0.5rem;
            font-size: 1.2rem; font-weight: 600; color: #fff;
            margin: 2rem 0 1rem 0;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
        }}

        .risk-item {{
            border-left: 4px solid var(--border);
            margin-bottom: 1rem;
            background: rgba(255, 255, 255, 0.02);
            border-radius: 0 var(--radius-md) var(--radius-md) 0;
            padding: 1rem 1.25rem;
        }}
        .risk-item.critical {{ border-left-color: var(--critical); background: rgba(239, 68, 68, 0.04); }}
        .risk-item.high {{ border-left-color: var(--high); background: rgba(245, 158, 11, 0.04); }}
        .risk-item.medium {{ border-left-color: var(--medium); background: rgba(249, 115, 22, 0.04); }}
        .risk-item.low {{ border-left-color: var(--low); }}
        .risk-item.info {{ border-left-color: var(--info); }}

        .tag {{
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            padding: 0.2rem 0.5rem;
            border-radius: var(--radius-sm);
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            margin-right: 0.4rem;
        }}
        .tag.critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); }}
        .tag.high {{ background: rgba(245, 158, 11, 0.2); color: var(--high); }}
        .tag.medium {{ background: rgba(249, 115, 22, 0.2); color: var(--medium); }}
        .tag.low {{ background: rgba(100, 116, 139, 0.2); color: var(--low); }}
        .tag.info {{ background: rgba(59, 130, 246, 0.2); color: var(--info); }}
        .tag.badge {{ background: rgba(255, 255, 255, 0.06); color: var(--text-secondary); border: 1px solid var(--border); }}

        .search-box-wrapper {{
            position: relative;
            margin-bottom: 1rem;
        }}
        .search-box-wrapper iconify-icon {{
            position: absolute;
            left: 1rem;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            font-size: 1.1rem;
        }}
        .search-box {{
            width: 100%;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 0.75rem 1rem 0.75rem 2.5rem;
            color: #fff;
            font-size: 0.9rem;
            outline: none;
            transition: border-color 0.2s;
        }}
        .search-box:focus {{ border-color: var(--cyan); }}

        table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
        th {{ text-align: left; padding: 0.75rem 1rem; font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); border-bottom: 1px solid var(--border); }}
        td {{ padding: 0.85rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.875rem; }}
        tr:hover td {{ background: rgba(255, 255, 255, 0.02); }}
        .url-link {{
            color: var(--cyan);
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            max-width: 260px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            vertical-align: middle;
        }}
        .url-link:hover {{ text-decoration: underline; }}

        .rec-list {{ list-style: none; }}
        .rec-item {{
            display: flex; align-items: flex-start; gap: 0.75rem;
            padding: 0.75rem 1rem;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            margin-bottom: 0.5rem;
            font-size: 0.9rem;
        }}
        .rec-icon {{ color: var(--emerald); font-size: 1.1rem; flex-shrink: 0; }}

        footer {{
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-muted);
        }}

        @media print {{
            body {{
                background-color: #ffffff !important;
                color: #0f172a !important;
                padding: 0 !important;
            }}
            .card {{
                background: #ffffff !important;
                border: 1px solid #e2e8f0 !important;
                box-shadow: none !important;
                backdrop-filter: none !important;
            }}
            .brand-title, .stat-num, .score-val, h1, h2, h3, th, td {{
                color: #0f172a !important;
            }}
            .score-inner {{ background: #ffffff !important; }}
            .search-box-wrapper {{ display: none !important; }}
        }}
    """

    parts = [
        "<!DOCTYPE html>",
        "<html lang='pt-BR'>",
        "<head>",
        "<meta charset='UTF-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
        f"<title>Protection Report — {disp_username}</title>",
        "<link rel='preconnect' href='https://fonts.googleapis.com'>",
        "<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>",
        "<link href='https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap' rel='stylesheet'>",
        "<script src='https://code.iconify.design/iconify-icon/2.1.0/iconify-icon.min.js'></script>",
        f"<style>{css_content}</style>",
        "</head>",
        "<body>",
        "<div class='container'>",
        "<header>",
        "  <div class='brand'>",
        "    <div class='brand-icon'><iconify-icon icon='lucide:shield-check'></iconify-icon></div>",
        "    <div>",
        "      <div class='brand-title'>Protection Report</div>",
        f"     <div style='font-size: 0.85rem; color: var(--text-secondary);'>Alvo: <strong style='color: #fff;'>@{disp_username}</strong></div>",
        "    </div>",
        "  </div>",
        "  <div style='display: flex; gap: 0.5rem;'>",
        f"   <span class='meta-pill'><iconify-icon icon='lucide:calendar'></iconify-icon> {now}</span>",
        "    <span class='meta-pill'><iconify-icon icon='lucide:tag'></iconify-icon> v1.0.0</span>",
        "  </div>",
        "</header>",
        "<div class='hero-grid'>",
        "  <div class='card score-card'>",
        "    <div class='score-dial'>",
        "      <div class='score-inner'>",
        f"       <span class='score-val'>{risk_score}</span>",
        "        <span class='score-max'>/ 10</span>",
        "      </div>",
        "    </div>",
        f"   <div class='score-label'>{level}</div>",
        "  </div>",
        "  <div class='card'>",
        "    <div class='stats-grid'>",
        "      <div class='stat-box'>",
        f"       <div class='stat-num'>{len(accounts)}</div>",
        "        <div class='stat-lbl'><iconify-icon icon='lucide:user-check'></iconify-icon> Contas</div>",
        "      </div>",
        "      <div class='stat-box'>",
        f"       <div class='stat-num'>{len(source_count)}</div>",
        "        <div class='stat-lbl'><iconify-icon icon='lucide:globe'></iconify-icon> Fontes OSINT</div>",
        "      </div>",
        "      <div class='stat-box'>",
        f"       <div class='stat-num'>{len(risks)}</div>",
        "        <div class='stat-lbl'><iconify-icon icon='lucide:alert-triangle'></iconify-icon> Riscos</div>",
        "      </div>",
        "      <div class='stat-box'>",
        f"       <div class='stat-num'>{(breach_data.count if breach_data and breach_data.found else 0)}</div>",
        "        <div class='stat-lbl'><iconify-icon icon='lucide:database-zap'></iconify-icon> Vazamentos</div>",
        "      </div>",
        "    </div>",
        "    <div style='margin-top: 1rem; font-size: 0.8rem; color: var(--text-muted);'>",
        "      Fontes analisadas: " + ", ".join(f"<code>{esc(k)}</code> ({v})" for k, v in source_count.items()) + "",
        "    </div>",
        "  </div>",
        "</div>",
    ]

    # Risks section
    parts.append("<div class='section-header'><iconify-icon icon='lucide:shield-alert' style='color: var(--critical);'></iconify-icon> Riscos Identificados</div>")
    parts.append("<div class='card'>")
    if risks:
        for risk in risks:
            cls = risk.severity.lower()
            icon_name = "lucide:alert-octagon" if risk.severity == "CRITICAL" else ("lucide:alert-triangle" if risk.severity in ("HIGH", "MEDIUM") else "lucide:info")
            parts.append(f"<div class='risk-item {cls}'>")
            parts.append(f"  <div style='display: flex; justify-content: space-between; align-items: center;'>")
            parts.append(f"    <div><span class='tag {cls}'><iconify-icon icon='{icon_name}'></iconify-icon> {esc(risk.severity)}</span><strong>{esc(risk.title)}</strong></div>")
            parts.append(f"    <span class='tag badge'>{esc(risk.category)} · {esc(risk.confidence)}</span>")
            parts.append(f"  </div>")
            parts.append(f"  <p style='margin-top: 0.4rem; font-size: 0.875rem; color: var(--text-secondary);'>{esc(risk.description)}</p>")
            if risk.affected:
                parts.append(f"  <div style='margin-top: 0.4rem; font-size: 0.75rem; color: var(--text-muted);'>Afetados: {', '.join(esc(a) for a in risk.affected[:5])}</div>")
            parts.append(f"</div>")
    else:
        parts.append("<p style='color: var(--text-muted);'>Nenhum risco relevante identificado.</p>")
    parts.append("</div>")

    # Score breakdown section
    if score_breakdown:
        parts.append("<div class='section-header'><iconify-icon icon='lucide:bar-chart-3' style='color: var(--cyan);'></iconify-icon> Decomposição do Score de Risco</div>")
        parts.append("<div class='card'><table><tr><th>Regra</th><th>Pontos</th><th>Evidência</th></tr>")
        for b in score_breakdown:
            parts.append(f"<tr><td><code>{esc(b['rule'])}</code></td><td><strong style='color: var(--cyan);'>+{b['points']}</strong></td><td>{esc(b['evidence'])}</td></tr>")
        parts.append("</table></div>")

    # Clusters section
    parts.append("<div class='section-header'><iconify-icon icon='lucide:network' style='color: var(--cyan);'></iconify-icon> Clusters de Identidade</div>")
    parts.append("<div class='card'>")
    has_clusters = False
    for cid, accs in clusters.items():
        if cid == "unclustered":
            continue
        has_clusters = True
        parts.append(f"<div style='margin-bottom: 1rem;'>")
        cnt_lbl = "conta vinculada" if len(accs) == 1 else "contas vinculadas"
        parts.append(f"  <div style='font-weight: 600; color: var(--cyan); margin-bottom: 0.3rem; display: flex; align-items: center; gap: 0.35rem;'><iconify-icon icon='lucide:git-commit'></iconify-icon> {esc(cid)} ({len(accs)} {cnt_lbl})</div>")
        parts.append(f"  <div style='display: flex; flex-wrap: wrap; gap: 0.5rem;'>")
        for a in accs:
            fn = (esc(a.fullname[0]) + ". ***") if (redact and a.fullname) else esc(a.fullname)
            parts.append(f"    <span class='tag badge'><strong>{esc(a.site)}</strong>: {fn or 'N/A'}</span>")
        parts.append(f"  </div>")
        parts.append(f"</div>")
    if not has_clusters:
        parts.append("<p style='color: var(--text-muted);'>Nenhum cluster de identidade formado.</p>")
    parts.append("</div>")

    # Account table section
    parts.append("<div class='section-header'><iconify-icon icon='lucide:users' style='color: var(--cyan);'></iconify-icon> Contas Encontradas</div>")
    parts.append("<div class='card'>")
    parts.append("<div class='search-box-wrapper'><iconify-icon icon='lucide:search'></iconify-icon><input type='text' class='search-box' id='accountSearch' placeholder='Filtrar por plataforma, usuário ou nome...' onkeyup='filterAccounts()'></div>")
    parts.append("<table id='accountsTable'><thead><tr><th>Plataforma</th><th>URL</th><th>Usuário</th><th>Nome</th><th>Fonte</th></tr></thead><tbody>")
    for a in accounts:
        u = esc(a.url) if not redact else "[REDACTED]"
        un = (esc(a.username[0]) + "***") if (redact and a.username) else esc(a.username)
        fn = (esc(a.fullname[0]) + ". ***") if (redact and a.fullname) else esc(a.fullname)
        link = f"<a href='{u}' target='_blank' rel='noreferrer' class='url-link' title='{u}'>{u} <iconify-icon icon='lucide:external-link' style='font-size: 0.75rem; flex-shrink: 0;'></iconify-icon></a>" if (not redact and u) else f"<span>{u}</span>"
        srcs = ", ".join(esc(s) for s in a.sources)
        parts.append(f"<tr><td><strong>{esc(a.site)}</strong></td><td>{link}</td><td><code>{un}</code></td><td>{fn or '-'}</td><td><span class='tag badge'>{srcs}</span></td></tr>")
    parts.append("</tbody></table></div>")

    # Recommendations
    parts.append("<div class='section-header'><iconify-icon icon='lucide:check-square' style='color: var(--emerald);'></iconify-icon> Recomendações de Segurança</div>")
    parts.append("<div class='card'><ul class='rec-list'>")
    for rec in recommendations:
        parts.append(f"<li class='rec-item'><iconify-icon icon='lucide:check-circle-2' class='rec-icon'></iconify-icon><span>{esc(rec)}</span></li>")
    parts.append("</ul></div>")

    # Breach section
    if breach_data and breach_data.found:
        parts.append("<div class='section-header'><iconify-icon icon='lucide:database-zap' style='color: var(--critical);'></iconify-icon> Vazamentos de Dados Confirmados (XposedOrNot)</div>")
        parts.append("<div class='card'>")
        parts.append(f"<p style='margin-bottom: 1rem;'>O e-mail foi identificado em <strong>{esc(breach_data.count)} vazamentos</strong> (Pontuação de risco: {breach_data.risk_score}/100).</p>")
        parts.append("<div style='display: flex; flex-wrap: wrap; gap: 0.4rem;'>")
        for b in breach_data.breaches[:15]:
            parts.append(f"<span class='tag critical'><iconify-icon icon='lucide:shield-off'></iconify-icon> {esc(b)}</span>")
        parts.append("</div></div>")

    # Footer
    parts.append("<footer>")
    parts.append("<p>Protection Report v1.0.0 — Relatório gerado automaticamente a partir de dados públicos de OSINT.</p>")
    parts.append("</footer>")

    # Script for live filter with empty state
    parts.append("<script>")
    parts.append("""
    function filterAccounts() {
        const input = document.getElementById('accountSearch');
        const filter = input.value.toLowerCase();
        const table = document.getElementById('accountsTable');
        const tbody = table.getElementsByTagName('tbody')[0];
        const trs = tbody.getElementsByTagName('tr');
        let visibleCount = 0;

        for (let i = 0; i < trs.length; i++) {
            if (trs[i].id === 'noResultsRow') continue;
            const text = trs[i].textContent || trs[i].innerText;
            const match = text.toLowerCase().indexOf(filter) > -1;
            trs[i].style.display = match ? '' : 'none';
            if (match) visibleCount++;
        }

        let noResultsRow = document.getElementById('noResultsRow');
        if (visibleCount === 0) {
            if (!noResultsRow) {
                noResultsRow = document.createElement('tr');
                noResultsRow.id = 'noResultsRow';
                noResultsRow.innerHTML = `<td colspan="5" style="text-align: center; padding: 2rem; color: var(--text-muted);">Nenhuma conta encontrada para "${filter}"</td>`;
                tbody.appendChild(noResultsRow);
            } else {
                noResultsRow.style.display = '';
                noResultsRow.cells[0].innerText = `Nenhuma conta encontrada para "${filter}"`;
            }
        } else if (noResultsRow) {
            noResultsRow.style.display = 'none';
        }
    }
    """)
    parts.append("</script>")

    parts.append("</div>") # container
    parts.append("</body></html>")
    return "\n".join(parts)

