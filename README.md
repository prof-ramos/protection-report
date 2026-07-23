# Protection Report

[![CI](https://github.com/prof-ramos/protection-report/actions/workflows/ci.yml/badge.svg)](https://github.com/prof-ramos/protection-report/actions/workflows/ci.yml)

Gera relatórios de exposição de identidade a partir de resultados JSON de ferramentas OSINT (Maigret, Sherlock, Blackbird, Naminter, Enola e Vesper).

O projeto normaliza resultados de busca, deduplica contas por chave canônica, calcula risco explicável com evidências, agrupa evidências por identidade e pode consultar vazamentos no XposedOrNot.

---

## 🚀 Instalação

```bash
python3 -m pip install -e .
```

---

## 💻 Uso da CLI

```bash
# Execução básica
protection-report /caminho/para/report_username.json

# Múltiplas fontes com verificação de vazamento
protection-report maigret.json sherlock.json blackbird.json --email user@example.com

# Formato JSON ou HTML com redação de PII
protection-report input.json --format html --redact --output-dir ./dist

# Imprimir diretamente no stdout
protection-report input.json --format json --stdout
```

### Argumentos da CLI

| Argumento | Descrição |
| --------- | --------- |
| `FILE...` | Arquivo(s) JSON gerado(s) pelas ferramentas OSINT suportadas |
| `--email` | Verifica o e-mail na base de vazamentos do XposedOrNot |
| `--username` | Nome de usuário do relatório (detectado automaticamente se omitido) |
| `-o, --output-dir` | Diretório de destino do relatório gerado |
| `-f, --format` | Formato de saída: `md` (padrão), `json`, `html` ou `pdf` |
| `--redact` | Redige PII (e-mail, nome de usuário, nome completo e URLs) na saída |
| `--stdout` | Imprime o relatório diretamente no stdout |
| `-q, --quiet` | Suprime a saída no stdout, salvando apenas o arquivo |

### Códigos de Retorno da CLI

| Código | Significado |
| :---: | ----------- |
| `0` | Relatório gerado com sucesso |
| `1` | Erro de uso / argumentos inválidos |
| `2` | Erro no parsing de um ou mais arquivos de entrada |
| `3` | Nenhuma conta encontrada após o parsing |

---

## 🐍 Uso da API Python

```python
from protection_report.parsers import detect_source_and_parse
from protection_report.report import RiskAnalyzer, generate_report

# Parse de arquivo JSON OSINT
result = detect_source_and_parse(json_data, source_hint="maigret")

# Deduplicação e análise de risco
accounts = RiskAnalyzer.deduplicate(result.accounts)
analyzer = RiskAnalyzer(accounts)
clusters = analyzer.cluster()
risk_score = analyzer.risk_score(clusters)
risks = analyzer.identify_risks(clusters)

# Geração de relatório em Markdown
markdown_output = generate_report(
    username="usuario",
    accounts=accounts,
    clusters=clusters,
    risks=risks,
    recommendations=analyzer.recommendations(risks),
    risk_score=risk_score,
    source_count={"maigret": len(accounts)},
    score_breakdown=analyzer.score_breakdown,
)
```

---

## 🛠️ Fontes OSINT Aceitas

- **Maigret** (`report_*_simple.json`)
- **Sherlock** (`sherlock_*.json`)
- **Blackbird** (`blackbird_*.json`)
- **Naminter** (`naminter_*.json`)
- **Enola** (`enola_*.json`)
- **Vesper** (`vesper_*.json`)

---

## 🧪 Testes

Para executar a suíte de testes automatizados:

```bash
python3 -m pytest tests/ -v
```

---

## 🔒 Segurança

Consulte [SECURITY.md](SECURITY.md) para diretrizes de comunicação e reporte de vulnerabilidades.
