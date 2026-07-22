# Protection Report

Gera relatórios de exposição de identidade a partir de resultados JSON de ferramentas OSINT.

O projeto normaliza resultados de Maigret, Sherlock, Blackbird e Naminter, deduplica contas, calcula risco, agrupa evidências por identidade e pode consultar vazamentos no XposedOrNot.

## Instalação

```bash
python3 -m pip install -e .
```

## Uso

```bash
# Maigret
maigret --json simple --timeout 10 -n 50 gfcramos
protection-report /tmp/reports/report_gfcramos_simple.json

# Múltiplas fontes
protection-report maigret.json sherlock.json blackbird.json --email user@example.com

# Compatibilidade com o entrypoint antigo
python3 protection_report.py report_gfcramos_simple.json
```

O relatório é salvo em `/tmp/reports/protection_<username>.md`.

## Fontes aceitas

- Maigret
- Sherlock
- Blackbird
- Naminter

## Verificação

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q protection_report
```

## Limites

A consulta de vazamentos é opcional e usa a API pública do XposedOrNot. A ferramenta não faz monitoramento contínuo, integração HIBP ou remediação automática.
