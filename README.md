# Protection Report

[![CI](https://github.com/prof-ramos/protection-report/actions/workflows/ci.yml/badge.svg)](https://github.com/prof-ramos/protection-report/actions/workflows/ci.yml)

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

# Enola (JSON export)
enola gfcramos -o enola_gfcramos.json
protection-report enola_gfcramos.json

# Vesper (JSON export)
vesper gfcramos --output vesper_gfcramos.json --no-color
protection-report vesper_gfcramos.json

# Compatibilidade com o entrypoint antigo
python3 protection_report.py report_gfcramos_simple.json
```

O relatório é salvo em `/tmp/reports/protection_<username>.md`.

## Fontes aceitas

- Maigret
- Sherlock
- Blackbird
- Naminter
- Enola (JSON export)
- Vesper (JSON export)

Os executáveis Enola e Vesper são opcionais e devem ser instalados separadamente; o pacote apenas lê seus JSONs. O nome do arquivo deve conter `enola` ou `vesper` para ativar o parser correto.

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q protection_report
```

## Limites

A consulta de vazamentos é opcional e usa a API pública do XposedOrNot. A ferramenta não faz monitoramento contínuo, integração HIBP ou remediação automática.
