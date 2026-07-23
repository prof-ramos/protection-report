# Domain Documentation & ADR Rules

This repository uses a single-context domain documentation layout.

## Layout

- **`CONTEXT.md`**: Canonical glossary and ubiquitous domain language at the repository root.
- **`docs/adr/`**: Architectural Decision Records (ADRs).

## Consumer Rules

- Always consult `CONTEXT.md` before inventing new domain terms or model names.
- Record significant, hard-to-reverse architectural decisions as ADRs under `docs/adr/`.
