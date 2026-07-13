# Security tooling integration plan

This project is intentionally structured so that it can evolve into a production-grade evaluation pipeline for LLM-generated code.

## Recommended integrations
- Bandit for Python static analysis.
- CodeQL for semantic vulnerability detection across multiple languages.
- Optional Ollama-based local model evaluation for offline environments.

## Suggested workflow
1. Run the platform against a repository or single file.
2. Collect findings from built-in heuristics and from Bandit/CodeQL.
3. Normalize all findings into the shared JSON schema.
4. Publish reports to object storage or a dashboard for triage.
