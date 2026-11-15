# Automated Web App Vuln Log Audit Assistant

Pipeline: parse -> classify -> retrieve OWASP rules -> draft remediation -> triage

## Who owns what
- Ines: data/, src/classifier.py, src/triage.py
- Hiba: knowledge_base/, src/parser.py, src/retriever.py, src/remediation.py

## Shared formats
- CSV columns: id, log_line, label, attack_type, source
- parse_log(line) -> dict {ip, method, uri, payload}
- classify(line) -> (label, confidence)
- retrieve(payload, k=3) -> list of (passage, score)

## Rules
- Never commit API keys or model weights.
- Work only in your own files.
- Run `git pull origin main` before you start and before you push.

## Pushing without commands (Hiba)
- Website: open the folder -> Add file -> Upload files -> Commit changes
- Colab: File -> Save a copy in GitHub
