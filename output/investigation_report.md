# CaseTrace Investigation Report

Scope: Synthetic training data only.
Evidence source: 'data/case_log.csv'
SHA-256: '51e8d8bbe2aee4b22f4cd2aaf38f59e72c6c502510ef877c9cfdb700ce964717'
Valid events: 9
Malformed rows skipped: 1
Baseline findings: 5

## Correlated conclusion

Severity: HIGH
User: jrivera
Device: workstation-07
Reason: Three authentification failures were followed by a success,sensitive file access, and an outbound connection.
