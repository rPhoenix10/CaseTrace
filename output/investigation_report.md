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

## Timeline

- 2026-10-27T08:45:00Z | workstation-02 | asmith | AUTH_SUCCESS |routine sign-in
- 2026-10-27T08:50:00Z | sensor-gateway-02 | system | DEVICE_HEALTH |status normal
- 2026-10-27T09:00:00Z | workstation-07 | jrivera | AUTH_FAILURE |invalid password
- 2026-10-27T09:01:00Z | workstation-07 | jrivera | AUTH_FAILURE |invalid password
- 2026-10-27T09:02:00Z | workstation-07 | jrivera | AUTH_FAILURE |invalid password
- 2026-10-27T09:03:00Z | workstation-07 | jrivera | AUTH_SUCCESS |successful sign-in after failures
- 2026-10-27T09:04:00Z | workstation-07 | jrivera | FILE_ACCESS |sensitive_plans.zip opened
- 2026-10-27T09:05:00Z | workstation-07 | jrivera | OUTBOUND_CONNECTION |destination 203.0.113.77
- 2026-10-27T09:06:00Z | workstation-07 | system | DEVICE_WARNING |network adapter reset unexpectedly

## Limitations

This educational rule set analyzes one known CSV schema and does not establish identity, intent, or legal conclusions.
