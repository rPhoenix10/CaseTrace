import csv
import hashlib
from pathlib import Path


REQUIRED_FIELDS = (
    "timestamp",
    "device",
    "user",
    "source_ip",
    "event_type",
    "detail",
)

SUSPICIOUS_TYPES = {
    "AUTH_FAILURE",
    "FILE_ACCESS",
    "OUTBOUND_CONNECTION",
}


def load_events(path):
    events = []
    skipped = 0

    with path.open(mode="r", encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        for row in reader:
            is_valid = row and all(
                (row.get(field) or "").strip() for field in REQUIRED_FIELDS
            )
            if not is_valid:
                skipped += 1
                continue

            event = {
                field: row[field].strip()
                for field in REQUIRED_FIELDS
            }
            events.append(event)

    return sorted(events, key=lambda event: event["timestamp"]), skipped


def baseline_findings(events):
    return [
        event
        for event in events
        if event["event_type"] in SUSPICIOUS_TYPES
    ]

    
def correlate_incident(events):
    users = sorted({event["user"] for event in events})

    for user in users:
        user_events = [event for event in events if event["user"] == user]
        failures = [event for event in user_events if event["event_type"] == "AUTH_FAILURE"]
        successes = [event for event in user_events if event["event_type"] == "AUTH_SUCCESS"]

        for success in successes:
            device = success["device"]
            earlier_failures = [event for event in failures if event["device"] == device and event["timestamp"] < success["timestamp"]]
            sensitive_accesses = [event for event in user_events if event["device"] == device and event["event_type"] == "FILE_ACCESS" and event["timestamp"] > success["timestamp"]]

            if len(earlier_failures) < 3 or not sensitive_accesses:
                continue

            sensitive_access = sensitive_accesses[0]
            outbound_connections = [event for event in user_events if event["device"] == device and event["event_type"] == "OUTBOUND_CONNECTION" and event["timestamp"] > sensitive_access["timestamp"]]

            if outbound_connections:
                return {
                    "severity": "HIGH",
                    "user": user,
                    "device": device,
                    "reason": ("Three authentification failures were followed by a success,"
                                "sensitive file access, and an outbound connection."
                    ),
                    "evidence": (earlier_failures + [success, sensitive_access, outbound_connections[0]]
                    ),
                }
            
    return None


# Read source file as bytes and return as text
def integrity_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_report(source_path, events, skipped, findings, incident, digest):
    lines = [
        "# CaseTrace Investigation Report",
        "",
        "Scope: Synthetic training data only.",
        f"Evidence source: '{source_path.as_posix()}'",
        f"SHA-256: '{digest}'",
        f"Valid events: {len(events)}",
        f"Malformed rows skipped: {skipped}",
        f"Baseline findings: {len(findings)}",
        "",
        "## Correlated conclusion",
        "",
    ]

    if incident:
        lines.extend(
            [
                f"Severity: {incident['severity']}",
                f"User: {incident['user']}",
                f"Device: {incident['device']}",
                f"Reason: {incident['reason']}",
            ]
        )
    else: lines.append("no corrdinated incident identified.")

    lines.extend(["", "## Timeline", ""])
    for event in events:
        lines.append(
            f"- {event['timestamp']} | {event['device']} | "
            f"{event['user']} | {event['event_type']} |{event['detail']}"
        )

    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "This educational rule set analyzes one known CSV schema and does not "
            "establish identity, intent, or legal conclusions.",
        ]
    )

    return "\n".join(lines) + "\n"


def main():
    source_path = Path("data/case_log.csv")
    report_path = Path("output/investigation_report.md")
    hash_path = Path("output/evidence_hash.sha256")

    if not source_path.exists():
        print("ERROR: data/case_log.csv was not found.")
        return 1

    events, skipped = load_events(source_path)
    findings = baseline_findings(events)
    print(f"Loaded {len(events)} valid events; skipped {skipped} malformed row(s).")
    print(f"Baseline findings: {len(findings)} individual suspicious events(s).")
    print("Baseline result: individual suspicious events found, "
          "but no coordinated incident was identified."
    )

    incident = correlate_incident(events)
    if incident:
        print(
            f"Correlated incident: {incident['severity']} severity for "
            f"{incident['user']} on {incident['device']}."
        )
    else:
        print("Correlated incident: none.")
        
    digest = integrity_hash(source_path)
    report = build_report(
        source_path,
        events,
        skipped,
        findings,
        incident,
        digest,
    )

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")
    hash_path.write_text(
        f"{digest} {source_path.as_posix()}\n",
        encoding="utf-8",
    )

    print(f"Integrity record: {hash_path.as_posix()}")
    print(f"Report written: {report_path.as_posix()}")
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
    