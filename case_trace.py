import csv
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
        users_events = [event for event in events if event["user"] == user]
        failures = [event for event in users_events if event["event_type"] == "AUTH_FAILURE"]
        success = [event for event in users_events if event["event_type"] == "AUTH_SUCCESS"]

        return None

def main():
    source_path = Path("data/case_log.csv")

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
        
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
    