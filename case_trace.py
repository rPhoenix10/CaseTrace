import csv
from pathlib import Path

REQUIRED_FIELDS = (
    "timestamp",
    "device",
    "user",
    "sourece_ip",
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
