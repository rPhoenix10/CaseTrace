import csv
from pathlib import Path

REQIRED_FIELDS = (
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

def baseline_findings(events):
    return [
        eventsfor event in events
         event["event_type"] in SUSPICIOUS_TYPES
    ]