import unittest
from pathlib import Path

from case_trace import baseline_findings
from case_trace import correlate_incident
from case_trace import integrity_hash
from case_trace import load_events

CASE_LOG = Path("data/case_log.csv")


class CaseTraceTests(unittest.TestCase):
    def setUp(self):
        self.events, self.skipped = load_events(CASE_LOG)

    def test_known_dataset_counts(self):
        self.assertEqual(len(self.events), 9)
        self.assertEqual(self.skipped, 1)
        self.assertEqual(len(baseline_findings(self.events)), 5)

    def test_correlates_high_severity_incident(self):
        incident = correlate_incident(self.events)
        self.assertIsNotNone(incident)
        self.assertEqual(incident["severity"], "HIGH")
        self.assertEqual(incident["user"], "jrivera")
        self.assertEqual(incident["device"], "workstation-07")

    def test_routine_events_do_not_create_incident(self):
        routine_events = [
            event
            for event in self.events
            if event["user"] == "asmith"
            or event["event_type"] == "DEVICE_HEALTH"
        ]
        self.assertIsNone(correlate_incident(routine_events))

    def test_malformed_row_is_rejected(self):
        users = {event["user"] for event in self.events}
        self.assertNotIn("", users)
        self.assertEqual(self.skipped, 1)

    def test_hash_is_repeatable_for_unchanged_source(self):
        first_digest = integrity_hash(CASE_LOG)
        second_digest = integrity_hash(CASE_LOG)
        self.assertEqual(first_digest, second_digest)


if __name__ == "__main__":
    unittest.main()