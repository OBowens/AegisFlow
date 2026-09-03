import json
import unittest
from datetime import timezone

from aegis_agent.events import (
    EventParseError,
    parse_event_xml,
    parse_system_time,
    to_ingest_event,
)

from . import FIXTURES


class ParseSystemTimeTests(unittest.TestCase):
    def test_seven_digit_fractional_and_z(self):
        dt = parse_system_time("2026-02-11T14:22:07.1234567Z")
        self.assertEqual(dt.tzinfo, timezone.utc)
        self.assertEqual((dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second), (2026, 2, 11, 14, 22, 7))
        self.assertEqual(dt.microsecond, 123456)

    def test_no_fractional_seconds(self):
        dt = parse_system_time("2026-02-11T14:22:07Z")
        self.assertEqual(dt.microsecond, 0)

    def test_explicit_offset_is_converted_to_utc(self):
        dt = parse_system_time("2026-02-11T09:22:07-05:00")
        self.assertEqual(dt.hour, 14)
        self.assertEqual(dt.tzinfo, timezone.utc)

    def test_missing_value_raises(self):
        with self.assertRaises(EventParseError):
            parse_system_time(None)

    def test_garbage_raises(self):
        with self.assertRaises(EventParseError):
            parse_system_time("not a time")


class Parse4688Tests(unittest.TestCase):
    def setUp(self):
        self.record = parse_event_xml((FIXTURES / "event_4688_keep.xml").read_text())

    def test_core_fields(self):
        self.assertEqual(self.record.event_id, 4688)
        self.assertEqual(self.record.channel, "Security")
        self.assertEqual(self.record.record_id, 884412)
        self.assertEqual(self.record.computer, "WIN-PILOT-01")
        self.assertEqual(self.record.event_type, "Security/4688")
        self.assertEqual(self.record.agent_event_id, "WIN-PILOT-01|Security|884412")

    def test_normalized_data(self):
        data = self.record.data
        self.assertEqual(data["new_process_name"], r"C:\Windows\System32\whoami.exe")
        self.assertEqual(data["parent_process_name"], r"C:\Windows\System32\cmd.exe")
        self.assertEqual(data["command_line"], r'"C:\Windows\system32\whoami.exe" /priv')
        self.assertEqual(data["subject_user_name"], "j.reyes")
        self.assertNotIn("subjectlogonid", data)  # unmapped fields are dropped

    def test_missing_command_line_is_absent_not_crash(self):
        xml = (FIXTURES / "event_4688_keep.xml").read_text().replace(
            '<Data Name=\'CommandLine\'>"C:\\Windows\\system32\\whoami.exe" /priv</Data>', ""
        )
        record = parse_event_xml(xml)
        self.assertNotIn("command_line", record.data)


class Parse4104Tests(unittest.TestCase):
    def setUp(self):
        self.record = parse_event_xml((FIXTURES / "event_4104_keep.xml").read_text())

    def test_core_fields(self):
        self.assertEqual(self.record.event_id, 4104)
        self.assertEqual(self.record.channel, "Microsoft-Windows-PowerShell/Operational")
        self.assertEqual(self.record.event_type, "Microsoft-Windows-PowerShell/4104")
        self.assertEqual(self.record.record_id, 21877)

    def test_script_block_and_ints(self):
        data = self.record.data
        self.assertIn("Invoke-WebRequest", data["script_block_text"])
        self.assertEqual(data["message_number"], 1)
        self.assertEqual(data["message_total"], 1)
        self.assertNotIn("path", data)  # empty <Path/> is dropped


class MalformedXmlTests(unittest.TestCase):
    def test_not_xml(self):
        with self.assertRaises(EventParseError):
            parse_event_xml("<not-closed")

    def test_no_system_element(self):
        with self.assertRaises(EventParseError):
            parse_event_xml("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'></Event>")

    def test_no_record_id(self):
        xml = (FIXTURES / "event_4688_keep.xml").read_text().replace(
            "<EventRecordID>884412</EventRecordID>", ""
        )
        with self.assertRaises(EventParseError):
            parse_event_xml(xml)


class ToIngestEventTests(unittest.TestCase):
    def test_matches_shipped_payload_fixture_4688(self):
        record = parse_event_xml((FIXTURES / "event_4688_keep.xml").read_text())
        expected = json.loads((FIXTURES / "payload_4688.json").read_text())[0]
        self.assertEqual(to_ingest_event(record), expected)

    def test_matches_shipped_payload_fixture_4104(self):
        record = parse_event_xml((FIXTURES / "event_4104_keep.xml").read_text())
        expected = json.loads((FIXTURES / "payload_4104.json").read_text())[0]
        self.assertEqual(to_ingest_event(record), expected)

    def test_occurred_at_is_utc_z_suffixed(self):
        record = parse_event_xml((FIXTURES / "event_4688_keep.xml").read_text())
        self.assertTrue(to_ingest_event(record)["occurred_at"].endswith("Z"))

    def test_event_type_stays_under_100_chars(self):
        record = parse_event_xml((FIXTURES / "event_4104_keep.xml").read_text())
        self.assertLessEqual(len(to_ingest_event(record)["event_type"]), 100)


if __name__ == "__main__":
    unittest.main()
