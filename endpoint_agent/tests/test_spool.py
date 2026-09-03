import json
import tempfile
import unittest
from pathlib import Path

from aegis_agent.events import to_ingest_event
from aegis_agent.spool import Spool

from .support import record_4104, record_4688


def _events(*record_ids):
    return [to_ingest_event(record_4688(record_id=rid)) for rid in record_ids]


class SpoolTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def spool(self, **kw):
        return Spool(self.dir, **kw)

    def test_append_persists_events_and_bookmarks(self):
        s = self.spool()
        s.append(_events(1, 2), bookmarks={"Security": 2})
        self.assertEqual(s.depth(), 2)

        reloaded = self.spool()
        self.assertEqual(reloaded.depth(), 2)
        self.assertEqual(reloaded.load_bookmarks(), {"Security": 2})

    def test_append_is_idempotent_by_agent_event_id(self):
        s = self.spool()
        s.append(_events(1, 2), bookmarks={"Security": 2})
        added = s.append(_events(2, 3), bookmarks={"Security": 3})
        self.assertEqual(added, 1)
        self.assertEqual(s.depth(), 3)

    def test_bookmarks_saved_only_reflect_last_call(self):
        s = self.spool()
        s.append(_events(1), bookmarks={"Security": 1})
        s.append([], bookmarks={"Security": 1, "Microsoft-Windows-PowerShell/Operational": 99})
        self.assertEqual(
            self.spool().load_bookmarks(),
            {"Security": 1, "Microsoft-Windows-PowerShell/Operational": 99},
        )

    def test_pending_batch_respects_count(self):
        s = self.spool()
        s.append(_events(*range(1, 11)), bookmarks={"Security": 10})
        self.assertEqual(len(s.pending_batch(max_count=4, max_bytes=10_000_000)), 4)

    def test_pending_batch_respects_byte_budget_but_always_yields_one(self):
        s = self.spool()
        big = to_ingest_event(record_4104(record_id=1, script_block_text="X" * 5000))
        small = to_ingest_event(record_4688(record_id=2))
        s.append([big, small], bookmarks={})
        batch = s.pending_batch(max_count=50, max_bytes=1000)
        self.assertEqual(len(batch), 1)  # the big one alone, over budget but unsplittable

    def test_ack_removes_and_compacts(self):
        s = self.spool()
        s.append(_events(1, 2, 3), bookmarks={"Security": 3})
        batch = s.pending_batch(max_count=2, max_bytes=10_000_000)
        s.ack(batch)
        self.assertEqual(s.depth(), 1)

        reloaded = self.spool()
        self.assertEqual(reloaded.depth(), 1)
        lines = [
            line for line in (self.dir / "pending.jsonl").read_text().splitlines() if line.strip()
        ]
        self.assertEqual(len(lines), 1)

    def test_reject_quarantines_and_drops(self):
        s = self.spool()
        s.append(_events(1, 2), bookmarks={"Security": 2})
        batch = s.pending_batch(max_count=2, max_bytes=10_000_000)
        path = s.reject(batch, detail="HTTP 400: bad payload")
        self.assertEqual(s.depth(), 0)
        self.assertTrue(path.exists())
        saved = json.loads(path.read_text())
        self.assertEqual(saved["detail"], "HTTP 400: bad payload")
        self.assertEqual(len(saved["events"]), 2)

    def test_remaining_capacity(self):
        s = self.spool(max_events=5)
        self.assertEqual(s.remaining_capacity(), 5)
        s.append(_events(1, 2), bookmarks={"Security": 2})
        self.assertEqual(s.remaining_capacity(), 3)

    def test_over_capacity_keeps_every_event_and_logs(self):
        # The runner is responsible for backpressure; if the spool is
        # somehow handed more than the cap, it must NOT drop anything.
        s = self.spool(max_events=5)
        with self.assertLogs("aegis_agent.spool", level="ERROR"):
            s.append(_events(*range(1, 9)), bookmarks={"Security": 8})
        self.assertEqual(s.depth(), 8)
        self.assertEqual(s.remaining_capacity(), 0)
        reloaded_ids = {
            e["payload"]["record_id"]
            for e in self.spool().pending_batch(max_count=99, max_bytes=10_000_000)
        }
        self.assertEqual(reloaded_ids, set(range(1, 9)))

    def test_crash_between_append_and_bookmark_is_recovered_by_dedupe(self):
        # Simulate: events written to pending.jsonl but the process died
        # before the *next* poll could advance/rewrite anything. A fresh
        # spool + a re-read of the same events must not duplicate them.
        s = self.spool()
        s.append(_events(1, 2), bookmarks={"Security": 0})  # bookmark deliberately behind

        restarted = self.spool()
        added = restarted.append(_events(1, 2, 3), bookmarks={"Security": 3})
        self.assertEqual(added, 1)
        self.assertEqual(restarted.depth(), 3)

    def test_unreadable_state_file_starts_from_zero(self):
        (self.dir / "state.json").write_text("{ not json")
        self.assertEqual(self.spool().load_bookmarks(), {})

    def test_skips_corrupt_pending_lines_on_load(self):
        (self.dir / "pending.jsonl").write_text(
            json.dumps(_events(1)[0]) + "\n" + "{garbage\n" + json.dumps(_events(2)[0]) + "\n"
        )
        self.assertEqual(self.spool().depth(), 2)


if __name__ == "__main__":
    unittest.main()
