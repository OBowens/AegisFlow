import random
import tempfile
import unittest
from pathlib import Path

from aegis_agent.client import AuthError, EnrollResult, PermanentError, TransientError
from aegis_agent.filters import FilterChain, build_default_rules
from aegis_agent.runner import AgentRunner, RunnerSettings, TickStats
from aegis_agent.sources.fake import FakeEventSource
from aegis_agent.spool import Spool

from .support import FakeSleeper, StubClient, record_4104, record_4688

NOISE_4688 = dict(
    new_process_name=r"C:\Windows\System32\svchost.exe",
    parent_process_name=r"C:\Windows\System32\services.exe",
    command_line="svchost.exe -k netsvcs",
)


class RunnerTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state_dir = Path(self._tmp.name)
        self.source = FakeEventSource()
        self.client = StubClient()
        self.sleeper = FakeSleeper()

    def make_runner(self, *, source=None, spool=None, **settings_kw):
        settings = RunnerSettings(
            send_interval=(60, 120), backoff_base=5, backoff_cap=300, **settings_kw
        )
        return AgentRunner(
            source=source or self.source,
            filters=FilterChain(rules=build_default_rules()),
            spool=spool or Spool(self.state_dir),
            client=self.client,
            display_name="WIN-PILOT-01",
            settings=settings,
            sleep=self.sleeper,
            rng=random.Random(1),
        )


class EnrollTests(RunnerTestBase):
    def test_enroll_retries_transient_then_succeeds(self):
        self.client.enroll_results = [
            TransientError("net down"),
            TransientError("still down"),
            EnrollResult(1, "WIN-PILOT-01", False),
        ]
        runner = self.make_runner()
        result = runner.enroll_once()
        self.assertEqual(result.endpoint_id, 1)
        self.assertEqual(self.client.enroll_calls, 3)
        self.assertEqual(len(self.sleeper.calls), 2)

    def test_enroll_logs_adjusted_name(self):
        self.client.enroll_results = [EnrollResult(1, "WIN-PILOT-01-2", True)]
        runner = self.make_runner()
        with self.assertLogs("aegis_agent.runner", level="WARNING") as logs:
            runner.enroll_once()
        self.assertIn("adjusted", "\n".join(logs.output).lower())

    def test_enroll_gives_up_after_max_attempts(self):
        self.client.enroll_results = [TransientError("x"), TransientError("y")]
        runner = self.make_runner()
        runner.settings.enroll_max_attempts = 2
        with self.assertRaises(TransientError):
            runner.enroll_once()


class PollFilterSpoolTests(RunnerTestBase):
    def test_kept_events_spooled_noise_suppressed_and_logged(self):
        self.source.add_batch(
            [
                record_4688(record_id=10, **NOISE_4688),
                record_4688(record_id=11),  # a real one
                record_4104(record_id=5, script_block_text="Invoke-Expression $x"),
            ]
        )
        runner = self.make_runner()
        with self.assertLogs("aegis_agent.runner", level="INFO") as logs:
            stats = runner.tick()

        self.assertEqual(stats.read, 3)
        self.assertEqual(stats.kept, 2)
        self.assertEqual(stats.suppressed, 1)
        self.assertIn("filtered", "\n".join(logs.output))
        self.assertIn("canonical_4688_system_noise", "\n".join(logs.output))

        # The suppressed event must be counted AND actually excluded --
        # never spooled, never sent.
        sent_ids = {
            event["payload"]["agent_event_id"]
            for batch in self.client.sent_batches
            for event in batch
        }
        self.assertNotIn("WIN-PILOT-01|Security|10", sent_ids)
        self.assertEqual(len(sent_ids), 2)
        self.assertEqual(runner.spool.depth(), 0)

    def test_bookmarks_advance_per_channel(self):
        self.source.add_batch([record_4688(record_id=42), record_4104(record_id=7)])
        runner = self.make_runner()
        runner.tick()
        self.assertEqual(
            Spool(self.state_dir).load_bookmarks(),
            {"Security": 42, "Microsoft-Windows-PowerShell/Operational": 7},
        )

    def test_events_below_bookmark_are_not_reprocessed_after_restart(self):
        self.source.add_batch([record_4688(record_id=100)])
        self.make_runner().tick()  # spools, sends (StubClient acks), advances bookmark to 100
        self.assertEqual(Spool(self.state_dir).load_bookmarks(), {"Security": 100})

        # New process, same source re-serving the same record.
        source2 = FakeEventSource([[record_4688(record_id=100), record_4688(record_id=101)]])
        client2 = StubClient()
        runner2 = AgentRunner(
            source=source2,
            filters=FilterChain(rules=build_default_rules()),
            spool=Spool(self.state_dir),
            client=client2,
            display_name="WIN-PILOT-01",
            sleep=self.sleeper,
            rng=random.Random(1),
        )
        runner2._enrolled = EnrollResult(1, "WIN-PILOT-01", False)
        runner2.tick()
        # record 100 already sent+acked in run 1; only 101 is new here.
        self.assertEqual([e["payload"]["record_id"] for b in client2.sent_batches for e in b], [101])


class SendTests(RunnerTestBase):
    def _runner_with_two_spooled(self, **settings_kw):
        runner = self.make_runner(**settings_kw)
        self.source.add_batch([record_4688(record_id=1), record_4688(record_id=2)])
        runner.poll_once(TickStats())
        self.assertEqual(runner.spool.depth(), 2)
        return runner

    def test_successful_send_acks_and_resets_failures(self):
        runner = self._runner_with_two_spooled()
        self.client.send_results = [2]
        stats = TickStats()
        runner.drain(stats)
        self.assertEqual(stats.sent, 2)
        self.assertEqual(runner.spool.depth(), 0)
        self.assertEqual(len(self.client.sent_batches[-1]), 2)

    def test_transient_send_failure_keeps_buffer_and_backs_off(self):
        runner = self._runner_with_two_spooled()
        self.client.send_results = [TransientError("502")]
        stats = TickStats()
        runner.drain(stats)
        self.assertTrue(stats.send_failed)
        self.assertEqual(runner.spool.depth(), 2)
        self.assertEqual(runner._failures, 1)
        # next delay is a backoff value, well under the normal 60s floor
        self.assertLess(runner.next_delay(), 60)

    def test_recovery_after_failure_drains_buffer(self):
        runner = self._runner_with_two_spooled()
        self.client.send_results = [TransientError("down"), 2]
        runner.drain(TickStats())  # fails, stops
        runner.drain(TickStats())  # recovers, empties
        self.assertEqual(runner.spool.depth(), 0)
        self.assertEqual(runner._failures, 0)

    def test_auth_error_keeps_events_buffered(self):
        runner = self._runner_with_two_spooled()
        self.client.send_results = [AuthError("401", status=401)]
        runner.drain(TickStats())
        self.assertEqual(runner.spool.depth(), 2)
        self.assertEqual(runner._failures, 1)

    def test_permanent_400_quarantines_batch_then_keeps_draining(self):
        runner = self._runner_with_two_spooled()
        self.client.send_results = [PermanentError("bad", status=400, body="events[0] bad")]
        stats = TickStats()
        runner.drain(stats)
        self.assertEqual(stats.rejected, 2)
        self.assertEqual(runner.spool.depth(), 0)
        self.assertEqual(runner._failures, 0)
        rejected = list((self.state_dir / "rejected").glob("*.json"))
        self.assertEqual(len(rejected), 1)

    def test_drain_clears_multi_batch_backlog_in_one_tick(self):
        runner = self.make_runner(max_batch=100)
        self.source.add_batch([record_4688(record_id=i) for i in range(1, 451)])
        runner.poll_once(TickStats())
        self.assertEqual(runner.spool.depth(), 450)

        stats = TickStats()
        runner.drain(stats)
        self.assertEqual(runner.spool.depth(), 0)
        self.assertEqual(stats.sent, 450)
        self.assertEqual(len(self.client.sent_batches), 5)  # 100,100,100,100,50

    def test_drain_respects_per_tick_batch_cap(self):
        runner = self.make_runner(max_batch=100, max_batches_per_tick=2)
        self.source.add_batch([record_4688(record_id=i) for i in range(1, 501)])
        runner.poll_once(TickStats())
        runner.drain(TickStats())
        self.assertEqual(runner.spool.depth(), 300)  # only 2*100 sent this tick


class BackpressureTests(RunnerTestBase):
    def test_full_buffer_holds_events_in_the_event_log_without_dropping(self):
        # Buffer holds 2; a batch of 4 kept events arrives while sends fail.
        runner = self.make_runner(spool=Spool(self.state_dir, max_events=2))
        self.client.send_results = [TransientError("backend down")]
        self.source.add_batch([record_4688(record_id=rid) for rid in (1, 2, 3, 4)])

        stats = runner.tick()

        self.assertEqual(stats.kept, 2)
        self.assertEqual(stats.held_back, 2)
        self.assertEqual(runner.spool.depth(), 2)
        # Bookmark stops at the last event we actually stored -- records 3
        # and 4 stay unread in the Event Log, not lost.
        self.assertEqual(Spool(self.state_dir).load_bookmarks(), {"Security": 2})

    def test_held_back_events_are_picked_up_once_the_buffer_drains(self):
        runner = self.make_runner(spool=Spool(self.state_dir, max_events=2))
        self.client.send_results = [TransientError("down")]
        self.source.add_batch([record_4688(record_id=rid) for rid in (1, 2, 3, 4)])
        runner.tick()  # keeps 1,2 ; holds 3,4 ; send fails
        self.assertEqual(runner.spool.depth(), 2)
        self.assertEqual(Spool(self.state_dir).load_bookmarks(), {"Security": 2})

        # Backend recovers. The Event Log still holds 3 and 4 (bookmark
        # never advanced past 2) and re-serves them next read.
        self.client.send_results = []  # StubClient default: accept all
        self.source.add_batch([record_4688(record_id=rid) for rid in (3, 4)])
        stats = runner.tick()

        self.assertEqual(stats.held_back, 0)
        self.assertEqual(runner.spool.depth(), 0)
        sent_ids = sorted(
            e["payload"]["record_id"] for b in self.client.sent_batches for e in b
        )
        self.assertEqual(sent_ids, [1, 2, 3, 4])  # nothing lost


class LoopTests(RunnerTestBase):
    def test_run_forever_enrolls_then_runs_n_ticks(self):
        self.client.enroll_results = [EnrollResult(1, "WIN-PILOT-01", False)]
        self.source.add_batch([record_4688(record_id=1)])
        self.source.add_batch([record_4688(record_id=2)])
        runner = self.make_runner()
        self.client.send_results = [1, 1]
        runner.run_forever(max_ticks=2)
        self.assertEqual(self.client.enroll_calls, 1)
        self.assertEqual(sum(len(b) for b in self.client.sent_batches), 2)
        self.assertEqual(len(self.sleeper.calls), 1)  # sleeps between ticks, not after the last

    def test_poll_exception_does_not_kill_the_loop(self):
        class Boom(FakeEventSource):
            def read_new_events(self, bookmarks):
                raise RuntimeError("evtlog exploded")

        runner = self.make_runner(source=Boom())
        runner._enrolled = EnrollResult(1, "x", False)
        with self.assertLogs("aegis_agent.runner", level="ERROR"):
            stats = runner.tick()  # must not raise
        self.assertEqual(stats.read, 0)


if __name__ == "__main__":
    unittest.main()
