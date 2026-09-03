import unittest

from aegis_agent.events import parse_event_xml
from aegis_agent.filters import (
    Canonical4688NoiseRule,
    FilterChain,
    build_default_rules,
)

from . import FIXTURES
from .support import record_4104, record_4688


class Canonical4688NoiseRuleTests(unittest.TestCase):
    def setUp(self):
        self.rule = Canonical4688NoiseRule()

    def suppress_reason(self, record):
        return self.rule.evaluate(record)

    def test_svchost_from_services_with_k_is_suppressed(self):
        rec = record_4688(
            new_process_name=r"C:\Windows\System32\svchost.exe",
            parent_process_name=r"C:\Windows\System32\services.exe",
            command_line=r"C:\Windows\system32\svchost.exe -k netsvcs -p",
        )
        self.assertIsNotNone(self.suppress_reason(rec))

    def test_svchost_with_wrong_parent_is_kept(self):
        rec = record_4688(
            new_process_name=r"C:\Windows\System32\svchost.exe",
            parent_process_name=r"C:\Users\j.reyes\AppData\Local\Temp\dropper.exe",
            command_line=r"svchost.exe -k netsvcs",
        )
        self.assertIsNone(self.suppress_reason(rec))

    def test_svchost_without_k_flag_is_kept(self):
        rec = record_4688(
            new_process_name=r"C:\Windows\System32\svchost.exe",
            parent_process_name=r"C:\Windows\System32\services.exe",
            command_line=r"svchost.exe -embedding",
        )
        self.assertIsNone(self.suppress_reason(rec))

    def test_svchost_outside_system32_is_kept(self):
        rec = record_4688(
            new_process_name=r"C:\Users\Public\svchost.exe",
            parent_process_name=r"C:\Windows\System32\services.exe",
            command_line=r"svchost.exe -k netsvcs",
        )
        self.assertIsNone(self.suppress_reason(rec))

    def test_conhost_canonical_args_suppressed(self):
        rec = record_4688(
            new_process_name=r"C:\Windows\System32\conhost.exe",
            parent_process_name=r"C:\Windows\System32\cmd.exe",
            command_line=r"\??\C:\WINDOWS\system32\conhost.exe 0xffffffff -ForceV1",
        )
        self.assertIsNotNone(self.suppress_reason(rec))

    def test_conhost_with_extra_args_is_kept(self):
        rec = record_4688(
            new_process_name=r"C:\Windows\System32\conhost.exe",
            parent_process_name=r"C:\Windows\System32\cmd.exe",
            command_line=r"conhost.exe 0xffffffff -ForceV1 && whoami",
        )
        self.assertIsNone(self.suppress_reason(rec))

    def test_missing_command_line_still_suppresses_known_pair(self):
        rec = record_4688(
            new_process_name=r"C:\Windows\System32\lsass.exe",
            parent_process_name=r"C:\Windows\System32\wininit.exe",
            command_line=None,
        )
        self.assertIsNotNone(self.suppress_reason(rec))

    def test_lsass_with_unexpected_parent_is_kept(self):
        rec = record_4688(
            new_process_name=r"C:\Windows\System32\lsass.exe",
            parent_process_name=r"C:\Windows\System32\cmd.exe",
            command_line=None,
        )
        self.assertIsNone(self.suppress_reason(rec))

    def test_normal_user_process_is_kept(self):
        self.assertIsNone(self.suppress_reason(record_4688()))

    def test_non_4688_ignored_by_this_rule(self):
        self.assertIsNone(self.suppress_reason(record_4104()))

    def test_case_and_slash_insensitive(self):
        rec = record_4688(
            new_process_name="c:/windows/system32/SVCHOST.EXE",
            parent_process_name="C:/Windows/System32/SERVICES.EXE",
            command_line="svchost.exe -k appmodel",
        )
        self.assertIsNotNone(self.suppress_reason(rec))


class ScriptBlockRuleTests(unittest.TestCase):
    def setUp(self):
        self.chain = FilterChain(rules=build_default_rules())

    def test_empty_script_block_suppressed(self):
        decision = self.chain.decide(record_4104(script_block_text="   \n  "))
        self.assertEqual(decision.action, "suppress")
        self.assertEqual(decision.rule, "empty_powershell_script_block")

    def test_real_script_block_kept(self):
        decision = self.chain.decide(record_4104(script_block_text="Invoke-Expression $payload"))
        self.assertEqual(decision.action, "keep")

    def test_allowlisted_script_block_suppressed(self):
        chain = FilterChain(rules=build_default_rules(allowlist_texts=("prompt",)))
        self.assertEqual(chain.decide(record_4104(script_block_text="prompt")).action, "suppress")
        # whitespace differences are normalized
        self.assertEqual(chain.decide(record_4104(script_block_text="  prompt  ")).action, "suppress")

    def test_allowlist_is_exact_not_substring(self):
        chain = FilterChain(rules=build_default_rules(allowlist_texts=("prompt",)))
        self.assertEqual(
            chain.decide(record_4104(script_block_text="prompt; rm -rf /")).action, "keep"
        )


class ConfiguredSuppressAndDisableTests(unittest.TestCase):
    def test_extra_suppress_matches_all_present_keys(self):
        chain = FilterChain(
            rules=build_default_rules(
                extra_suppress=(
                    {
                        "event_id": 4688,
                        "new_process_name": "MpCmdRun.exe",
                        "parent_process_name": "MsMpEng.exe",
                        "reason": "Defender helper",
                    },
                )
            )
        )
        hit = record_4688(
            new_process_name=r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MpCmdRun.exe",
            parent_process_name=r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
            command_line="MpCmdRun.exe -SignatureUpdate",
        )
        miss = record_4688(
            new_process_name=r"C:\Windows\System32\MpCmdRun.exe",
            parent_process_name=r"C:\Windows\System32\cmd.exe",
        )
        self.assertEqual(chain.decide(hit).reason, "Defender helper")
        self.assertEqual(chain.decide(miss).action, "keep")

    def test_extra_suppress_entry_needs_a_condition(self):
        with self.assertRaises(ValueError):
            FilterChain(rules=build_default_rules(extra_suppress=({"reason": "nope"},)))

    def test_disabling_a_builtin_rule(self):
        noisy = record_4688(
            new_process_name=r"C:\Windows\System32\svchost.exe",
            parent_process_name=r"C:\Windows\System32\services.exe",
            command_line="svchost.exe -k netsvcs",
        )
        chain = FilterChain(rules=build_default_rules(), disabled=("canonical_4688_system_noise",))
        self.assertEqual(chain.decide(noisy).action, "keep")


NOISE_SVCHOST = dict(
    new_process_name=r"C:\Windows\System32\svchost.exe",
    parent_process_name=r"C:\Windows\System32\services.exe",
    command_line="svchost.exe -k netsvcs",
)
NOISE_CONHOST = dict(
    new_process_name=r"C:\Windows\System32\conhost.exe",
    parent_process_name=r"C:\Windows\System32\cmd.exe",
    command_line=r"\??\C:\WINDOWS\system32\conhost.exe 0xffffffff -ForceV1",
)


class MixedBatchClassificationTests(unittest.TestCase):
    """The chain must classify a whole batch correctly -- an explicit
    count of how many events each rule suppresses, not just 'a log line
    appeared'.
    """

    def test_counts_suppressions_across_a_realistic_batch(self):
        chain = FilterChain(rules=build_default_rules())
        batch = [
            record_4688(record_id=1, **NOISE_SVCHOST),
            record_4688(record_id=2, **NOISE_CONHOST),
            record_4688(record_id=3),  # whoami /priv from cmd -> keep
            record_4104(record_id=4, script_block_text="   "),  # empty -> suppress
            record_4104(record_id=5, script_block_text="iex $payload"),  # keep
            record_4688(  # lsass with the wrong parent -> keep
                record_id=6,
                new_process_name=r"C:\Windows\System32\lsass.exe",
                parent_process_name=r"C:\Windows\System32\cmd.exe",
                command_line=None,
            ),
        ]
        decisions = [chain.decide(record) for record in batch]

        suppressed = [d for d in decisions if d.action == "suppress"]
        kept = [d for d in decisions if d.action == "keep"]
        self.assertEqual(len(suppressed), 3)
        self.assertEqual(len(kept), 3)
        self.assertEqual(
            sorted(d.rule for d in suppressed),
            [
                "canonical_4688_system_noise",
                "canonical_4688_system_noise",
                "empty_powershell_script_block",
            ],
        )


class ParsedFixtureFilterTests(unittest.TestCase):
    def test_noise_fixture_is_suppressed_and_keep_fixture_passes(self):
        chain = FilterChain(rules=build_default_rules())
        noise = parse_event_xml((FIXTURES / "event_4688_noise.xml").read_text())
        keep = parse_event_xml((FIXTURES / "event_4688_keep.xml").read_text())
        self.assertEqual(chain.decide(noise).action, "suppress")
        self.assertEqual(chain.decide(keep).action, "keep")


if __name__ == "__main__":
    unittest.main()
