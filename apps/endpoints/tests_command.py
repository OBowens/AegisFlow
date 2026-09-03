"""Coverage for `manage.py createendpoint`."""

from __future__ import annotations

from io import StringIO

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from apps.endpoints.models import Endpoint, hash_token
from apps.organizations.models import Organization


def _printed_token(output: str) -> str:
    """The command prints the raw token on its own indented last line."""
    return output.strip().splitlines()[-1].strip()


def _make_org(name="AegisFlow AI Demo Organization"):
    return Organization.objects.create(
        name=name,
        organization_type="Demo",
        country="St. Vincent and the Grenadines",
        sector="Demo",
        risk_profile="medium",
    )


class CreateEndpointCommandTests(TestCase):
    def _run(self, *args):
        out = StringIO()
        call_command("createendpoint", *args, stdout=out, stderr=out)
        return out.getvalue()

    def test_creates_row_in_current_organization_and_prints_raw_token_only(self):
        org = _make_org()
        output = self._run("--name", "PILOT-1")

        endpoint = Endpoint.objects.get()
        self.assertEqual(endpoint.organization, org)
        self.assertEqual(endpoint.display_name, "PILOT-1")

        raw_token = _printed_token(output)
        # What was printed authenticates, and only its hash is stored.
        self.assertEqual(hash_token(raw_token), endpoint.token_hash)
        self.assertNotIn(endpoint.token_hash, output)

    def test_auto_creates_organization_when_none_exists(self):
        self.assertEqual(Organization.objects.count(), 0)
        self._run("--name", "PILOT-1")
        self.assertEqual(Organization.objects.count(), 1)
        self.assertEqual(Endpoint.objects.get().organization, Organization.objects.get())

    def test_duplicate_name_is_auto_suffixed_with_a_warning(self):
        org = _make_org()
        Endpoint.objects.create(organization=org, display_name="PILOT-1")
        output = self._run("--name", "PILOT-1")
        self.assertIn("PILOT-1-2", output)
        self.assertTrue(
            Endpoint.objects.filter(organization=org, display_name="PILOT-1-2").exists()
        )

    def test_explicit_org_id(self):
        _make_org(name="First")
        second = _make_org(name="Second")
        self._run("--name", "PILOT-1", "--org-id", str(second.pk))
        self.assertEqual(Endpoint.objects.get().organization, second)

    def test_unknown_org_id_errors(self):
        with self.assertRaises(CommandError):
            self._run("--name", "PILOT-1", "--org-id", "999999")

    def test_blank_name_errors(self):
        with self.assertRaises(CommandError):
            self._run("--name", "   ")
