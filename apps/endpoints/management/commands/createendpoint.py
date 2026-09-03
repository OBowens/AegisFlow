"""Provision one Windows endpoint and print its enrollment token.

This is the intended way to register a pilot machine before installing
its agent. It mirrors ``manage.py createuser``: it creates a single row
and emits the secret exactly once, on stdout -- the token is never taken
from an argument, so it does not land in shell history or process
listings, and is not stored anywhere you can retrieve it in plaintext
later except the database itself.

    python manage.py createendpoint --name "PILOT-LAPTOP-3"

Hand the printed token and a name to whoever runs the installer. Their
name answer is bound to this row at enrollment (auto-suffixed if it
collides with another endpoint in the organization); the ``--name`` here
is just the provisioning label until then.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError

from apps.endpoints.models import Endpoint
from apps.endpoints.services import resolve_available_name
from apps.organizations.models import Organization
from apps.organizations.services.current_organization import get_current_organization


class Command(BaseCommand):
    help = "Create one Windows endpoint row and print its enrollment token."

    def add_arguments(self, parser):
        parser.add_argument(
            "--name",
            required=True,
            help="Provisioning label for the endpoint (unique within the organization).",
        )
        parser.add_argument(
            "--org-id",
            type=int,
            default=None,
            help="Organization id to attach to. Defaults to the current organization.",
        )

    def handle(self, *args, **options):
        name = " ".join(options["name"].split()).strip()
        if not name:
            raise CommandError("--name cannot be blank.")

        org_id = options["org_id"]
        if org_id is None:
            organization = get_current_organization()
        else:
            try:
                organization = Organization.objects.get(pk=org_id)
            except Organization.DoesNotExist as exc:
                raise CommandError(f"No organization with id {org_id}.") from exc

        effective_name = resolve_available_name(organization, name)
        if effective_name != name:
            self.stdout.write(
                self.style.WARNING(
                    f"An endpoint named {name!r} already exists in "
                    f"{organization.name!r}; using {effective_name!r} instead."
                )
            )

        try:
            endpoint, raw_token = Endpoint.issue(
                organization=organization, display_name=effective_name
            )
        except IntegrityError as exc:  # pragma: no cover - race on the name
            raise CommandError(f"Could not create endpoint: {exc}") from exc

        self.stdout.write(
            self.style.SUCCESS(
                f"Created endpoint {endpoint.display_name!r} (id={endpoint.id}) "
                f"in organization {organization.name!r}."
            )
        )
        self.stdout.write("")
        self.stdout.write("Enrollment token (copy now -- shown once, only its hash is stored):")
        self.stdout.write(f"    {raw_token}")
