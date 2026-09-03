"""Create a single real login account for AegisFlow AI.

This is the intended way to make the account you actually sign in with.
It deliberately creates a *plain* active user -- not a superuser and not
staff -- because nothing in this scope grants more than "can use the app"
(there is no role/permission model). Use Django's own `createsuperuser`
separately if you also need `/admin/` access.

The password is never taken from an argument or a file: it is prompted
for interactively and read without echo, so it never lands in shell
history, process listings, or the repo.

    python manage.py createuser --username analyst --email analyst@example.com
"""

from __future__ import annotations

from getpass import getpass

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError


class Command(BaseCommand):
    help = "Create one real, non-privileged login account (password prompted, not echoed)."

    def add_arguments(self, parser):
        parser.add_argument("--username", required=True)
        parser.add_argument("--email", default="")
        parser.add_argument(
            "--first-name", default="", help="Optional. Shown in the app's profile chip."
        )
        parser.add_argument("--last-name", default="")

    def handle(self, *args, **options):
        User = get_user_model()
        username = options["username"].strip()
        if not username:
            raise CommandError("--username cannot be blank.")
        if User.objects.filter(username__iexact=username).exists():
            raise CommandError(f"A user named {username!r} already exists.")

        password = getpass("Password: ")
        if not password:
            raise CommandError("Password cannot be blank.")
        if getpass("Password (again): ") != password:
            raise CommandError("The two passwords did not match.")

        stub = User(
            username=username,
            email=options["email"].strip(),
            first_name=options["first_name"].strip(),
            last_name=options["last_name"].strip(),
        )
        try:
            validate_password(password, user=stub)
        except ValidationError as exc:
            raise CommandError("\n".join(exc.messages)) from exc

        try:
            user = User.objects.create_user(
                username=username,
                email=stub.email,
                password=password,
                first_name=stub.first_name,
                last_name=stub.last_name,
            )
        except IntegrityError as exc:  # pragma: no cover - race on username
            raise CommandError(f"Could not create user: {exc}") from exc

        self.stdout.write(
            self.style.SUCCESS(
                f"Created login account {user.get_username()!r} "
                f"(staff={user.is_staff}, superuser={user.is_superuser})."
            )
        )
