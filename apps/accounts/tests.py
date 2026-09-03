from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client, TestCase
from django.urls import reverse

from config.testcase import AuthedTestCase

from apps.audit.models import AuditLog
from apps.incidents.models import IncidentGroup
from apps.log_intake.models import UploadedLogFile
from apps.organizations.models import Organization
from apps.reports.models import GeneratedReport

User = get_user_model()

# A representative real view from each app -- none of these should be
# reachable without logging in.
PROTECTED_URLS = [
    "/",
    "/organizations/",
    "/organizations/profile/",
    "/logs/",
    "/logs/upload/",
    "/incidents/",
    "/risk/",
    "/resilience/",
    "/playbooks/",
    "/reports/",
    "/audit/",
]


class LoginRequiredEverywhereTests(TestCase):
    def setUp(self):
        self.anon = Client()

    def test_every_real_page_redirects_anonymous_to_login(self):
        for url in PROTECTED_URLS:
            with self.subTest(url=url):
                response = self.anon.get(url)
                self.assertEqual(response.status_code, 302, url)
                self.assertTrue(
                    response["Location"].startswith(reverse("accounts:login")),
                    f"{url} redirected to {response['Location']!r}",
                )
                self.assertIn("next=", response["Location"])

    def test_login_page_itself_is_reachable_anonymously(self):
        response = self.anon.get(reverse("accounts:login"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'name="username"')
        self.assertContains(response, 'name="password"')
        self.assertContains(response, "csrfmiddlewaretoken")

    def test_admin_login_is_still_reachable(self):
        # LoginRequiredMiddleware must not shadow the admin's own login.
        response = self.anon.get("/admin/login/")
        self.assertEqual(response.status_code, 200)


class LoginFlowTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="analyst",
            email="analyst@example.test",
            password="corr3ct-h0rse-staple",
            first_name="Ada",
            last_name="Lovelace",
        )
        self.login_url = reverse("accounts:login")

    def test_wrong_password_is_a_real_error_not_a_500(self):
        response = self.client.post(
            self.login_url, {"username": "analyst", "password": "nope"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "incorrect")
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_correct_password_logs_in_and_redirects_to_the_dashboard(self):
        response = self.client.post(
            self.login_url,
            {"username": "analyst", "password": "corr3ct-h0rse-staple"},
        )
        self.assertRedirects(response, reverse("core:index"), target_status_code=200)
        self.assertEqual(
            int(self.client.session["_auth_user_id"]), self.user.pk
        )

    def test_next_param_is_honoured_after_login(self):
        target = reverse("reports:index")
        response = self.client.post(
            f"{self.login_url}?next={target}",
            {
                "username": "analyst",
                "password": "corr3ct-h0rse-staple",
                "next": target,
            },
        )
        self.assertRedirects(response, target, target_status_code=200)

    def test_logout_clears_the_session_and_lands_on_login(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse("accounts:logout"))
        self.assertRedirects(
            response, reverse("accounts:login"), target_status_code=200
        )
        self.assertNotIn("_auth_user_id", self.client.session)


class RealUserIsShownNotTheHardcodedOneTests(AuthedTestCase):
    """AutoLoginClient signs in as 'test-analyst' / 'Test Analyst'."""

    def setUp(self):
        Organization.objects.create(name="Demo Organization", organization_type="Demo")

    def test_shell_profile_chip_shows_the_logged_in_user(self):
        response = self.client.get(reverse("core:index"))
        self.assertContains(response, "Test Analyst")
        self.assertNotContains(response, "Osreah Bowens")
        self.assertNotContains(response, "Alex Daniel")

    def test_my_profile_page_shows_the_logged_in_user(self):
        response = self.client.get(reverse("organizations:my_profile"))
        self.assertContains(response, "Test Analyst")
        self.assertNotContains(response, "Osreah Bowens")
        self.assertNotContains(response, "SOC Analyst")

    def test_sign_out_control_is_present_in_the_shell(self):
        response = self.client.get(reverse("core:index"))
        self.assertContains(response, reverse("accounts:logout"))
        self.assertContains(response, "Sign out")


class RealUserPopulatesOwnershipFieldsTests(AuthedTestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Demo Organization", organization_type="Demo"
        )
        self.the_user = User.objects.get_or_create(username="test-analyst")[0]

    def test_auditlog_user_is_the_real_user(self):
        incident = IncidentGroup.objects.create(
            organization=self.organization,
            title="Brute force against admin",
            incident_type="failed_login",
            severity=IncidentGroup.Severity.HIGH,
            status=IncidentGroup.Status.OPEN,
            workflow_state={"stage": "understand"},
        )
        self.client.post(reverse("incidents:assign_to_me", args=[incident.id]))

        entry = AuditLog.objects.get(
            action="incident_assigned", target_id=str(incident.id)
        )
        self.assertEqual(entry.user, self.the_user)

    def test_uploaded_by_is_the_real_user(self):
        from django.core.files.uploadedfile import SimpleUploadedFile

        response = self.client.post(
            reverse("log_intake:upload"),
            {
                "log_file": SimpleUploadedFile(
                    "sample.log", b"2026-09-01 12:00:00 host app: nothing much happened\n"
                ),
                "source_type": UploadedLogFile.SourceType.OTHER,
                "notes": "",
            },
        )
        self.assertEqual(response.status_code, 302)
        uploaded = UploadedLogFile.objects.get(file_name="sample.log")
        self.addCleanup(uploaded.delete)
        self.assertEqual(uploaded.uploaded_by, self.the_user)

    def test_generated_by_is_the_real_user(self):
        with patch("apps.reports.views.run_report_generation") as gen:
            gen.return_value = {
                "summary": "s",
                "report_text": "body",
                "model": "claude-sonnet-5",
            }
            self.client.post(reverse("reports:generate", args=["executive"]))

        report = GeneratedReport.objects.get(report_type="executive")
        self.assertEqual(report.generated_by, self.the_user)


class CreateUserCommandTests(TestCase):
    def _run(self, *args, password="s3cret-passphrase", confirm=None):
        confirm = password if confirm is None else confirm
        with patch(
            "apps.accounts.management.commands.createuser.getpass",
            side_effect=[password, confirm],
        ):
            out = StringIO()
            call_command("createuser", *args, stdout=out)
            return out.getvalue()

    def test_creates_a_plain_active_non_staff_account_that_can_log_in(self):
        out = self._run("--username", "realuser", "--email", "real@example.test")
        self.assertIn("realuser", out)

        user = User.objects.get(username="realuser")
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

        self.assertTrue(
            Client().login(username="realuser", password="s3cret-passphrase")
        )

    def test_rejects_a_duplicate_username(self):
        User.objects.create_user(username="taken")
        with self.assertRaises(CommandError):
            self._run("--username", "taken")

    def test_rejects_mismatched_password_confirmation(self):
        with self.assertRaises(CommandError):
            self._run("--username", "mismatch", password="one", confirm="two")

    def test_rejects_a_password_that_fails_validation(self):
        with self.assertRaises(CommandError):
            self._run("--username", "weak", password="123")
