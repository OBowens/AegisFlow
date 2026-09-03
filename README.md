# AegisFlow AI

An AI-assisted cyber-resilience workflow for a small security team. You upload
operational logs and monitoring exports; the app parses them into normalized
alerts, groups the alerts into incidents, derives control-gap and disaster-
readiness findings, and then lets a human ask a Claude-backed assistant to
analyse, explain, compare, prioritize, and write response playbooks and reports
against that real, already-persisted context.

It is a single Django monolith (Django 6.0, Python 3.12). The AI layer talks to
the Anthropic Messages API directly over `urllib` — there is no vendor SDK
dependency.

---

## 1. What the app actually does

The core loop, in order:

1. **Upload.** A user uploads one or more log/export files on the *Upload Logs*
   page and picks a source type (or lets the content sniffer guess it). The
   file is stored under `private_uploads/` (never served publicly).

2. **Parse.** `run_demo_log_workflow` (`apps/ai_core/orchestrator.py`) runs a
   **fully deterministic** pipeline — no AI call anywhere in it:
   - `parse_uploaded_log` dispatches to a format-specific parser
     (Wazuh, Graylog, PRTG, Proxmox, Fortinet-style firewall, backup-report,
     SSL-certificate, Windows Security, Linux `auth.log`) or a generic
     extension-based fallback for "other". Output is `ParsedAlert` rows
     (capped at 50 events per file).
   - `group_alerts_for_upload` clusters alerts into `IncidentGroup` rows.
   - `link_source_ip_matches_for_incidents` cross-links incidents that share a
     source IP within a 90-day window.
   - `create_risk_findings_for_incidents` derives `GapFinding` /
     `RiskAssessment` rows.
   - `create_readiness_findings_for_risks` derives `DisasterReadinessFinding`
     rows.
   - `create_playbooks_for_incidents` creates a `ResponsePlaybook` per incident
     with a fixed generic step list.
   - `create_upload_summary_report_for_upload` writes a summary
     `GeneratedReport`.
   Every run writes one `AIRun` row (`ai_module="demo_log_workflow"`) for audit,
   even though it makes no model call.

3. **Investigate with AI.** From an incident, a gap, the readiness page, or the
   dashboard, a user triggers one of the Claude-backed agents (see §2). Each
   agent gathers real context from the database, sends it to Claude, stores the
   result in its own model, and shows it on the page. Nothing the AI returns is
   treated as ground truth — the prompts instruct the model to reason only from
   the supplied context and to say when the evidence is inconclusive.

Everything is scoped to one organization (see §5).

---

## 2. Architecture

### Django apps

| App | Owns |
| --- | --- |
| `apps/core` | Dashboard / home page; the "prioritize what to fix first" briefing (`PriorityBriefing`). |
| `apps/accounts` | Login / logout (Django's built-in auth views + Codex's login template) and the `createuser` command. **No membership / role model exists.** |
| `apps/organizations` | `Organization`, `CriticalSystem`; the canonical `get_current_organization()` resolver; org profile pages. |
| `apps/log_intake` | `UploadedLogFile`, `ParsedAlert`; all file parsers (`services/*_parser.py`), the content sniffer, private-file storage, alert list/export. |
| `apps/incidents` | `IncidentGroup`, `IncidentEvidence`, `IncidentSourceIPLink`; the guided Understand/Verify/Respond/Resolve workflow (`workflow_state` JSON); AI result models `AnalystResult`, `AnalystQuestion`, `IncidentComparison`, `IncidentExplanation`, `WorkflowStepGuidance`, `WorkflowStepQuestion`; alert grouping, source-IP correlation, confidence scoring. |
| `apps/risk` | `GapFinding`, `RiskAssessment`; AI models `RiskNarration`, `RiskQuestion`; `UserQuestion`; deterministic risk-derivation service. |
| `apps/resilience` | `DisasterReadinessFinding`, `ReadinessPlan`, `ReadinessAnswer`, `ReadinessScoreSnapshot`; AI models `ReadinessExplanation`, `ReadinessQuestion`; readiness scoring, readiness-vs-finding contradiction detection. |
| `apps/playbooks` | `SOPChecklist`, `ResponsePlaybook`, `PlaybookStep`, `ChecklistItemState`; the deterministic approval gate that flags destructive step text; SOP library. |
| `apps/reports` | `GeneratedReport` (types: executive, technical, incident, risk, readiness, upload_summary, action_plan); report list/detail; deterministic upload-summary generator. |
| `apps/audit` | `AIRun` (one row per AI call attempt, including rate-limited rejections and the no-op parse pipeline) and `AuditLog` (user actions). Audit history page + CSV export. |
| `apps/ai_core` | Everything AI: the provider, the Sanitizer, the rate limiter, and the agent modules + their context builders. |

### The shared AI agent pattern

Every live AI feature is built the same way, in three layers:

```
view  ──►  agent module              ──►  provider
          (apps/ai_core/modules/*.py)     (AnthropicProvider.send_message)
              │                                │
              ├─ context builder               ├─ Sanitizer  (sanitize → call → restore)
              │  (apps/ai_core/services/*.py)   │
              └─ persistence model              └─ returns plain text
```

1. **Context builder** (`apps/ai_core/services/*_context.py`) — pure functions
   that turn ORM objects into one structured plain-text prompt section. No AI
   call, no network. `build_incident_context` is the big one and is reused
   verbatim by the analyst, incident-explainer, writer, workflow-advisor, and
   the technical/incident report writers rather than being reimplemented.

2. **Agent module** (`apps/ai_core/modules/*.py`) — composes a system preamble +
   the context (+ a user question, for the Q&A variants), calls
   `provider.send_message(prompt, organization=...)`, and returns a small
   display-ready dict. The `provider` argument defaults to a real
   `AnthropicProvider()` but accepts any object with `.send_message()` and
   `.model`, which is how tests inject a fake.

   Live modules: `analyst`, `comparator`, `incident_explainer`, `prioritizer`,
   `readiness_advisor`, `risk_advisor`, `workflow_advisor`, `writer`,
   `report_writer` (one module, dispatches on report type).

3. **Persistence** — the view saves the result to that feature's own model
   (`AnalystResult`, `RiskNarration`, `ReadinessExplanation`, `PlaybookStep`,
   `GeneratedReport`, …) and updates the `AIRun` row to `success` / `failed`.

### The layer every AI call goes through

Inside `AnthropicProvider.send_message()`, in this order:

- **Rate limiting** is applied one level up, in the view: `deny_ai_call(org,
  ai_module)` runs *before* the `AIRun` STARTED row is written. See §5.
- **Sanitizer** (`apps/ai_core/sanitizer.py`): `sanitize_for_ai(prompt,
  organization=...)` replaces real identifiers — the org's own name, its
  `CriticalSystem` names/owners, incident/finding affected-system strings,
  parsed-alert accounts, plus regex-matched IPs, internal FQDNs, emails,
  file paths, uppercase host tags — with stable per-prompt `[[TYPE_n]]`
  tokens. The same real value maps to the same token *within one prompt*.
  The token→value map lives only for the duration of that one call and is
  never persisted. Claude's reply is rehydrated back to real values before
  `send_message()` returns, so stored output and on-page display are
  unaffected. `settings.AI_SANITIZER_ENABLED` (default `True`) is an
  escape hatch for the handful of tests that assert on raw prompt text.
- **Error normalization**: every realistic failure (missing key, non-200,
  DNS/connection error, read timeout, reset connection, unexpected body
  shape, empty response) is re-raised as a plain `RuntimeError`, which every
  view already catches and turns into a friendly on-page message.

`config/test_runner.py` additionally pops `ANTHROPIC_API_KEY` out of the
environment for the entire test run, so no test can ever make a real billed
call even if it forgets to mock.

---

## 3. Setup and running

Tested on Python 3.12 with the checked-in `venv/`.

### 3.1 Environment

```bash
cd /home/prett/caribsecure_live
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

`requirements.txt` is `Django`, `psycopg2-binary` (only needed for Postgres),
`gunicorn` (only needed for a non-dev server).

### 3.2 Configuration (`.env`)

`config/settings.py` loads `.env` from the project root itself (a tiny built-in
parser — no `python-dotenv`). Real environment variables always win over
`.env`. Variables actually read:

| Variable | Default | Purpose |
| --- | --- | --- |
| `DJANGO_SECRET_KEY` | insecure dev key | Django secret. |
| `DJANGO_DEBUG` | `True` | Debug mode. |
| `DJANGO_ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated. |
| `BRAND_NAME` | `AegisFlow AI` | Shown in UI + admin. |
| `BRAND_TAGLINE` | (a sentence) | Shown in UI. |
| `ANTHROPIC_API_KEY` | *(unset)* | **Required for any AI feature.** Read by `AnthropicProvider`. Without it, AI actions fail gracefully with a "not configured" message; the rest of the app works. |
| `ANTHROPIC_MODEL` | `claude-sonnet-5` | Override the model. |
| `AI_SANITIZER_ENABLED` | `True` | Prompt pseudonymization (§2). |
| `AI_RATE_LIMIT_ENABLED` | `True` | AI rate limiting (§5). |
| `AI_RATE_LIMIT_GLOBAL_PER_HOUR` | `40` | Hourly cap across all AI endpoints. |
| `AI_RATE_LIMIT_ENDPOINT_PER_MINUTE` | `8` | Per-endpoint burst cap. |
| `AI_TRIAGE_INTERACTIVE_RESERVE` | `15` | Hourly-budget calls the background endpoint-triage scan keeps free for interactive AI features. |
| `DATABASE_NAME` / `DATABASE_USER` / `DATABASE_PASSWORD` / `DATABASE_HOST` / `DATABASE_PORT` | *(unset)* | If **all five** are set, Postgres is used; otherwise SQLite at `db.sqlite3`. |
| `PRIVATE_UPLOAD_ROOT` | `private_uploads` | Upload storage dir (relative to project). |
| `PRIVATE_EXPORT_ROOT` | `private_exports` | Export storage dir. |

> Note: `OPENAI_API_KEY` is **not** in the table because nothing live reads
> it — it is only referenced by `OpenAIProvider`, a non-functional scaffold
> placeholder with no callers. `.env.example` mirrors the table above.

### 3.3 Migrations

All apps have migrations and there are no pending model changes:

```bash
./venv/bin/python manage.py migrate
```

The checked-in `db.sqlite3` already has all migrations applied plus demo data
(see §4). To start clean, delete `db.sqlite3` and re-run `migrate`.

### 3.4 Run the dev server

```bash
./venv/bin/python manage.py runserver
# http://127.0.0.1:8000/
```

Every app view requires login (`LoginRequiredMiddleware`). Create the one
real account you sign in with:

```bash
./venv/bin/python manage.py createuser --username you --email you@example.com
# prompts for a password, not echoed; creates a plain non-staff user
```

`createsuperuser` is separate and only needed if you also want `/admin/`.

### 3.5 Tests

```bash
./venv/bin/python manage.py test --noinput
```

591 tests, all passing as of this writing. The custom test runner blocks live
Anthropic calls. View tests inherit `config.testcase.AuthedTestCase`, whose
client authenticates as a throwaway user on the first request (every view now
requires login); tests that need an anonymous request use a plain
`django.test.Client`.

### 3.6 Maintenance commands

- `apps/accounts`: `createuser` (make the real login account; password prompted)
- `apps/incidents`: `backfill_incident_confidence`
- `apps/log_intake`: `backfill_graylog_severity`, `try_linux_parser` (dev aid)
- `apps/endpoints`: `createendpoint` (provision a Windows endpoint + print its token);
  `triage_endpoint_events` (correlate recent endpoint events and AI-triage the
  flagged clusters — run on an interval by host cron, e.g. `*/10 * * * *`;
  `--dry-run` to preview, `--max-candidates N` to cap AI calls per run)

---

## 4. Honest known limitations

- **Parsers are validated against synthetic fixtures only.** Every parser test
  runs against hand-written sample files in `apps/log_intake/fixtures/` and
  `sample_data/`. None of them have been checked against a real export from an
  actual Wazuh / Graylog / PRTG / Fortinet / Proxmox / Veeam / etc. instance.
  Real vendor output very likely has fields, encodings, and edge cases the
  parsers don't handle yet.

- **Single-tenant; auth is login-only.** Every view requires a logged-in
  Django user (`LoginRequiredMiddleware`; the login page is the only
  exception), and `uploaded_by` / `generated_by` / `AuditLog.user` now populate
  with that user. But there is still **no registration/SSO/password-reset flow,
  no roles or permissions, and no user↔organization membership model**. "The
  current organization" is resolved by `get_current_organization()` (oldest
  `Organization` row, created on demand if none exists); the "Team & Users"
  view shows only the authenticated user, with no invented role or status.

- **Demo data is present in `db.sqlite3`.** The checked-in database contains
  ~5 uploads, ~221 parsed alerts, ~115 incidents, ~114 gap findings, ~11
  reports, ~51 AI runs. It also still contains a stray second organization
  named `"T"` from an earlier test-contamination incident; the canonical
  resolver ignores it, but it will show up in the Django admin. Start from a
  fresh DB for anything real.

- **The `run_log_analysis_pipeline` orchestrator and the six "module registry"
  agents are a design sketch, not live code.** `apps/ai_core/orchestrator.py::
  run_log_analysis_pipeline`, `apps/ai_core/registry.py`, the
  `modules/{loglens,signalsort,riskscope,readyguard,playbookpilot,briefbuilder}
  .py` files, and `apps/ai_core/prompts/` + `apps/ai_core/schemas/` belong to
  it. They have no callers, build in-memory dicts that are never persisted, and
  are incompatible with the current model schema. The live pipeline is
  `run_demo_log_workflow` in the same file, and the live agents are the nine
  listed in §2. `OpenAIProvider` is likewise a placeholder.

- **`staticfiles/` is stale** (build artifacts from mid-2025). Dev and tests
  serve from `static/`, so this only matters for a real deployment, which would
  need `collectstatic`.

- **Top-level scaffold leftovers.** `core/`, `services/`, `models.py`,
  `views.py`, `urls.py`, `orchestrator.py`, `admin.py`, `forms.py`, and the
  loose `*.html` files at the project root are from an earlier project layout.
  Nothing in `config/` or `apps/` imports them; only `apps/` is on
  `INSTALLED_APPS`.

- **Sanitizer residual risk (accepted, documented in the module).** A person
  name or username that appears *only* in free prose — matching no structured
  DB value and no tight regex — can still reach the Anthropic API. General
  name/username NER over prose is explicitly out of scope.

---

## 5. Key design decisions

### The Sanitizer sits inside the provider layer, not per-context-builder

Pseudonymization runs once, inside `AnthropicProvider.send_message()`, rather
than being called by each of the nine context builders. Putting it at the
single choke point every prompt already passes through means a future agent
module physically cannot send an un-sanitized prompt — there is no code path to
Claude that skips it. A per-builder helper would rely on every new builder
remembering to call it, and the failure mode (a raw prompt leaking real IPs and
hostnames to a third party) is exactly the one worth making structurally
impossible. The cost is that `send_message` needs the `organization` to seed its
dictionary of real values, so all nine modules pass `organization=...`.

### Rate limiting is DB-backed against `AIRun`, not cache-based

The limiter (`apps/ai_core/rate_limit.py`) counts rows in the `AIRun` table over
rolling time windows (`COUNT(*) WHERE created_at >= now - window`). `AIRun`
already gets one row per AI call, written just before the provider call, so
there is nothing new to maintain and no new dependency. A cache-based counter
was rejected because the default `LocMemCache` is per-gunicorn-worker — four
workers would each independently allow the full quota, silently 4×-ing the real
limit. A shared cache backend (Redis/Memcached) would fix that but is
infrastructure this project doesn't otherwise need. The DB count is exact,
worker-count-independent, and already indexed (`airun_created_at_desc_idx`).
Because there is no auth and one tenant, the windows are keyed on time alone.
Rejections are themselves written as `AIRun` FAILED rows (so every denial is
audited like a real failure) and count toward the window — deliberately sticky.
`demo_log_workflow` rows are excluded since that pipeline makes no model call.

### Organization resolution was unified into one shared function

`apps/organizations/services/current_organization.py::get_current_organization()`
is the single way any "ambient, whole-app summary" page resolves which
organization it is about. Previously half a dozen places each guessed
independently — some took the oldest `Organization`, others sniffed whichever
upload/incident/finding/report was most recently touched. The sniffing approach
is fragile: a single stray or test row belonging to a different organization
(the `"T"` contamination in §4) could silently hijack an entire page's
org-scoped data, which is exactly what happened to the Work Queue Overview
panel. One canonical resolver (oldest row, created with sane defaults if the DB
is empty) removed that whole class of bug. Pages already scoped to a specific
record (e.g. one uploaded file) keep using that record's own `.organization` —
that is a real request-driven scope, not a guess.

### Context builders return plain text, and error handling collapses to `RuntimeError`

Prompts are assembled as human-readable Markdown-ish sections rather than JSON,
because the model reasons over them directly and a developer needs to be able to
read exactly what was sent. And every provider-side failure — transport,
HTTP status, malformed body, empty response, missing key — is normalized to a
single `RuntimeError` type so that each view has exactly one `except` path and
the user never sees a raw 500.
