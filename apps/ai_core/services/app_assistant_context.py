"""Static, versioned reference material for the general App Assistant
(Part H) -- what the AegisFlow AI application itself does: navigation,
the guided incident workflow, and terminology. Unlike every other
*_context.py in this package, this is NOT built from live
organization/incident data -- it's the same fixed text for every
question, which is exactly what keeps it safe to answer from: there is
nothing here to fabricate specifics about.

Bump APP_ASSISTANT_CORPUS_VERSION whenever the corpus text changes.
apps.ai_core.modules.app_assistant stamps every AIRun with it (via
AIRun.prompt_version) so a past answer can be traced back to the
corpus revision that produced it.
"""

APP_ASSISTANT_CORPUS_VERSION = "1"

APP_ASSISTANT_CORPUS = """
# AegisFlow AI -- App Reference

## What this is
AegisFlow AI is a security operations platform for small/medium
organizations. It ingests security log data, correlates it into
incidents, and guides a user through investigating and responding to
each one, alongside a disaster-readiness assessment and a library of
standard operating procedures.

## Navigation
- **Home** -- the main dashboard: priority incidents, recent activity,
  and current risk snapshot.
- **Work Queue** -- the list of open incidents, filterable by
  severity/status, each with a "Start Investigation" action into the
  guided workflow below.
- **Upload Data** -- upload raw security log files (firewall, auth,
  monitoring exports, etc.) for AegisFlow to parse into alerts and
  correlate into incidents.
- **Readiness** -- an organization-wide disaster-readiness score
  broken down by domain (e.g. backups, access control), with gaps and
  recommended next steps.
- **SOP Library** -- standard operating procedure checklists for
  common response scenarios (SOC-mode only).
- **Reports** -- generate and view technical or incident reports for a
  specific incident.
- **Audit History** -- the log of every AI call the system has made
  (which module, when, success/failure, which model) plus other
  recorded activity, exportable as CSV.
- **Organization** -- your organization's own profile (name, sector,
  country, risk profile) and critical systems list.
- **Settings** -- manage critical systems and organization-level
  configuration.

## The guided incident workflow
Opening an incident from the Work Queue starts a six-stage guided
response:
1. **Overview** -- a summary of the incident, its evidence, affected
   system, and current risk before starting.
2. **Understand** -- what AegisFlow found: the correlated evidence
   groups, affected system, and timeline, with an option to explain it
   more simply.
3. **Verify** -- a set of AI-suggested verification questions specific
   to this incident. Each question shows an evidence-tier badge:
   "Evidence Available" when a real, on-hand data source (like linked
   authentication alerts or a source-IP correlation to other
   incidents) actually backs that specific question, or "Manual check
   required" when nothing in the app's own data can speak to it and a
   human has to check something outside the app (e.g. calling the
   system owner, checking a change calendar). Each question also has a
   "Show me how" explainer with the exact steps to check it yourself.
4. **Respond** -- the AI-generated response playbook: an ordered list
   of actions to take, each trackable to a status (pending, in
   progress, done, skipped), with some actions flagged as requiring
   human approval before they're performed.
5. **Resolve** -- an outcome check: is the issue resolved, partially
   resolved, still happening, or unclear? This decides whether the
   incident moves to Close or loops back to Respond.
6. **Close** -- a final review of the incident record (summary,
   response actions taken, evidence retained) before marking it
   closed. Closed incidents remain visible in Audit History and
   Reports.

At most workflow stages, an "AegisFlow recommends" panel offers an
AI-generated suggested next step for that specific stage -- it has to
be generated on demand (a button click), it does not appear
automatically on page load.

## Key terms
- **Evidence tier** -- shown as a pill on each Verify-stage question:
  "Evidence Available" (a real data source backs this exact question
  for this exact incident) or "Manual check required" (no such source
  exists; a human must check outside the app).
- **AI confidence pill** -- shown on some incident cards, reflecting
  how confident the AI correlation was that the linked evidence
  belongs to that incident.
- **Severity pill** -- an incident's severity level (e.g. critical,
  high, medium, low).
- **AI Run / Audit History** -- every AI-generated action (analysis,
  explanation, playbook step, question answered) is logged as an AI
  Run: which module made the call, when, whether it succeeded, and
  which model was used. Viewable and exportable from Audit History.
- **Experience Mode** -- a display preference (Business or SOC),
  switchable from the profile menu. Business Mode favors simple
  explanations and guided actions; SOC Mode surfaces more technical
  evidence and analyst tools (e.g. the SOP Library nav item is
  SOC-mode only).

## Other AI features in this app
Besides this general assistant, AegisFlow has four other "Ask
AegisFlow" question boxes, each scoped to one specific thing and able
to see only that thing's real data:
- On an incident's own page: questions about that specific incident.
- On an incident's workflow stage: questions about that stage's
  current recommended step.
- On a specific detected risk/gap: questions about that risk.
- On the Readiness page: questions about the organization's overall
  disaster-readiness score.

This assistant does not have access to any organization's live
incident, risk, or readiness data. If a question is about a specific
incident, alert, risk, or score, the right place to ask it is that
item's own "Ask AegisFlow" box, not here.
""".strip()


def build_app_assistant_context() -> str:
    return APP_ASSISTANT_CORPUS
