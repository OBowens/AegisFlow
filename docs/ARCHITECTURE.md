# AegisFlow AI Architecture Scaffold

## Purpose
AegisFlow AI is an AI-powered cyber resilience workflow that helps small teams turn uploaded logs, alerts, and operational context into prioritized incidents, risk findings, disaster-readiness concerns, response playbooks, and manager-ready reports.

This scaffold keeps AegisFlow AI as a Django monolith while separating domain apps, AI workflow code, private file storage, public frontend assets, and documentation.

## Folder structure
```text
Caribsecure/
├── config/
├── apps/
│   ├── core/
│   ├── accounts/
│   ├── organizations/
│   ├── log_intake/
│   ├── incidents/
│   ├── risk/
│   ├── resilience/
│   ├── playbooks/
│   ├── reports/
│   ├── ai_core/
│   └── audit/
├── templates/
├── static/
├── private_uploads/
├── private_exports/
├── sample_data/
├── docs/
└── runtime_logs/
```

## App responsibilities
- `apps/log_intake` handles uploaded logs and future normalized event ingestion.
- `apps/ai_core` contains AI modules, prompts, schemas, providers, and the orchestrator.
- `apps/incidents` stores alert triage, grouped incidents, and supporting evidence workflows.
- `apps/risk` stores gap findings and risk assessments.
- `apps/resilience` stores disaster readiness findings and continuity guidance.
- `apps/playbooks` stores response playbooks and SOP checklist workflows.
- `apps/reports` stores generated reports and export-oriented report views.
- `apps/audit` stores user activity tracking and AI run history.

## Storage rules
- `private_uploads` stores uploaded log files and should never be publicly served.
- `private_exports` stores generated reports and should never be publicly served.
- `static` stores only frontend assets such as CSS, JavaScript, and images.
- `templates` stores shared templates and layout building blocks.

## AI workflow
The placeholder orchestrator runs modules in this order:

1. `AegisFlow AI · LogLens`
2. `AegisFlow AI · SignalSort`
3. `AegisFlow AI · RiskScope`
4. `AegisFlow AI · ReadyGuard`
5. `AegisFlow AI · PlaybookPilot`
6. `AegisFlow AI · BriefBuilder`

The current scaffold only defines contracts, inputs, and outputs. No external AI provider is called yet.
