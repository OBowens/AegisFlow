LOG_LENS = "LOG_LENS"
SIGNAL_SORT = "SIGNAL_SORT"
RISK_SCOPE = "RISK_SCOPE"
READY_GUARD = "READY_GUARD"
PLAYBOOK_PILOT = "PLAYBOOK_PILOT"
BRIEF_BUILDER = "BRIEF_BUILDER"


MODULE_REGISTRY = {
    LOG_LENS: {
        "display_name": "LogLens AI",
        "module": "apps.ai_core.modules.loglens",
        "class": "LogLensModule",
        "callable": "analyze_upload",
        "prompt": "apps/ai_core/prompts/loglens.md",
        "schema": "apps/ai_core/schemas/loglens_schema.py",
    },
    SIGNAL_SORT: {
        "display_name": "SignalSort AI",
        "module": "apps.ai_core.modules.signalsort",
        "class": "SignalSortModule",
        "callable": "triage_and_group",
        "prompt": "apps/ai_core/prompts/signalsort.md",
        "schema": "apps/ai_core/schemas/signalsort_schema.py",
    },
    RISK_SCOPE: {
        "display_name": "RiskScope AI",
        "module": "apps.ai_core.modules.riskscope",
        "class": "RiskScopeModule",
        "callable": "assess_risk",
        "prompt": "apps/ai_core/prompts/riskscope.md",
        "schema": "apps/ai_core/schemas/riskscope_schema.py",
    },
    READY_GUARD: {
        "display_name": "ReadyGuard AI",
        "module": "apps.ai_core.modules.readyguard",
        "class": "ReadyGuardModule",
        "callable": "assess_readiness",
        "prompt": "apps/ai_core/prompts/readyguard.md",
        "schema": "apps/ai_core/schemas/readyguard_schema.py",
    },
    PLAYBOOK_PILOT: {
        "display_name": "PlaybookPilot AI",
        "module": "apps.ai_core.modules.playbookpilot",
        "class": "PlaybookPilotModule",
        "callable": "generate_playbook",
        "prompt": "apps/ai_core/prompts/playbookpilot.md",
        "schema": "apps/ai_core/schemas/playbook_schema.py",
    },
    BRIEF_BUILDER: {
        "display_name": "BriefBuilder AI",
        "module": "apps.ai_core.modules.briefbuilder",
        "class": "BriefBuilderModule",
        "callable": "generate_report",
        "prompt": "apps/ai_core/prompts/briefbuilder.md",
        "schema": "apps/ai_core/schemas/report_schema.py",
    },
}


def get_registered_module(module_key: str) -> dict:
    return MODULE_REGISTRY[module_key]
