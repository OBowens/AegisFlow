from apps.audit.models import AIRun, AuditLog
from apps.incidents.services.grouping import group_alerts_for_upload
from apps.ai_core.modules import (
    analyze_upload,
    assess_readiness,
    assess_risk,
    generate_playbook,
    generate_report,
    triage_and_group,
)
from apps.ai_core.registry import (
    BRIEF_BUILDER,
    LOG_LENS,
    MODULE_REGISTRY,
    PLAYBOOK_PILOT,
    READY_GUARD,
    RISK_SCOPE,
    SIGNAL_SORT,
)
from apps.log_intake.models import UploadedLogFile
from apps.log_intake.services.parser import parse_uploaded_log
from apps.playbooks.services.generator import create_playbooks_for_incidents
from apps.reports.services.generator import create_manager_report_for_upload
from apps.resilience.services.readiness import create_readiness_findings_for_risks
from apps.risk.services.assessment import create_risk_findings_for_incidents


def run_log_analysis_pipeline(
    uploaded_file_path: str,
    source_type: str | None = None,
    organization_context: dict | None = None,
) -> dict:
    organization_context = organization_context or {}
    critical_systems = organization_context.get("critical_systems", [])

    loglens_result = analyze_upload(uploaded_file_path, source_type=source_type)
    parsed_alerts = loglens_result["output"].get("parsed_alerts", [])

    signalsort_result = triage_and_group(
        parsed_alerts,
        critical_systems=critical_systems,
    )
    incident_groups = signalsort_result["output"].get("incident_groups", [])

    riskscope_result = assess_risk(
        incident_groups,
        context={
            "organization_context": organization_context,
            "parsed_alert_count": len(parsed_alerts),
        },
    )
    risk_assessments = riskscope_result["output"].get("risk_assessments", [])

    readyguard_result = assess_readiness(
        risk_assessments,
        organization_context=organization_context,
    )
    readiness_findings = readyguard_result["output"].get("readiness_findings", [])

    primary_incident = incident_groups[0] if incident_groups else {"title": "No incident grouped yet"}
    playbookpilot_result = generate_playbook(
        primary_incident,
        risks=risk_assessments,
        readiness_findings=readiness_findings,
    )

    analysis_bundle = {
        "module": "CaribSecure Analysis Pipeline",
        "status": "placeholder",
        "input_summary": {
            "uploaded_file_path": uploaded_file_path,
            "source_type": source_type or "auto-detect",
            "critical_system_count": len(critical_systems),
        },
        "pipeline_order": [
            LOG_LENS,
            SIGNAL_SORT,
            RISK_SCOPE,
            READY_GUARD,
            PLAYBOOK_PILOT,
            BRIEF_BUILDER,
        ],
        "registry": MODULE_REGISTRY,
        "results": {
            LOG_LENS: loglens_result,
            SIGNAL_SORT: signalsort_result,
            RISK_SCOPE: riskscope_result,
            READY_GUARD: readyguard_result,
            PLAYBOOK_PILOT: playbookpilot_result,
        },
    }

    briefbuilder_result = generate_report(analysis_bundle, report_type="manager")
    analysis_bundle["results"][BRIEF_BUILDER] = briefbuilder_result
    analysis_bundle["output"] = {
        "parsed_alerts": parsed_alerts,
        "incident_groups": incident_groups,
        "risk_assessments": risk_assessments,
        "readiness_findings": readiness_findings,
        "playbook": playbookpilot_result["output"],
        "report": briefbuilder_result["output"],
    }

    return analysis_bundle


def run_demo_log_workflow(uploaded_log_file: UploadedLogFile) -> dict:
    workflow_run = AIRun.objects.create(
        organization=uploaded_log_file.organization,
        ai_module="demo_log_workflow",
        input_type="UploadedLogFile",
        input_id=str(uploaded_log_file.id),
        output_type="GeneratedReport",
        output_id="",
        status=AIRun.Status.STARTED,
    )
    errors = []

    try:
        uploaded_log_file.status = UploadedLogFile.Status.PARSING
        uploaded_log_file.save(update_fields=["status"])

        parsed_alerts = parse_uploaded_log(uploaded_log_file)
        uploaded_log_file.refresh_from_db()
        if uploaded_log_file.status == UploadedLogFile.Status.FAILED:
            raise RuntimeError("Placeholder parser could not process the uploaded file.")

        uploaded_log_file.status = UploadedLogFile.Status.PARSED
        uploaded_log_file.save(update_fields=["status"])

        incidents = group_alerts_for_upload(uploaded_log_file)
        risks = create_risk_findings_for_incidents(incidents)
        readiness_findings = create_readiness_findings_for_risks(risks)
        playbooks = create_playbooks_for_incidents(incidents)
        report = create_manager_report_for_upload(uploaded_log_file)

        workflow_run.output_id = str(report.id)
        workflow_run.status = AIRun.Status.SUCCESS
        workflow_run.save(update_fields=["output_id", "status"])

        AuditLog.objects.create(
            organization=uploaded_log_file.organization,
            user=uploaded_log_file.uploaded_by,
            action="demo_log_workflow_completed",
            target_type="UploadedLogFile",
            target_id=str(uploaded_log_file.id),
            details=(
                f"Parsed alerts={len(parsed_alerts)}, incidents={len(incidents)}, "
                f"risks={len(risks)}, readiness findings={len(readiness_findings)}, "
                f"playbooks={len(playbooks)}, report_id={report.id}."
            ),
        )

        return {
            "uploaded_file_id": uploaded_log_file.id,
            "parsed_alerts": len(parsed_alerts),
            "incidents": len(incidents),
            "risks": len(risks),
            "readiness_findings": len(readiness_findings),
            "playbooks": len(playbooks),
            "report_id": report.id,
            "status": "success",
            "errors": [],
        }
    except Exception as exc:
        uploaded_log_file.status = UploadedLogFile.Status.FAILED
        uploaded_log_file.save(update_fields=["status"])
        errors.append(str(exc))
        workflow_run.status = AIRun.Status.FAILED
        workflow_run.error_message = str(exc)
        workflow_run.save(update_fields=["status", "error_message"])

        AuditLog.objects.create(
            organization=uploaded_log_file.organization,
            user=uploaded_log_file.uploaded_by,
            action="demo_log_workflow_failed",
            target_type="UploadedLogFile",
            target_id=str(uploaded_log_file.id),
            details=str(exc),
        )

        return {
            "uploaded_file_id": uploaded_log_file.id,
            "parsed_alerts": 0,
            "incidents": 0,
            "risks": 0,
            "readiness_findings": 0,
            "playbooks": 0,
            "report_id": None,
            "status": "failed",
            "errors": errors,
        }
