# NOT WIRED UP -- placeholder/design-sketch only. LogLensModule.analyze_upload
# never reads the uploaded file; it fabricates one fake alert per call. Zero
# callers outside the dead apps.ai_core.orchestrator.run_log_analysis_pipeline,
# and its output schema is incompatible with the current ParsedAlert model
# (see the 2026-08-24 investigation). Do not extend without re-reading that
# note first -- the real, live parsing lives in apps/log_intake/services/*.

from pathlib import Path


class LogLensModule:
    module_name = "LogLens AI"

    def analyze_upload(self, uploaded_file_path: str, source_type: str | None = None) -> dict:
        source_hint = source_type or "auto-detect"
        file_name = Path(uploaded_file_path).name if uploaded_file_path else "unknown"
        return {
            "module": self.module_name,
            "status": "placeholder",
            "input_summary": {
                "uploaded_file_path": uploaded_file_path,
                "source_type": source_hint,
            },
            "output": {
                "normalized_source_type": source_hint,
                "parsed_alerts": [
                    {
                        "source_tool": source_hint,
                        "event_type": "placeholder_event",
                        "affected_system": "unknown_system",
                        "timestamp": None,
                        "severity_clue": "review_needed",
                        "raw_message": f"Placeholder parsing output for {file_name}.",
                    }
                ],
                "normalization_notes": [
                    "Source detection is scaffolded only.",
                    "Field extraction rules will be added in the next step.",
                ],
            },
            "confidence": 0.2,
            "notes": [
                "Use this placeholder to define the upload contract before connecting parsers.",
            ],
        }


def analyze_upload(uploaded_file_path: str, source_type: str | None = None) -> dict:
    return LogLensModule().analyze_upload(uploaded_file_path, source_type=source_type)
