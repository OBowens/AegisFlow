AI_RUN_METADATA_SCHEMA = {
    "schema": "ai_run_metadata",
    "description": "Shared trace metadata for a single AI module execution.",
    "fields": {
        "ai_module": "Friendly AI module name.",
        "input_type": "Type of object used as input.",
        "input_reference": "File path, primary key, or external reference.",
        "output_type": "Type of structured output created.",
        "status": "Run lifecycle status such as placeholder, success, or failed.",
        "model_used": "Reserved for future provider/model tracking.",
        "prompt_version": "Reserved prompt version marker.",
        "created_at": "Timestamp for the module run.",
    },
}
