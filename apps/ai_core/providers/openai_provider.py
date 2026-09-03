import os
from typing import Any


class OpenAIProvider:
    """Placeholder provider used to keep AI integration out of the scaffold."""

    provider_name = "openai"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def build_request_payload(self, prompt_name: str, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "provider": self.provider_name,
            "prompt_name": prompt_name,
            "configured": self.is_configured(),
            "payload": payload,
            "notes": [
                "Placeholder provider only.",
                "No outbound API calls are made in this scaffold.",
            ],
        }
