import http.client
import json
import os
import urllib.error
import urllib.request
from typing import Any

from apps.ai_core.sanitizer import sanitize_for_ai

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_API_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-sonnet-5"
# Long-form outputs (all five report types, the prioritizer briefing,
# multi-paragraph analyses) were truncating mid-sentence at 1024. 4096 is
# comfortably inside every current Claude model's output ceiling.
DEFAULT_MAX_TOKENS = 4096
DEFAULT_TIMEOUT_SECONDS = 60

# Realistic transport-level failures that urllib does NOT surface as a
# urllib.error.URLError: a read/response timeout (urllib only wraps
# *connect-phase* OSErrors in URLError), a connection reset or broken
# pipe, a remote disconnect, a truncated body. These otherwise propagate
# as bare TimeoutError / ConnectionError / http.client.HTTPException and
# blow past every caller's `except RuntimeError`.
_TRANSPORT_ERRORS = (
    TimeoutError,
    ConnectionError,  # ConnectionResetError, BrokenPipeError, RemoteDisconnected, ...
    http.client.IncompleteRead,
    http.client.HTTPException,  # BadStatusLine, LineTooLong, ...
)


class AnthropicProvider:
    """Real Anthropic Messages API client.

    NOTE on the OpenAIProvider it's modeled after (apps/ai_core/providers/
    openai_provider.py): that provider is a no-op scaffold placeholder --
    it never makes a network call and never raises on a missing key, it
    just returns a descriptive dict. This provider is not that: it makes a
    real HTTP request and raises a clear error if ANTHROPIC_API_KEY isn't
    set, per this feature's requirements.
    """

    provider_name = "anthropic"

    def __init__(self, api_key: str | None = None, model: str | None = None) -> None:
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model or os.environ.get("ANTHROPIC_MODEL", DEFAULT_MODEL)

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def send_message(
        self,
        prompt: str,
        *,
        organization=None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> str:
        """Send `prompt` as a single user message and return Claude's text
        response.

        The prompt is run through `sanitize_for_ai` first, so real
        identifiers (IPs, hostnames, usernames, emails, file paths, the
        org's own name) are replaced with `[[TYPE_n]]` placeholder tokens
        before anything leaves the process; the model's reply is
        rehydrated back to the real values before this method returns, so
        callers and stored data are unaffected. `organization` seeds the
        dictionary of known real values -- pass it whenever the caller has
        one. See apps/ai_core/sanitizer.py.

        Every realistic failure -- a missing API key, a non-200 response,
        a DNS/connection error, a read timeout, a reset connection, a body
        that isn't the JSON shape we expect, or an empty response -- is
        raised as a plain RuntimeError so that every caller's existing
        `except RuntimeError` / _friendly_*_error path handles it and the
        user never sees a raw 500.
        """
        if not self.is_configured():
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Configure it in the environment "
                "before calling AnthropicProvider.send_message()."
            )

        sanitized = sanitize_for_ai(prompt, organization=organization)

        request_body = json.dumps(
            {
                "model": self.model,
                "max_tokens": max_tokens,
                "messages": [{"role": "user", "content": sanitized.text}],
            }
        ).encode("utf-8")

        request = urllib.request.Request(
            ANTHROPIC_API_URL,
            data=request_body,
            method="POST",
            headers={
                "content-type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": ANTHROPIC_API_VERSION,
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw_body = response.read()
            payload = json.loads(raw_body.decode("utf-8"))
            text = _extract_text(payload)
        except urllib.error.HTTPError as exc:
            error_detail = exc.read().decode("utf-8", errors="ignore")
            raise RuntimeError(
                f"Anthropic API request failed ({exc.code}): {error_detail}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Anthropic API request failed: {exc.reason}") from exc
        except _TRANSPORT_ERRORS as exc:
            raise RuntimeError(f"Anthropic API request failed: {exc!r}") from exc
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError(
                f"Anthropic API returned an unreadable response: {exc}"
            ) from exc
        except (AttributeError, TypeError, KeyError, IndexError) as exc:
            raise RuntimeError(
                f"Anthropic API returned an unexpected response shape: {exc!r}"
            ) from exc

        text = sanitized.restore(text)

        if not text or not text.strip():
            raise RuntimeError("Anthropic API returned an empty response.")

        return text


def _extract_text(response_body: dict[str, Any]) -> str:
    content_blocks = response_body.get("content", [])
    text_blocks = [
        block.get("text", "") for block in content_blocks if block.get("type") == "text"
    ]
    return "".join(text_blocks)
