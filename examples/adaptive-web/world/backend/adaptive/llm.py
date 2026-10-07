"""Model APIs, called with urllib: Anthropic's Messages API and OpenRouter's
OpenAI-compatible chat completions.

Each client has one method, `complete(system, user, max_tokens)`, which
returns a `Completion`: the text, the model that answered, the tokens, the
cost when the API reports it, and the time the call took.

The key comes only from the environment: ANTHROPIC_API_KEY or
OPENROUTER_API_KEY. It goes into the request's header and nowhere else. It
is never logged or stored, and no error message carries it.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

DEFAULT_MODELS = {
    "anthropic": "claude-haiku-4-5-20251001",
    "openrouter": "google/gemini-3.1-flash-lite",
}

# Answers worth trying again: rate limits and overloaded or failing servers.
RETRY = (408, 429, 500, 502, 503, 504, 529)


class Error(RuntimeError):
    """A model call that failed: what was asked of whom, and why it failed."""


@dataclass
class Completion:
    text: str
    model: str
    input_tokens: int | None
    output_tokens: int | None
    cost: float | None  # US dollars, when the API reports it
    ms: int
    cut_off: bool = False  # the answer stopped at max_tokens


def _post(url: str, headers: dict[str, str], body: dict, timeout: float, what: str) -> tuple[dict, int]:
    """POSTs `body` as JSON. Returns the parsed answer and the milliseconds
    the successful call took. Tries three times on the answers in RETRY."""
    data = json.dumps(body).encode()
    failure = ""
    for attempt in range(3):
        started = time.monotonic()
        request = urllib.request.Request(url, data=data, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as r:
                answer = json.loads(r.read())
            return answer, round((time.monotonic() - started) * 1000)
        except urllib.error.HTTPError as err:
            failure = f"HTTP {err.code}: {err.read()[:400].decode('utf-8', 'replace')}"
            if err.code not in RETRY:
                break
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as err:
            failure = f"{type(err).__name__}: {err}"
        time.sleep(1.5 * (attempt + 1))
    raise Error(f"{what} failed: {failure}")


class Anthropic:
    provider = "anthropic"

    def __init__(self, model: str = "", timeout: float = 120.0):
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise Error("ANTHROPIC_API_KEY is not set")
        self.model = model or DEFAULT_MODELS["anthropic"]
        self.timeout = timeout

    def complete(self, system: str, user: str, max_tokens: int) -> Completion:
        headers = {"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01",
                   "content-type": "application/json"}
        body = {"model": self.model, "max_tokens": max_tokens, "temperature": 1.0, "system": system,
                "messages": [{"role": "user", "content": user}]}
        answer, ms = _post(ANTHROPIC_URL, headers, body, self.timeout, f"Anthropic {self.model}")
        text = "".join(b.get("text", "") for b in answer.get("content", []) if b.get("type") == "text")
        usage = answer.get("usage", {})
        return Completion(text, answer.get("model", self.model), usage.get("input_tokens"),
                          usage.get("output_tokens"), None, ms, answer.get("stop_reason") == "max_tokens")


class OpenRouter:
    provider = "openrouter"

    def __init__(self, model: str = "", timeout: float = 120.0):
        if not os.environ.get("OPENROUTER_API_KEY"):
            raise Error("OPENROUTER_API_KEY is not set")
        self.model = model or DEFAULT_MODELS["openrouter"]
        self.timeout = timeout
        # Reasoning models think before they write unless told not to,
        # which costs time. ADAPTIVE_WEB_REASONING sets the effort
        # ("minimal", "low", ...); unset, the model's default applies.
        self.reasoning = os.environ.get("ADAPTIVE_WEB_REASONING", "")

    def complete(self, system: str, user: str, max_tokens: int) -> Completion:
        headers = {"Authorization": f"Bearer {os.environ['OPENROUTER_API_KEY']}", "content-type": "application/json",
                   "X-Title": "Fictionet adaptive web"}
        body = {"model": self.model, "max_tokens": max_tokens, "temperature": 1.0,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "usage": {"include": True},
                # The fastest provider that serves the model, not the cheapest.
                "provider": {"sort": "throughput"}}
        if self.reasoning:
            body["reasoning"] = {"effort": self.reasoning}
        answer, ms = _post(OPENROUTER_URL, headers, body, self.timeout, f"OpenRouter {self.model}")
        if "error" in answer:
            raise Error(f"OpenRouter {self.model} failed: {json.dumps(answer['error'])[:400]}")
        choices = answer.get("choices") or [{}]
        text = (choices[0].get("message") or {}).get("content") or ""
        usage = answer.get("usage", {})
        return Completion(text, answer.get("model", self.model), usage.get("prompt_tokens"),
                          usage.get("completion_tokens"), usage.get("cost"), ms, choices[0].get("finish_reason") == "length")


def client(provider: str, model: str = "") -> Anthropic | OpenRouter:
    """The client for `provider` ("anthropic" or "openrouter")."""
    if provider == "anthropic":
        return Anthropic(model)
    if provider == "openrouter":
        return OpenRouter(model)
    raise Error(f"no model provider named {provider!r}")
