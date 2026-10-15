"""Model APIs, called with urllib: Anthropic's Messages API and OpenRouter's
OpenAI-compatible chat completions.

Each client has one method, `complete(system, user, max_tokens)`, which
returns a `Completion`: the text, the model that answered, the tokens, the
cost when the API reports it, and the successful call's time (`ms`).
`gen_ms` includes failed HTTP attempts and backoff; `attempts` counts them.

The key comes only from the environment: ANTHROPIC_API_KEY or
OPENROUTER_API_KEY. The client validates it at startup and keeps it in
memory to send in the request's header. It is never written to logs or
the store, and configured keys are redacted from error messages.
"""
from __future__ import annotations

import json
import math
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from .attempts import Attempt, Ledger

# Local injection points keep tests off the network and real clock.
_clock = time.monotonic
_sleep = time.sleep
_open = urllib.request.urlopen

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

    def __init__(self, message: str, ledger: Ledger | None = None):
        super().__init__(redact(message))
        self.ledger = ledger


def _key(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise Error(f"{name} is not set")
    if any(not 0x21 <= ord(c) <= 0x7e for c in value):
        raise Error(f"{name} holds characters an HTTP header cannot carry")
    return value


def redact(text: str) -> str:
    """Replace configured keys with their variable names before logging."""
    keys = {value: f"<{name}>" for name in ("OPENROUTER_API_KEY", "ANTHROPIC_API_KEY")
            if (value := os.environ.get(name))}
    if not keys:
        return text
    pattern = "|".join(re.escape(value) for value in sorted(keys, key=len, reverse=True))
    return re.sub(pattern, lambda match: keys[match.group()], text)


def describe(err: BaseException) -> str:
    """Describe an exception without configured keys, for logs and errors."""
    return redact(f"{type(err).__name__}: {err}")


@dataclass
class Completion:
    """One answer: `ms` is its call time; `gen_ms` includes HTTP retries."""
    text: str
    model: str
    input_tokens: int | None
    output_tokens: int | None
    cost: float | None  # US dollars, when the API reports it
    ms: int
    cut_off: bool = False  # the answer stopped at max_tokens
    gen_ms: int | None = None
    attempts: int = 1
    backoff_ms: int = 0


def _usage(answer: dict, attempt: Attempt) -> None:
    """Keep reported usage; missing or invalid amounts remain unknown."""
    model = answer.get("model")
    if isinstance(model, str) and model:
        attempt.model = model
    usage = answer.get("usage")
    if not isinstance(usage, dict):
        return
    for name, alias in (("input_tokens", "prompt_tokens"), ("output_tokens", "completion_tokens")):
        value = usage.get(name, usage.get(alias))
        if type(value) is int and value >= 0:
            setattr(attempt, name, value)
    cost = usage.get("cost")
    if (type(cost) is int or type(cost) is float and math.isfinite(cost)) and cost >= 0:
        attempt.cost = cost


def _post(url: str, headers: dict[str, str], body: dict, timeout: float, what: str,
          ledger: Ledger) -> tuple[dict, Attempt]:
    """POST JSON, keeping each attempt's call time and the backoff spent.

    The ledger spans the first start through return or raise. Retryable
    failures get at most three attempts, with no backoff after the last.
    """
    data = json.dumps(body).encode()
    failure = ""
    for index in range(1, 4):
        request = urllib.request.Request(url, data=data, method="POST", headers=headers)
        attempt = Attempt(ledger.ask, index, ledger.clock(), 0, "transport", body["model"])
        ledger.attempts.append(attempt)
        retry = True
        try:
            with _open(request, timeout=timeout) as r:
                answer = json.loads(r.read())
            if not isinstance(answer, dict):
                raise ValueError("model response is not an object")
            _usage(answer, attempt)
            attempt.outcome = "ok"
            return answer, attempt
        except urllib.error.HTTPError as err:
            attempt.outcome = f"http {err.code}"
            with err:
                raw = err.read()
            detail = redact(raw.decode("utf-8", "replace")).encode("utf-8")
            failure = f"HTTP {err.code}: {detail[:400].decode('utf-8', 'replace')}"
            try:
                answer = json.loads(raw)
            except (ValueError, UnicodeError) as invalid:
                failure += f" (unreadable error response: {describe(invalid)})"
            else:
                if isinstance(answer, dict):
                    _usage(answer, attempt)
            retry = err.code in RETRY
        except (ValueError, UnicodeError) as err:
            attempt.outcome = "unreadable"
            failure = describe(err)
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            failure = describe(err)
        finally:
            attempt.ended = ledger.clock()
            if attempt.outcome != "ok":
                attempt.error = failure
            ledger.finish()
        if not retry or index == 3:
            break
        started = ledger.clock()
        try:
            _sleep(1.5 * index)
        finally:
            attempt.backoff_ms = round((ledger.clock() - started) * 1000)
            ledger.finish()
    raise Error(f"{what} failed: {failure}", ledger)


def _completion(text: str, cut_off: bool, attempt: Attempt, ledger: Ledger) -> Completion:
    attempt.raw, attempt.cut_off = text, cut_off
    ledger.finish()
    usage = ledger.usage()
    return Completion(text, attempt.model, attempt.input_tokens, attempt.output_tokens, attempt.cost,
                      attempt.ms, cut_off, usage["gen_ms"], usage["attempts"], usage["backoff_ms"])


class Anthropic:
    provider = "anthropic"

    def __init__(self, model: str = "", timeout: float = 120.0):
        self._key = _key("ANTHROPIC_API_KEY")
        self.model = model or DEFAULT_MODELS["anthropic"]
        self.timeout = timeout

    def complete(self, system: str, user: str, max_tokens: int, *, ledger: Ledger | None = None) -> Completion:
        ledger = ledger if ledger is not None else Ledger(_clock)
        headers = {"x-api-key": self._key, "anthropic-version": "2023-06-01",
                   "content-type": "application/json"}
        body = {"model": self.model, "max_tokens": max_tokens, "temperature": 1.0, "system": system,
                "messages": [{"role": "user", "content": user}]}
        answer, attempt = _post(ANTHROPIC_URL, headers, body, self.timeout, f"Anthropic {self.model}", ledger)
        try:
            text = "".join(b.get("text", "") for b in answer.get("content", []) if b.get("type") == "text")
        except (AttributeError, TypeError) as err:
            attempt.outcome = "unreadable"
            attempt.error = redact(f"Anthropic {self.model}: unreadable response")
            raise Error(attempt.error, ledger) from err
        return _completion(text, answer.get("stop_reason") == "max_tokens", attempt, ledger)


class OpenRouter:
    provider = "openrouter"

    def __init__(self, model: str = "", timeout: float = 120.0):
        self._key = _key("OPENROUTER_API_KEY")
        self.model = model or DEFAULT_MODELS["openrouter"]
        self.timeout = timeout
        # Reasoning models think before they write unless told not to,
        # which costs time. ADAPTIVE_WEB_REASONING sets the effort
        # ("minimal", "low", ...); unset, the model's default applies.
        self.reasoning = os.environ.get("ADAPTIVE_WEB_REASONING", "")

    def complete(self, system: str, user: str, max_tokens: int, *, ledger: Ledger | None = None) -> Completion:
        ledger = ledger if ledger is not None else Ledger(_clock)
        headers = {"Authorization": f"Bearer {self._key}", "content-type": "application/json",
                   "X-Title": "Fictionet adaptive web"}
        body = {"model": self.model, "max_tokens": max_tokens, "temperature": 1.0,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "usage": {"include": True},
                # The fastest provider that serves the model, not the cheapest.
                "provider": {"sort": "throughput"}}
        if self.reasoning:
            body["reasoning"] = {"effort": self.reasoning}
        answer, attempt = _post(OPENROUTER_URL, headers, body, self.timeout, f"OpenRouter {self.model}", ledger)
        if "error" in answer:
            attempt.outcome = "unreadable"
            detail = redact(json.dumps(answer["error"]))[:400]
            attempt.error = redact(f"OpenRouter {self.model} failed: {detail}")
            raise Error(attempt.error, ledger)
        try:
            choices = answer.get("choices") or [{}]
            text = (choices[0].get("message") or {}).get("content") or ""
            if not isinstance(text, str):
                raise TypeError("model content is not text")
            cut_off = choices[0].get("finish_reason") == "length"
        except (AttributeError, TypeError, KeyError) as err:
            attempt.outcome = "unreadable"
            attempt.error = redact(f"OpenRouter {self.model}: unreadable response")
            raise Error(attempt.error, ledger) from err
        return _completion(text, cut_off, attempt, ledger)


def client(provider: str, model: str = "") -> Anthropic | OpenRouter:
    """The client for `provider` ("anthropic" or "openrouter")."""
    if provider == "anthropic":
        return Anthropic(model)
    if provider == "openrouter":
        return OpenRouter(model)
    raise Error(f"no model provider named {provider!r}")
