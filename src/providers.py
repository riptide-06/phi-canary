"""Provider shims. No SDKs, no agent frameworks: raw HTTP via httpx.

Every response is cached to disk keyed by (model, payload_id, turn) so the run
survives suspend/resume. Call budget is tracked in results/api_calls.json.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import random
import threading
import time

import httpx

ROOT = pathlib.Path(__file__).resolve().parent.parent
CACHE = ROOT / "cache"
RESULTS = ROOT / "results"
CALL_BUDGET = 1000
_lock = threading.Lock()


def load_env() -> None:
    env = ROOT / ".env"
    if not env.exists():
        return
    for line in env.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_env()

# family: "proprietary" (API-only) vs "open_weights" (self-hostable)
MODELS = {
    "claude-sonnet-5": {
        "provider": "anthropic",
        "api_model": "claude-sonnet-5",
        "family": "proprietary",
        "label": "Claude Sonnet 5",
    },
    "claude-haiku-4-5": {
        "provider": "anthropic",
        "api_model": "claude-haiku-4-5-20251001",
        "family": "proprietary",
        "label": "Claude Haiku 4.5",
    },
    "llama-3.3-70b": {
        "provider": "together",
        "api_model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "family": "open_weights",
        "label": "Llama 3.3 70B",
    },
    "mistral-small-4": {
        "provider": "mistral",
        "api_model": "mistral-small-latest",
        "family": "open_weights",
        "label": "Mistral Small 4",
    },
}

ENDPOINTS = {
    "anthropic": "https://api.anthropic.com/v1/messages",
    "together": "https://api.together.xyz/v1/chat/completions",
    "mistral": "https://api.mistral.ai/v1/chat/completions",
}
KEY_NAMES = {
    "anthropic": "ANTHROPIC_API_KEY",
    "together": "TOGETHER_API_KEY",
    "mistral": "MISTRAL_API_KEY",
}


class ProviderError(RuntimeError):
    """Non-retryable provider failure (auth, bad request, dead model)."""


# ---------------------------------------------------------------- call budget
def _budget_path() -> pathlib.Path:
    RESULTS.mkdir(parents=True, exist_ok=True)
    return RESULTS / "api_calls.json"


def calls_used() -> int:
    p = _budget_path()
    if not p.exists():
        return 0
    try:
        return int(json.loads(p.read_text())["calls"])
    except Exception:
        return 0


def _bump_calls() -> int:
    with _lock:
        n = calls_used() + 1
        _budget_path().write_text(json.dumps({"calls": n}))
        return n


# --------------------------------------------------------------------- cache
def cache_key(model_key: str, payload_id: str, turn: int) -> str:
    safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in f"{model_key}__{payload_id}__t{turn}")
    return safe


def cache_read(model_key: str, payload_id: str, turn: int, prompt_hash: str):
    p = CACHE / (cache_key(model_key, payload_id, turn) + ".json")
    if not p.exists():
        return None
    try:
        blob = json.loads(p.read_text())
    except Exception:
        return None
    if blob.get("prompt_hash") != prompt_hash:
        return None  # conversation diverged; recompute
    return blob


def cache_write(model_key: str, payload_id: str, turn: int, prompt_hash: str, record: dict) -> None:
    CACHE.mkdir(parents=True, exist_ok=True)
    blob = dict(record)
    blob["prompt_hash"] = prompt_hash
    p = CACHE / (cache_key(model_key, payload_id, turn) + ".json")
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(blob, indent=2))
    tmp.replace(p)


def hash_prompt(system: str, messages: list[dict]) -> str:
    h = hashlib.sha256()
    h.update(system.encode())
    for m in messages:
        h.update(b"\x00" + m["role"].encode() + b"\x00" + m["content"].encode())
    return h.hexdigest()[:32]


# ---------------------------------------------------------------------- call
def _build(provider: str, api_model: str, system: str, messages: list[dict], max_tokens: int, temperature: float):
    key = os.environ.get(KEY_NAMES[provider], "")
    if not key:
        raise ProviderError(f"missing {KEY_NAMES[provider]}")
    if provider == "anthropic":
        headers = {"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"}
        body = {
            "model": api_model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system,
            "messages": messages,
        }
    else:
        headers = {"Authorization": f"Bearer {key}", "content-type": "application/json"}
        body = {
            "model": api_model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "system", "content": system}] + messages,
        }
    return ENDPOINTS[provider], headers, body


def _extract_text(provider: str, data: dict) -> str:
    if provider == "anthropic":
        return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
    return (data.get("choices") or [{}])[0].get("message", {}).get("content") or ""


def call_model(
    model_key: str,
    system: str,
    messages: list[dict],
    *,
    payload_id: str,
    turn: int,
    max_tokens: int = 900,
    temperature: float = 0.0,
    use_cache: bool = True,
    max_retries: int = 3,
) -> dict:
    """Returns {text, error, cached, calls_used, finish}. Never raises on transport."""
    spec = MODELS[model_key]
    provider, api_model = spec["provider"], spec["api_model"]
    ph = hash_prompt(system, messages)

    if use_cache:
        hit = cache_read(model_key, payload_id, turn, ph)
        if hit is not None:
            hit["cached"] = True
            return hit

    if calls_used() >= CALL_BUDGET:
        return {"text": "", "error": "call_budget_exhausted", "cached": False, "finish": None}

    url, headers, body = _build(provider, api_model, system, messages, max_tokens, temperature)
    last_err = None
    for attempt in range(max_retries):
        try:
            _bump_calls()
            with httpx.Client(timeout=120.0) as client:
                r = client.post(url, headers=headers, json=body)
            if r.status_code == 200:
                data = r.json()
                rec = {
                    "text": _extract_text(provider, data),
                    "error": None,
                    "cached": False,
                    "finish": data.get("stop_reason") or (data.get("choices") or [{}])[0].get("finish_reason"),
                    "model_key": model_key,
                    "api_model": api_model,
                    "usage": data.get("usage"),
                    "ts": time.time(),
                }
                if use_cache:
                    cache_write(model_key, payload_id, turn, ph, rec)
                return rec
            snippet = r.text[:400].replace("\n", " ")
            if r.status_code in (429, 500, 502, 503, 504, 529):
                last_err = f"http_{r.status_code}: {snippet}"
                time.sleep(min(2 ** attempt * 2 + random.random(), 20))
                continue
            return {"text": "", "error": f"http_{r.status_code}: {snippet}", "cached": False, "finish": None}
        except Exception as e:  # transport
            last_err = f"{type(e).__name__}: {e}"
            time.sleep(min(2 ** attempt * 2 + random.random(), 20))
    return {"text": "", "error": last_err or "unknown", "cached": False, "finish": None}
