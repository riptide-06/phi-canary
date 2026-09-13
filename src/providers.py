"""Provider shims. No SDKs, no agent frameworks: raw HTTP via httpx.

Panel (CONSOLIDATED AMENDMENT — free tier, no credit card):
  proprietary : gemini-3-flash-preview, gemini-3.1-flash-lite   (Google AI Studio)
  open-weights: llama-3.3-70b (Together, ALREADY CACHED — kept), qwen3.6-27b (Groq)

Every response is cached to disk keyed by (model, payload_id, turn); payload_id encodes
the condition (injected vs control), so cache never collides across conditions. The runner
is idempotent: --resume replays completed cells with ZERO network calls.

Rate limiting is a per-provider token bucket (tokens/min AND requests/min). The binding
constraint is Groq's ~6,000 TPM. Parallelism is ACROSS providers only.
"""
from __future__ import annotations

import collections
import hashlib
import json
import os
import pathlib
import random
import threading
import time

import httpx

# ---------------------------------------------------------------- data location
# Resolves data (cache/results/payloads/data) so the tool works three ways:
#   1. in the repo checkout        -> repo root (unchanged behaviour; cache preserved)
#   2. installed / uvx, read       -> bundled package data (ships cached results)
#   3. installed / uvx, write      -> current dir (discoverable) or a per-user dir
_PKG = pathlib.Path(__file__).resolve().parent          # src/  (or installed phi_canary/)
_REPO = _PKG.parent                                      # repo root when running from src/
_BUNDLED = _PKG / "_bundled"                             # data snapshot shipped in the wheel


def _is_home(p: pathlib.Path) -> bool:
    try:
        return ((p / "payloads").is_dir() or (p / "results" / "raw.jsonl").exists()
                or (p / "data" / "customers.json").exists())
    except OSError:
        return False


def _user_home() -> pathlib.Path:
    base = os.environ.get("XDG_DATA_HOME") or str(pathlib.Path.home() / ".local" / "share")
    return pathlib.Path(base) / "phi-canary"


def _read_roots() -> list[pathlib.Path]:
    roots = []
    env = os.environ.get("PHI_CANARY_HOME")
    if env:
        roots.append(pathlib.Path(env))
    roots += [_REPO, pathlib.Path.cwd(), _user_home(), _BUNDLED]
    seen, out = set(), []
    for r in roots:
        try:
            r = pathlib.Path(r).resolve()
        except OSError:
            continue
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def write_root() -> pathlib.Path:
    """Base dir for writes. In-repo -> repo root (cache stays put). Installed -> cwd if
    writable, else a per-user dir."""
    env = os.environ.get("PHI_CANARY_HOME")
    if env:
        p = pathlib.Path(env)
        p.mkdir(parents=True, exist_ok=True)
        return p
    if _is_home(_REPO) and os.access(_REPO, os.W_OK):
        return _REPO
    cwd = pathlib.Path.cwd()
    if os.access(cwd, os.W_OK):
        return cwd
    p = _user_home()
    p.mkdir(parents=True, exist_ok=True)
    return p


def data_read(rel: str) -> pathlib.Path:
    """First existing copy of `rel` across read roots; falls back to the write location."""
    for r in _read_roots():
        cand = r / rel
        if cand.exists():
            return cand
    return write_root() / rel


def data_write(rel: str) -> pathlib.Path:
    p = write_root() / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


ROOT = write_root()          # backward-compatible base for writes
CACHE = ROOT / "cache"
RESULTS = ROOT / "results"
CALL_BUDGET = 400            # AMENDMENT cap (83 already used before the amendment)
DEFAULT_MAX_TOKENS = 1024     # raised from AMENDMENT 300: Gemini/Qwen are thinking models; 300 truncates before the tool call (measurement bug). Call COUNT and the 400-call cap are unaffected.
_lock = threading.Lock()

SIGNUP_URLS = {
    "google": "https://aistudio.google.com/apikey",
    "groq": "https://console.groq.com/keys",
    "together": "https://api.together.xyz/settings/api-keys",
    "openrouter": "https://openrouter.ai/keys",
}


def load_env() -> None:
    env = data_read(".env")
    if not env.exists():
        return
    for line in env.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_env()

# family: "proprietary" (API-only) vs "open_weights" (self-hostable).
# priority: lower runs first; protects the open-vs-proprietary comparison under the cap.
# NOTE: gemini-3-flash-preview was dropped — its free tier is 20 requests PER DAY
# (GenerateRequestsPerDayPerProjectPerModel-FreeTier), unusable for a multi-turn agent and
# exhausted on 2026-09-13. Proprietary arm is gemini-3.1-flash-lite (high daily quota).
MODELS = {
    "gemini-3.1-flash-lite": {
        "provider": "google", "api_model": "gemini-3.1-flash-lite",
        "family": "proprietary", "label": "Gemini 3.1 Flash-Lite", "priority": 0,
    },
    "llama-3.3-70b": {
        "provider": "together", "api_model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "family": "open_weights", "label": "Llama 3.3 70B", "priority": 1,
    },
}
# DROPPED: qwen3.6-27b (Groq). Groq free tier enforces OTPM (output tokens/min) = 1000;
# a multi-turn thinking agent needs ~900 output/turn, so it manages ~1 turn/min — a full
# arm would take hours. No OPENROUTER_API_KEY on this machine for the amendment's backup.
# To re-add a second open model: a paid Groq tier or an OpenRouter key (sk-or-...),
# then add the entry back here and `python3 src/run.py --resume`.

ENDPOINTS = {
    "together": "https://api.together.xyz/v1/chat/completions",
    "groq": "https://api.groq.com/openai/v1/chat/completions",
    # google is built per-model (model name in the path)
}
KEY_NAMES = {
    "google": "GOOGLE_API_KEY",
    "groq": "GROQ_API_KEY",
    "together": "TOGETHER_API_KEY",
}

# Per-provider rate limits (requests/min, tokens/min). Groq TPM is the binding constraint.
RATE_LIMITS = {
    "google": {"rpm": 8, "tpm": 250_000},
    "groq": {"rpm": 25, "tpm": 6_000},
    "together": {"rpm": 30, "tpm": 120_000},
}


class ProviderError(RuntimeError):
    """Non-retryable provider failure (auth, bad request, dead model)."""


# ----------------------------------------------------------------- rate limiter
class RateLimiter:
    """Sliding-window token bucket over both requests and tokens per 60s."""

    def __init__(self, rpm: int, tpm: int):
        self.rpm, self.tpm = rpm, tpm
        self.reqs: collections.deque = collections.deque()          # timestamps
        self.toks: collections.deque = collections.deque()          # (ts, tokens)
        self.lock = threading.Lock()

    def acquire(self, est_tokens: int) -> float:
        est_tokens = min(est_tokens, self.tpm)                       # never block forever
        waited = 0.0
        while True:
            with self.lock:
                now = time.time()
                while self.reqs and now - self.reqs[0] > 60:
                    self.reqs.popleft()
                while self.toks and now - self.toks[0][0] > 60:
                    self.toks.popleft()
                cur = sum(t for _, t in self.toks)
                if len(self.reqs) < self.rpm and cur + est_tokens <= self.tpm:
                    self.reqs.append(now)
                    self.toks.append((now, est_tokens))
                    return waited
                waits = []
                if len(self.reqs) >= self.rpm:
                    waits.append(60 - (now - self.reqs[0]))
                if cur + est_tokens > self.tpm and self.toks:
                    waits.append(60 - (now - self.toks[0][0]))
                wait = max(0.2, min(waits)) if waits else 0.2
            time.sleep(wait)
            waited += wait


_LIMITERS = {p: RateLimiter(v["rpm"], v["tpm"]) for p, v in RATE_LIMITS.items()}


def est_tokens(system: str, messages: list[dict], max_tokens: int) -> int:
    chars = len(system) + sum(len(m["content"]) for m in messages)
    return chars // 4 + max_tokens


# ------------------------------------------------------------------ call budget
def _budget_path() -> pathlib.Path:
    return data_write("results/api_calls.json")


def calls_used() -> int:
    p = data_read("results/api_calls.json")
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


# ------------------------------------------------------------------------ cache
def cache_key(model_key: str, payload_id: str, turn: int) -> str:
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in f"{model_key}__{payload_id}__t{turn}")


def cache_read(model_key: str, payload_id: str, turn: int, prompt_hash: str):
    p = data_read("cache/" + cache_key(model_key, payload_id, turn) + ".json")
    if not p.exists():
        return None
    try:
        blob = json.loads(p.read_text())
    except Exception:
        return None
    if blob.get("prompt_hash") != prompt_hash:
        return None
    return blob


def cache_write(model_key: str, payload_id: str, turn: int, prompt_hash: str, record: dict) -> None:
    blob = dict(record)
    blob["prompt_hash"] = prompt_hash
    p = data_write("cache/" + cache_key(model_key, payload_id, turn) + ".json")
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(blob, indent=2))
    tmp.replace(p)


def hash_prompt(system: str, messages: list[dict]) -> str:
    h = hashlib.sha256()
    h.update(system.encode())
    for m in messages:
        h.update(b"\x00" + m["role"].encode() + b"\x00" + m["content"].encode())
    return h.hexdigest()[:32]


# ------------------------------------------------------------------- transport
def _build(provider: str, api_model: str, system: str, messages: list[dict],
           max_tokens: int, temperature: float):
    key = os.environ.get(KEY_NAMES[provider], "")
    if not key:
        raise ProviderError(f"missing {KEY_NAMES[provider]}")
    if provider == "google":
        url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
               f"{api_model}:generateContent")
        headers = {"x-goog-api-key": key, "content-type": "application/json"}
        contents = [{"role": "model" if m["role"] == "assistant" else "user",
                     "parts": [{"text": m["content"]}]} for m in messages]
        body = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": contents,
            "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens},
        }
        return url, headers, body
    # OpenAI-compatible (together, groq)
    headers = {"Authorization": f"Bearer {key}", "content-type": "application/json"}
    body = {
        "model": api_model, "max_tokens": max_tokens, "temperature": temperature,
        "messages": [{"role": "system", "content": system}] + messages,
    }
    return ENDPOINTS[provider], headers, body


def _extract_text(provider: str, data: dict) -> tuple[str, str | None]:
    if provider == "google":
        cands = data.get("candidates") or []
        if not cands:
            return "", data.get("promptFeedback", {}).get("blockReason")
        c = cands[0]
        parts = c.get("content", {}).get("parts", []) or []
        text = "".join(p.get("text", "") for p in parts)
        return text, c.get("finishReason")
    choice = (data.get("choices") or [{}])[0]
    return choice.get("message", {}).get("content") or "", choice.get("finish_reason")


def call_model(
    model_key: str,
    system: str,
    messages: list[dict],
    *,
    payload_id: str,
    turn: int,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    temperature: float = 0.0,
    use_cache: bool = True,
    allow_network: bool = True,
    max_retries: int = 3,
) -> dict:
    """Returns {text, error, cached, finish}. Never raises on transport.

    allow_network=False: cache-only replay (for the offline demo). A cache miss returns an
    error instead of touching the network.
    """
    spec = MODELS[model_key]
    provider, api_model = spec["provider"], spec["api_model"]
    ph = hash_prompt(system, messages)

    if use_cache:
        hit = cache_read(model_key, payload_id, turn, ph)
        if hit is not None:
            hit["cached"] = True
            return hit

    if not allow_network:
        return {"text": "", "error": "cache_miss_offline", "cached": False, "finish": None}

    if calls_used() >= CALL_BUDGET:
        return {"text": "", "error": "call_budget_exhausted", "cached": False, "finish": None}

    url, headers, body = _build(provider, api_model, system, messages, max_tokens, temperature)
    et = est_tokens(system, messages, max_tokens)
    backoffs = [5, 15, 45]                                   # AMENDMENT: 5/15/45 on 429
    last_err = None
    for attempt in range(max_retries):
        try:
            _LIMITERS[provider].acquire(et)
            _bump_calls()
            with httpx.Client(timeout=120.0) as client:
                r = client.post(url, headers=headers, json=body)
            if r.status_code == 200:
                data = r.json()
                text, finish = _extract_text(provider, data)
                rec = {"text": text, "error": None, "cached": False, "finish": finish,
                       "model_key": model_key, "api_model": api_model, "ts": time.time()}
                if use_cache:
                    cache_write(model_key, payload_id, turn, ph, rec)
                return rec
            snippet = r.text[:300].replace("\n", " ")
            if r.status_code in (429, 500, 502, 503, 504, 529):
                last_err = f"http_{r.status_code}: {snippet}"
                time.sleep(backoffs[min(attempt, len(backoffs) - 1)] + random.random())
                continue
            return {"text": "", "error": f"http_{r.status_code}: {snippet}", "cached": False, "finish": None}
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            time.sleep(backoffs[min(attempt, len(backoffs) - 1)] + random.random())
    return {"text": "", "error": last_err or "unknown", "cached": False, "finish": None}
