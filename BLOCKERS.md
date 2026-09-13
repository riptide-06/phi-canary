# BLOCKERS

## B1 — CRITICAL — Anthropic API key is invalid. The proprietary arm of the study is empty.

Both Anthropic models (claude-sonnet-5, claude-haiku-4-5-20251001) return
`HTTP 401 {"type":"authentication_error","message":"API key is invalid."}`.

Keys tried (both 401):
- `~/Desktop/PersonalResearch/cx-llm-bench/.env` -> ANTHROPIC_API_KEY (sk-ant-api03-Q0GE7...)
- `~/Desktop/ACLsmith/.env.local` -> VITE_ANTHROPIC_API_KEY (sk-ant-api03-zICQa...)

**Impact:** the headline comparison (self-hostable open-weights vs proprietary) has no
proprietary side. What exists is the open-weights arm only.

**Recommended answer:** mint a fresh key at console.anthropic.com, put it in
`/Users/tarun/Documents/phi-canary/.env` as `ANTHROPIC_API_KEY=sk-ant-...`, then run
`python3 src/run.py --resume`. Cached Llama cells are skipped; only the 32 Anthropic
cells run. Cost ~32-190 calls, roughly 6 minutes. Then `python3 src/analyze.py`.

## B2 — HIGH — Mistral account is out of quota.

`HTTP 429 {"code":"1300","message":"Rate limit exceeded"}` on every attempt, including
after a 20s pause and 3 backoff retries. This is account-level, not burst.

**Impact:** second open-weights model missing. The open-weights arm is Llama-only, so
"open-weights models" generalizes from n=1 model family.

**Recommended answer:** if a paid Mistral workspace is available, swap the key and
`python3 src/run.py --resume`. Otherwise report the study as 1 open-weights model and
soften the claim in the paper to "a self-hostable model" rather than "open-weights models".

## B3 — LOW — "Mistral Small 4" API model id unverified.

Registry uses `mistral-small-latest`. Could not confirm which concrete snapshot that
resolves to because every call is rate-limited before reaching the model. If the key is
fixed, confirm the snapshot in the response body and pin it in `src/providers.py`.
