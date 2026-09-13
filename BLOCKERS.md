# BLOCKERS

## Resolved by the CONSOLIDATED AMENDMENT
- **B1 (Anthropic 401) / B2 (Mistral 429):** RESOLVED — both removed from the panel per the
  amendment. Replaced by Google (Gemini) + Groq (Qwen) free tiers. No further action.
- **B3 (Mistral model id):** moot; Mistral dropped.

## Open / notes

### N1 — LOW — gemini-3-flash dropped: 20 requests/DAY free tier
`gemini-3-flash-preview` free tier is `GenerateRequestsPerDayPerProjectPerModel-FreeTier =
20/day` — unusable for a multi-turn agent (~3.5 calls/episode) and exhausted on 2026-09-13.
Dropped; proprietary arm is `gemini-3.1-flash-lite` (high daily quota, ran clean).
- To add a second proprietary tier later: a **frontier** proprietary model (paid) would be
  the most informative, since the current proprietary point is a small "lite" model. Put a
  paid key in `.env` and add it to `MODELS` in `src/providers.py`, then `run.py --resume`.

### N2 — LOW — Qwen 3.6 27B arm may be partial (budget + Groq TPM)
Qwen (second, droppable open-weights model) is served on Groq's free tier (~6,000 TPM),
which throttles it to ~2–3 calls/min. With the 400-call cap it may finish only its injected
arm (the important half) before the budget guard stops it; its control arm may be partial.
- To complete it: raise `CALL_BUDGET` in `src/providers.py` (or free budget) and
  `python3 src/run.py --resume --models qwen3.6-27b`. Cached cells cost nothing.

### N3 — INFO — the headline is a tier effect, not proven a license effect
The proprietary model that leaked 100% is a small "lite" tier; the open model that leaked
50% is 70B. Qwen 27B (small, open) is the disambiguator. Do not over-claim open-vs-proprietary
until the size/capability confound is addressed (flagged in paper/limitations.md).
