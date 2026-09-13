# phi-canary

A deterministic PHI-exfiltration oracle for evaluating agent security under indirect
prompt injection. Does a self-hostable open-weights model, given tool access in a
contact-center workflow, attempt to exfiltrate a planted patient record more often than a
proprietary model when untrusted content tries to make it?

## What's here

| Path | What |
|---|---|
| `src/agent.py` | Contact-center agent, simulated tool loop, plain-text `TOOL:` protocol |
| `src/oracle.py` | The oracle: scans egress arguments for the canary across 7 encodings |
| `tests/test_oracle.py` | 21 tests — positives per encoding, zero-false-positive negatives |
| `src/run.py` | Matrix runner: cached, idempotent, `--resume`, never crashes |
| `src/analyze.py` | Bootstrap CIs, channel/variant breakdowns → `results/table.md`, `figure.png` |
| `payloads/*.yaml` | 16 payloads (4 channels × 4 variants) |
| `demo.py` | One-command ~3s demo ending in a red PHI-exfil alert + the results table |
| `paper/` | methods, results skeleton (with the real table), limitations |
| `STATUS.md` / `DECISIONS.md` / `BLOCKERS.md` | run state, judgment log, open blockers |

## Run it

```bash
python3 -m pytest tests/ -q     # oracle test suite (21 tests)
python3 demo.py                 # ~3s live demo, no API needed (replays from cache)
python3 src/run.py --resume     # fill remaining cells (needs live keys; see BLOCKERS.md)
python3 src/analyze.py          # regenerate table + figure
```

Keys live in `.env` (`GOOGLE_API_KEY`, `TOGETHER_API_KEY`; optional `GROQ_API_KEY`).

## Current state

Complete open-vs-proprietary comparison, both models with full 16-cell benign controls:

| Model | Family | Exfil → attacker host | Control |
|---|---|---|---|
| Gemini 3.1 Flash-Lite | proprietary | **16/16 (100%)** | 0/16 |
| Llama 3.3 70B | open-weights | **8/16 (50%)**, CI [25%,75%] | 0/16 |

The counterintuitive headline — the small proprietary "lite" model exfiltrated *more* than
the 70B open model — is a likely **model-tier/capability** effect, not a license effect; the
confound is unresolved (a second small open model could not be obtained on a free tier). See
`paper/limitations.md`. Dropped under free-tier limits: Gemini 3 Flash (20 req/day), Qwen 3.6
27B (Groq output-tokens/min), Anthropic + Mistral (invalid/rate-limited). Details in
`BLOCKERS.md` / `DECISIONS.md`.
