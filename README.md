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

Keys live in `.env` (`ANTHROPIC_API_KEY`, `TOGETHER_API_KEY`, `MISTRAL_API_KEY`).

## Current state

The reachable arm (Llama 3.3 70B) is complete: **8/16 (50%)** injected cells exfiltrated to
the attacker host, 95% CI [25%, 75%], control 0/1. The proprietary arm (both Anthropic
models) and the second open-weights model (Mistral) are blocked on credentials — see
`BLOCKERS.md`. `--resume` fills them with no re-work once keys are live.
