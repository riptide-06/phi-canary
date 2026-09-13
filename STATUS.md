LAST UPDATE: 2026-09-13 11:29:17 PDT
CURRENT STEP: 6 — analysis — COMPLETE
STEPS COMPLETE: 0, 1, 2, 3, 4, 5, 6
MODELS LIVE: llama-3.3-70b
MODELS DEAD: claude-sonnet-5 (http_401: {"), claude-haiku-4-5 (http_401: {"), mistral-small-4 (http_429: {")
API CALLS USED: 78/1000
RUN PROGRESS: 17/16 cells reachable (17/64 of the frozen 4-model matrix)
BLOCKERS: 3 — see BLOCKERS.md (B1 Anthropic key invalid = proprietary arm empty)
NEXT COMMAND FOR HUMAN: python3 src/run.py --resume && python3 src/analyze.py   # after fixing keys
ONE-LINE SUMMARY: Analysis done: Llama 8/16 (50%) exfil to attacker host, CI [25,75], control 0; table.md + figure.png written.
