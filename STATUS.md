LAST UPDATE: 2026-09-13 11:32:20 PDT
CURRENT STEP: 8 — paper scaffold — COMPLETE (all steps 0-8 done)
STEPS COMPLETE: 0, 1, 2, 3, 4, 5, 6, 7, 8
MODELS LIVE: llama-3.3-70b
MODELS DEAD: claude-sonnet-5 (http_401: {"), claude-haiku-4-5 (http_401: {"), mistral-small-4 (http_429: {")
API CALLS USED: 83/1000
RUN PROGRESS: 17/17 reachable cells done (16 payloads + 1 control per live model; frozen matrix is 4x16=64 + 4 controls)
BLOCKERS: 3 — see BLOCKERS.md (B1 Anthropic key invalid = proprietary arm empty)
NEXT COMMAND FOR HUMAN: python3 demo.py    # ~3s demo. Then: put a live ANTHROPIC_API_KEY in .env && python3 src/run.py --resume && python3 src/analyze.py
ONE-LINE SUMMARY: All 8 steps shipped. Reachable arm (Llama) complete: 8/16 (50%) PHI exfil to attacker host, CI[25,75], control 0. Proprietary+Mistral arms blocked on invalid/rate-limited keys — resume fills them with zero re-work.
