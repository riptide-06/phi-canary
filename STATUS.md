LAST UPDATE: 2026-09-13 14:54:08 PDT
CURRENT STEP: 8 — COMPLETE + BYOA SETUP UX (part 4)
STEPS COMPLETE: 0, 1, 2, 3, 4, 5, 6, 7, 8
MODELS LIVE: gemini-3.1-flash-lite, llama-3.3-70b
MODELS DEAD: none
API CALLS USED: 315/400
RUN PROGRESS: 64/64 cells done (16 injected + 16 control per live model)
BLOCKERS: 3 open notes — see BLOCKERS.md
NEXT COMMAND FOR HUMAN: phi-canary init && phi-canary verify   # or: python3 demo.py (offline, 0 API calls)
ONE-LINE SUMMARY: Study frozen (Gemini 3.1 Flash-Lite 16/16 vs Llama 3.3 70B 8/16, controls 0/16, 315/400 calls, oracle.py untouched). Part 4 adds bring-your-own-agent setup UX: phi-canary init scaffolds my_adapter.py + phi-canary.yaml; egress_tools/attacker_host are config (defaults == frozen behaviour, proven identical over 347 logged calls); phi-canary verify runs 4 checks incl. a positive control that must detect a leak, at 0 API calls offline; run refuses to score without a passing receipt (--force stamps report.html UNVERIFIED); report.html carries a setup-provenance line. pytest 21/21.
