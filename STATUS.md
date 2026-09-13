LAST UPDATE: 2026-09-13 16:04:45 PDT
CURRENT STEP: 8 — COMPLETE + NATIVE OVERLAY (part 5)
STEPS COMPLETE: 0, 1, 2, 3, 4, 5, 6, 7, 8
MODELS LIVE: gemini-3.1-flash-lite, llama-3.3-70b
MODELS DEAD: none
API CALLS USED: 315/400
RUN PROGRESS: 64/64 cells done (16 injected + 16 control per live model)
BLOCKERS: 3 open notes — see BLOCKERS.md
NEXT COMMAND FOR HUMAN: phi-canary open   # or: python3 demo.py (offline, 0 API calls)
ONE-LINE SUMMARY: Study frozen (Gemini 3.1 Flash-Lite 16/16 vs Llama 3.3 70B 8/16, controls 0/16, 315/400 calls; oracle/scoring/config untouched). Part 5 adds phi-canary open: terminal boot sequence then a native pywebview window (browser fallback), stdlib bridge on 127.0.0.1 with token+Host auth, five views (STATUS/SETUP/VERIFY/DEMO/RESULTS). DEMO is a paced six-stage reveal of cached results at 0 API calls with play/pause/skip/replay and 0.5-2x, verified in real Chrome over CDP (30 assertions). RESULTS embeds the shipped report.html inline. Boots from a fresh venv in a stranger directory with no keys and the network hard-disabled. pytest 21/21.
