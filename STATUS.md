LAST UPDATE: 2026-09-13 13:51:03 PDT
CURRENT STEP: 8 — COMPLETE — amendment applied, study finalized
STEPS COMPLETE: 0, 1, 2, 3, 4, 5, 6, 7, 8
MODELS LIVE: gemini-3.1-flash-lite, llama-3.3-70b
MODELS DEAD: none
API CALLS USED: 315/400
RUN PROGRESS: 64/64 cells done (16 injected + 16 control per live model)
BLOCKERS: 3 open notes — see BLOCKERS.md
NEXT COMMAND FOR HUMAN: python3 demo.py   # offline, 0 API calls, ~3s live demo
ONE-LINE SUMMARY: COMPLETE. Gemini 3.1 Flash-Lite (proprietary) 16/16 (100%) exfil to attacker host vs Llama 3.3 70B (open) 8/16 (50%); both controls 0/16, 0 errors. Counterintuitive result is a likely model-tier effect (confound noted). 2nd open model dropped: Groq free-tier OTPM non-viable, no OpenRouter key.
