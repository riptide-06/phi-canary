LAST UPDATE: 2026-09-13 17:25:35 PDT
CURRENT STEP: 9 — COMPLETE + NATIVE OVERLAY + BRIEFING DECK (part 6)
STEPS COMPLETE: 0, 1, 2, 3, 4, 5, 6, 7, 8, 9
MODELS LIVE: gemini-3.1-flash-lite, llama-3.3-70b
MODELS DEAD: none
API CALLS USED: 315/400
RUN PROGRESS: 64/64 cells done (16 injected + 16 control per live model)
BLOCKERS: 3 open notes — see BLOCKERS.md
NEXT COMMAND FOR HUMAN: phi-canary open   # opens on BRIEFING; press → to walk the deck, then RUN DEMO
ONE-LINE SUMMARY: Study frozen (Gemini 3.1 Flash-Lite 16/16 vs Llama 3.3 70B 8/16, controls 0/16, 315/400 calls; oracle/scoring/config untouched). Part 5 adds phi-canary open: terminal boot sequence then a native pywebview window (browser fallback), stdlib bridge on 127.0.0.1 with token+Host auth, five views (STATUS/SETUP/VERIFY/DEMO/RESULTS). DEMO is a paced six-stage reveal of cached results at 0 API calls with play/pause/skip/replay and 0.5-2x, verified in real Chrome over CDP (30 assertions). RESULTS embeds the shipped report.html inline. Boots from a fresh venv in a stranger directory with no keys and the network hard-disabled. pytest 21/21. Part 6 adds a sixth view, BRIEFING (`phi-canary open --view about`, now the default): a 15-slide deck that explains the method before RUN DEMO, with the verbatim narration pinned under each slide, a 12-question FAQ and a presenter run sheet. Its numbers bind from the same /api/demo payload the replay uses (8/16, 16/16, 0/16, and the 9 real amber control cells), so the pitch cannot drift from the study; hard-coded fallbacks render if the bridge is unreachable. Keys: ←/→, S short path (10 slides), N narration, M motion, K/F/R jump-and-return, 1–6 views (the nav digits were decorative until now), F11/rail button fullscreen. Verified by driving real Chrome over CDP: 84 assertions, 0 page errors, every slide fits without scrolling at 1280×860 / 1440×900 / 1920×1080 (the two appendices scroll by design). pytest 21/21; artifacts/oracle_tests.txt regenerated (it still read 20).
