"""Regenerate STATUS.md from on-disk state. Usage: status.py <step> <name> <next_cmd> <summary>"""
import json, pathlib, sys, time
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import providers as P

ROOT = P.ROOT
STEPS = {0:"provider smoke test",1:"agent loop",2:"the oracle",3:"payload corpus",
         4:"runner",5:"full run",6:"analysis",7:"demo",8:"paper scaffold"}

def main():
    step = int(sys.argv[1]); name = sys.argv[2]; nxt = sys.argv[3]; summary = sys.argv[4]
    smoke = {}
    sp = ROOT/"results"/"smoke.json"
    if sp.exists(): smoke = json.loads(sp.read_text())
    live = [k for k,v in smoke.items() if v.get("live")]
    dead = [f"{k} ({(v.get('error') or '')[:12]})" for k,v in smoke.items() if not v.get("live")]
    raw = ROOT/"results"/"raw.jsonl"
    cells = sum(1 for _ in raw.open()) if raw.exists() else 0
    total = len(live)*17 if live else 68  # 16 payloads + 1 control per model
    blockers = 0
    bp = ROOT/"BLOCKERS.md"
    if bp.exists(): blockers = bp.read_text().count("\n## B")
    (ROOT/"STATUS.md").write_text(f"""LAST UPDATE: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}
CURRENT STEP: {step} — {name}
STEPS COMPLETE: {', '.join(str(i) for i in range(step+1))}
MODELS LIVE: {', '.join(live) if live else 'NONE'}
MODELS DEAD: {', '.join(dead) if dead else 'none'}
API CALLS USED: {P.calls_used()}/{P.CALL_BUDGET}
RUN PROGRESS: {cells}/{total} reachable cells done (16 payloads + 1 control per live model; frozen matrix is 4x16=64 + 4 controls)
BLOCKERS: {blockers} — see BLOCKERS.md (B1 Anthropic key invalid = proprietary arm empty)
NEXT COMMAND FOR HUMAN: {nxt}
ONE-LINE SUMMARY: {summary}
""")
    print((ROOT/"STATUS.md").read_text())

if __name__ == "__main__":
    main()
