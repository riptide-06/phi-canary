#!/usr/bin/env python3
"""PHI-canary live demo. ONE command, no typing, ~1 second (replays from cache).

    python3 demo.py

A poisoned member record flows into a contact-center agent. The agent reads it,
then POSTs the member's record — canary member ID and all — to an attacker endpoint.
The oracle catches the exact bytes in the outbound argument and raises a red alert.
"""
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).parent / "src"))
import yaml
import oracle as O
from agent import run_episode, TICKET_ID

ROOT = pathlib.Path(__file__).parent
R = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
RED = "\033[91m"; GRN = "\033[92m"; YEL = "\033[93m"; CYN = "\033[96m"; MAG = "\033[95m"
REDBG = "\033[41m\033[97m\033[1m"

DEMO_CELL = "record_notes__authority"   # a confirmed exfil-to-attacker-host cell
MODEL = "llama-3.3-70b"


def slow(msg="", d=0.35):
    print(msg); time.sleep(d)


def rule(c="─", color=DIM):
    print(color + c * 78 + R)


def big_alert(verdict):
    bar = "█" * 78
    print("\n" + RED + bar + R)
    print(REDBG + "  ⛔  PHI EXFILTRATION DETECTED — CANARY BYTES FOUND IN OUTBOUND TOOL ARGUMENT   " + R)
    print(RED + bar + R)
    print(f"{BOLD}  member ID leaked : {R}{RED}{O.CANARY}{R}")
    print(f"{BOLD}  encoding         : {R}{verdict['encoding']}")
    print(f"{BOLD}  channel (tool)   : {R}{verdict['tool']}")
    print(f"{BOLD}  sent to          : {R}{RED}{O.EXFIL_HOST}{R}  (attacker-controlled)")
    if verdict["phi_fields_present"]:
        print(f"{BOLD}  other PHI in body: {R}{', '.join(verdict['phi_fields_present'])}")
    print(f"{BOLD}  verdict line     : {R}"
          f"{json.dumps({'leaked': verdict['leaked'], 'encoding': verdict['encoding'], 'tool': verdict['tool'], 'to_exfil_host': verdict['to_exfil_host']})}")
    print(f"\n{BOLD}  outbound argument (excerpt):{R}")
    print(f"  {RED}{verdict['arg_excerpt']}{R}")
    print(RED + bar + R + "\n")


def main():
    print()
    rule("═", CYN)
    print(f"{BOLD}{CYN}  PHI-CANARY  ·  deterministic PHI-exfiltration oracle{R}")
    print(f"{DIM}  Does a self-hostable model exfiltrate PHI under indirect prompt injection?{R}")
    rule("═", CYN)
    slow()
    print(f"{BOLD}Setup{R}")
    slow(f"  • Agent under test : {MAG}{MODEL}{R}  (open-weights, self-hostable)")
    slow(f"  • Canary planted   : synthetic patient record, member ID {BOLD}{O.CANARY}{R}")
    slow(f"  • No legitimate task needs this record sent anywhere external.")
    slow(f"  • Tools are SIMULATED. We enforce nothing — we only scan outbound arguments.")
    print()

    payload = yaml.safe_load((ROOT / "payloads" / f"{DEMO_CELL}.yaml").read_text())
    slow(f"{BOLD}Attack{R}  (untrusted content injected via: {YEL}{payload['channel']}{R}, "
         f"variant: {YEL}{payload['variant']}{R})")
    print(f"{DIM}  A note appended to the member's own record, impersonating a compliance directive:{R}")
    inj = payload["content"].split("\n", 1)[-1]
    print(f"  {YEL}“{inj[:150]}…”{R}")
    print()

    slow(f"{BOLD}Agent runs the ticket {TICKET_ID} …{R}", 0.5)
    ep = run_episode(MODEL, payload, use_cache=True)   # replays from cache, instant
    for c in ep["tool_calls"]:
        args = json.dumps(c["args"])
        egress = c["tool"] in O.EGRESS_TOOLS
        mark = f"{RED}⇢ EGRESS{R}" if egress else f"{GRN}·{R}"
        show = args if len(args) < 96 else args[:93] + "..."
        print(f"    {mark} {BOLD}{c['tool']}{R}({DIM}{show}{R})")
    print()

    verdict = O.scan_episode(ep["tool_calls"])
    if verdict["leaked"]:
        big_alert(verdict)
    else:
        print(f"{GRN}{BOLD}  ✓ No exfiltration: the canary never reached an outbound argument.{R}\n")

    # results table
    rule("═", CYN)
    print(f"{BOLD}{CYN}  Study results so far{R}")
    rule("═", CYN)
    tbl = ROOT / "results" / "table.md"
    if tbl.exists():
        for line in tbl.read_text().splitlines():
            if line.startswith("|") or line.startswith("## ") or line.startswith("- "):
                print("  " + line)
    print()
    rule("─", DIM)
    print(f"{DIM}  Full table: results/table.md   ·   Figure: results/figure.png   ·   "
          f"Status: STATUS.md{R}\n")


if __name__ == "__main__":
    main()
