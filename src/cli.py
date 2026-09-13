"""phi-canary command-line entry point.

    phi-canary run       run the study (auto-resumes from cache); --adapter to test your agent
    phi-canary report    regenerate report.html from cached results
    phi-canary demo      the offline cached demo (--live to call the model)
    phi-canary doctor    which provider keys are live + signup URLs

Works from any working directory and from bundled package data (see providers.data_read).
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # flat imports within pkg
import providers as P


def _doctor(argv) -> int:
    ap = argparse.ArgumentParser(prog="phi-canary doctor")
    ap.add_argument("--probe", action="store_true",
                    help="make a tiny live call per provider to confirm the key works "
                         "(costs a request; may consume a low daily quota)")
    args = ap.parse_args(argv)

    print("phi-canary doctor — provider keys\n")
    providers = {"google": "Gemini (proprietary)", "together": "Llama etc. (open-weights)",
                 "groq": "Qwen/GPT-OSS etc. (open-weights)"}
    any_missing = False
    live = {}
    if args.probe:
        import smoke  # runs the panel smoke test, writes results/smoke.json
        try:
            live = {P.MODELS[k]["provider"]: v["live"] for k, v in smoke.main().items()}
        except Exception as e:
            print(f"  (probe failed: {e})")
    for prov, desc in providers.items():
        key = os.environ.get(P.KEY_NAMES.get(prov, ""), "")
        present = bool(key)
        status = "SET " if present else "MISSING"
        if args.probe and prov in live:
            status += " · LIVE" if live[prov] else " · SET-BUT-DEAD"
        mark = "✓" if present else "✗"
        print(f"  {mark} {P.KEY_NAMES.get(prov,'?'):18s} {status:22s} {desc}")
        if not present:
            any_missing = True
            print(f"      → get one: {P.SIGNUP_URLS.get(prov)}")
    print("\nNote: `demo` and `report` work with NO keys (they replay bundled cached results).")
    print("Keys are only needed for a live `run`.")
    if any_missing:
        print("\nSome keys are missing (that is fine for demo/report).")
    return 0  # doctor never fails a pipeline — it is informational


def _run(argv) -> int:
    ap = argparse.ArgumentParser(prog="phi-canary run")
    ap.add_argument("--adapter", help="path to your AgentAdapter .py, or 'reference'")
    ap.add_argument("--resume", action="store_true", help="skip cached cells (built-in study)")
    ap.add_argument("--models", default="", help="comma list (built-in study)")
    ap.add_argument("--reprobe", action="store_true", help="re-run the provider smoke test first")
    ap.add_argument("--offline", action="store_true",
                    help="adapter mode: replay from cache only, no network")
    args = ap.parse_args(argv)

    if args.adapter:
        from adapters.base import load_adapter, evaluate_adapter, ContactCenterAdapter
        adapter = (ContactCenterAdapter(allow_network=not args.offline)
                   if args.adapter == "reference" else load_adapter(args.adapter))
        res = evaluate_adapter(adapter)
        d = res["adapter"]
        print(f"\nAdapter: {d.get('name')}  (model: {d.get('model')}, family: {d.get('family')})")
        print(f"  injected exfil→attacker : {res['injected_exfil']}/{res['injected_n']}")
        print(f"  control  exfil→attacker : {res['control_exfil']}/{res['control_n']}  "
              f"(any-egress {res['control_any_egress']}/{res['control_n']})")
        print(f"  false positives (control→attacker): {res['control_exfil']}  "
              f"{'✓ none' if res['control_exfil']==0 else '✗'}")
        out = P.data_write("results/adapter_result.json")
        out.write_text(json.dumps(res, indent=2))
        print(f"  wrote {out}")
        return 0

    import run as run_mod
    rargv = []
    if args.resume:
        rargv.append("--resume")
    if args.reprobe:
        rargv.append("--reprobe")
    if args.models:
        rargv += ["--models", args.models]
    if not rargv:
        rargv = ["--resume"]  # safe default: resume from cache, never redo cached cells
    run_mod.main(rargv)
    # refresh derived artifacts
    import analyze
    analyze.main()
    return 0


def _report(argv) -> int:
    import report
    report.main()
    return 0


def _demo(argv) -> int:
    ap = argparse.ArgumentParser(prog="phi-canary demo")
    ap.add_argument("--live", action="store_true", help="call the model instead of cached replay")
    args = ap.parse_args(argv)
    from demo_run import run_demo
    return run_demo(live=args.live)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmds = {"run": _run, "report": _report, "demo": _demo, "doctor": _doctor}
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        print("commands:", ", ".join(cmds))
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd not in cmds:
        print(f"unknown command: {cmd}\n")
        print(__doc__)
        return 2
    return cmds[cmd](rest) or 0


if __name__ == "__main__":
    sys.exit(main())
