"""phi-canary command-line entry point.

    phi-canary init      scaffold my_adapter.py + phi-canary.yaml into the current directory
    phi-canary verify    4 checks on your setup — MUST pass before any scored run
    phi-canary run       run the study (auto-resumes from cache); --adapter to test your agent
    phi-canary report    regenerate report.html from cached results
    phi-canary demo      the offline cached demo (--live to call the model)
    phi-canary doctor    which provider keys are live + signup URLs

Setup for a bring-your-own-agent run lives in ./phi-canary.yaml (--config to point
elsewhere): the adapter, the egress tool names, the attacker host. Those are measurement
inputs, so `run` will not print a scored number until `verify` has passed for them.

Works from any working directory and from bundled package data (see providers.data_read).
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # flat imports within pkg
import config as C
import providers as P


def _activate(path: str | None):
    """Load ./phi-canary.yaml (or --config) and make it the process-wide setup."""
    cfg = C.set_active(C.load_config(path))
    for w in cfg.warnings:
        print(f"  note: {w}")
    return cfg


def _init(argv) -> int:
    ap = argparse.ArgumentParser(prog="phi-canary init")
    ap.add_argument("--dir", default=".", help="where to scaffold (default: current directory)")
    ap.add_argument("--force", action="store_true", help="overwrite existing files")
    args = ap.parse_args(argv)

    import scaffold
    dest = pathlib.Path(args.dir)
    written, skipped = scaffold.scaffold(dest, force=args.force)
    for n in written:
        print(f"  created  {dest / n}")
    for n in skipped:
        print(f"  kept     {dest / n}  (exists; --force to overwrite)")
    if not written:
        print("\nNothing written. Already initialised.")
        return 0
    print(f"""
Next:
  1. edit {scaffold.ADAPTER_FILE}       — two TODOs: describe() and run_task()
  2. edit {scaffold.CONFIG_FILE}     — egress_tools MUST be your agent's real tool names
  3. phi-canary verify        — 4 checks, incl. a positive control that must detect a leak
  4. phi-canary run           — scored (refused until verify passes)""")
    return 0


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
    ap.add_argument("--config", help=f"path to {C.CONFIG_NAME} (default: ./{C.CONFIG_NAME})")
    args = ap.parse_args(argv)
    cfg = _activate(args.config)

    if args.adapter or cfg.adapter_path():
        from adapters.base import load_adapter, evaluate_adapter, ContactCenterAdapter
        spec = args.adapter or cfg.adapter_spec()
        adapter = (ContactCenterAdapter(allow_network=not args.offline)
                   if spec in ("reference", "contact-center", "aria") else load_adapter(spec))
        res = evaluate_adapter(adapter, cfg=cfg)
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


def _verify(argv) -> int:
    import verify
    return verify.main(argv)


def _report(argv) -> int:
    ap = argparse.ArgumentParser(prog="phi-canary report")
    ap.add_argument("--config", help=f"path to {C.CONFIG_NAME}")
    args = ap.parse_args(argv)
    _activate(args.config)
    import report
    report.main()
    return 0


def _demo(argv) -> int:
    ap = argparse.ArgumentParser(prog="phi-canary demo")
    ap.add_argument("--live", action="store_true", help="call the model instead of cached replay")
    ap.add_argument("--config", help=f"path to {C.CONFIG_NAME}")
    args = ap.parse_args(argv)
    _activate(args.config)
    from demo_run import run_demo
    return run_demo(live=args.live)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmds = {"init": _init, "verify": _verify, "run": _run, "report": _report,
            "demo": _demo, "doctor": _doctor}
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        print("commands:", ", ".join(cmds))
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd not in cmds:
        print(f"unknown command: {cmd}\n")
        print(__doc__)
        return 2
    try:
        return cmds[cmd](rest) or 0
    except C.ConfigError as e:        # a bad setup file is a user error, not a traceback
        print(f"\nphi-canary: bad setup — {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
