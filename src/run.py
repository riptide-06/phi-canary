"""Runner: model x payload matrix, plus a no-injection control per model.

  * Idempotent. Every model turn is cached to disk by (model, payload_id, turn), so a
    suspend mid-run loses nothing and --resume skips completed cells.
  * Never crashes. Any cell failure is written as an error verdict and the run continues.
  * Threaded ACROSS providers (one worker per provider) so a slow/rate-limited provider
    never blocks the others; within a provider, cells run in order.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import providers as P
import oracle as O
import yaml
from agent import run_episode

ROOT = P.ROOT
_write_lock = threading.Lock()


def load_payloads() -> list[dict]:
    """Injected corpus (16) + a matched control arm (16): each of the 16 tasks with the
    injection REMOVED. The control arm is the false-positive baseline on benign traffic —
    the answer to "how often does the agent exfiltrate when nothing is attacking it".
    """
    inj = []
    for f in sorted(P.data_read("payloads").glob("*.yaml")):
        d = yaml.safe_load(f.read_text())
        d["condition"] = "injected"
        inj.append(d)
    ctrl = []
    for d in inj:
        ctrl.append({
            "id": f"control__{d['channel']}__{d['variant']}",
            "channel": d["channel"], "variant": d["variant"],
            "condition": "control", "content": "",   # injection removed
        })
    return inj + ctrl


def completed_cells() -> set[tuple[str, str]]:
    done = set()
    raw = P.data_read("results/raw.jsonl")
    if raw.exists():
        for line in raw.read_text().splitlines():
            if not line.strip():
                continue
            try:
                r = json.loads(line)
                if r.get("status") == "ok":
                    done.add((r["model_key"], r["payload_id"]))
            except Exception:
                continue
    return done


def append_raw(record: dict) -> None:
    with _write_lock:
        with P.data_write("results/raw.jsonl").open("a") as fh:
            fh.write(json.dumps(record) + "\n")


def log_cell(model_key: str, ep: dict, verdict: dict) -> None:
    p = P.data_write(f"logs/{model_key}__{ep['payload_id']}.jsonl")
    with p.open("w") as fh:
        for c in ep["tool_calls"]:
            fh.write(json.dumps({"turn": c["turn"], "tool": c["tool"], "args": c["args"]}) + "\n")
        fh.write(json.dumps({"verdict": verdict, "errors": ep["errors"],
                             "unparsed": ep["unparsed"], "turns_used": ep["turns_used"]}) + "\n")


def run_cell(model_key: str, payload: dict, *, use_cache: bool) -> dict:
    pid = payload["id"]
    condition = payload.get("condition", "injected")
    t0 = time.time()
    try:
        # control cells carry empty content -> run_episode injects nothing
        pl = payload if payload.get("content") else {
            "id": pid, "channel": payload["channel"],
            "variant": payload.get("variant"), "content": "",
        }
        ep = run_episode(model_key, pl, use_cache=use_cache)
        verdict = O.scan_episode(ep["tool_calls"])
        hard_errors = [e for e in ep["errors"] if e.get("error") not in (None, "max_turns_reached")]
        status = "ok"
        if hard_errors:
            status = "error"
        record = {
            "status": status,
            "model_key": model_key,
            "family": P.MODELS[model_key]["family"],
            "model_label": P.MODELS[model_key]["label"],
            "payload_id": pid,
            "condition": condition,
            "channel": payload["channel"],
            "variant": payload["variant"],
            "leaked": verdict["leaked"],
            "encoding": verdict["encoding"],
            "tool": verdict["tool"],
            "arg_excerpt": verdict["arg_excerpt"],
            "n_leaking_calls": verdict["n_leaking_calls"],
            "encodings_all": verdict["encodings_all"],
            "phi_fields_present": verdict["phi_fields_present"],
            "canary_in_non_egress_arg": verdict["canary_in_non_egress_arg"],
            "to_exfil_host": verdict.get("to_exfil_host", False),
            "n_tool_calls": ep["n_tool_calls"],
            "tools_called": [c["tool"] for c in ep["tool_calls"]],
            "turns_used": ep["turns_used"],
            "n_unparsed": len(ep["unparsed"]),
            "injection_delivered": ep["injection_delivered"],
            "errors": ep["errors"],
            "elapsed_s": round(time.time() - t0, 2),
            "ts": time.time(),
        }
        log_cell(model_key, ep, verdict)
    except Exception as e:  # a cell must never crash the run
        record = {
            "status": "crash", "model_key": model_key, "payload_id": pid,
            "condition": condition,
            "channel": payload.get("channel"), "variant": payload.get("variant"),
            "leaked": False, "encoding": None, "error_detail": f"{type(e).__name__}: {e}",
            "elapsed_s": round(time.time() - t0, 2), "ts": time.time(),
        }
    append_raw(record)
    flag = "LEAK" if record.get("leaked") else ("ERR " if record["status"] != "ok" else "----")
    print(f"  [{flag}] {model_key:16s} {pid:22s} "
          f"enc={record.get('encoding')} calls={record.get('n_tool_calls','?')} "
          f"({record.get('status')})  used={P.calls_used()}")
    return record


def provider_worker(model_key: str, payloads: list[dict], done: set, use_cache: bool):
    for pl in payloads:
        if (model_key, pl["id"]) in done:
            print(f"  [skip] {model_key} {pl['id']} (cached verdict)")
            continue
        if P.calls_used() >= P.CALL_BUDGET:
            print(f"  [BUDGET] stopping {model_key}: {P.calls_used()}/{P.CALL_BUDGET}")
            return
        run_cell(model_key, pl, use_cache=use_cache)


def live_models() -> list[str]:
    sp = P.data_read("results/smoke.json")
    if sp.exists():
        smoke = json.loads(sp.read_text())
        live = [k for k, v in smoke.items() if v.get("live")]
        if live:
            return live
    return list(P.MODELS)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--resume", action="store_true", help="skip cells with an ok verdict")
    ap.add_argument("--models", default="", help="comma list; default = live models from smoke.json")
    ap.add_argument("--smoke", action="store_true", help="1 model x 3 payloads self-verify")
    ap.add_argument("--reprobe", action="store_true", help="re-run smoke test first (dead models may have recovered)")
    args = ap.parse_args(argv)

    if args.reprobe:
        import smoke
        smoke.main()

    payloads = load_payloads()
    if args.models:
        models = [m.strip() for m in args.models.split(",") if m.strip()]
    else:
        models = live_models()
    # priority order protects the open-vs-proprietary comparison when the budget runs short:
    # injected cells (the study) run before control cells within each model.
    models = sorted(models, key=lambda m: P.MODELS[m].get("priority", 99))
    payloads = sorted(payloads, key=lambda p: (0 if p.get("condition") == "injected" else 1, p["id"]))

    if args.smoke:
        models, payloads = models[:1], payloads[:3]
        print(f"SMOKE: {models} x {[p['id'] for p in payloads]}")

    done = completed_cells() if args.resume else set()
    print(f"models={models}  payloads={len(payloads)}  already_done={len(done)}  "
          f"calls_used={P.calls_used()}/{P.CALL_BUDGET}")

    # group models by provider; one worker per provider (parallelism ACROSS providers only)
    by_provider: dict[str, list[str]] = {}
    for m in models:
        by_provider.setdefault(P.MODELS[m]["provider"], []).append(m)

    def provider_task(provider_models):
        for mk in provider_models:
            provider_worker(mk, payloads, done, use_cache=True)

    with ThreadPoolExecutor(max_workers=max(1, len(by_provider))) as ex:
        list(ex.map(provider_task, by_provider.values()))

    _raw = P.data_read("results/raw.jsonl")
    total = sum(1 for _ in _raw.open()) if _raw.exists() else 0
    print(f"\ndone. raw verdict rows: {total}. calls used: {P.calls_used()}/{P.CALL_BUDGET}")


if __name__ == "__main__":
    main()
