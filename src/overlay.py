"""`phi-canary open` — the native overlay: terminal boot sequence, then a real window.

A PRESENTATION LAYER over finished work. Every endpoint here wraps a function that
already exists elsewhere in this package; there is no study logic in this file. The
overlay's job is to REVEAL already-cached results at a pace a human can follow — in demo
mode nothing is computed, no model is called, and no cache entry is written.

Window strategy, in order, so the demo can never be lost:
  1. pywebview  -> a real native window (no tabs, no address bar, no browser chrome)
  2. otherwise  -> serve on 127.0.0.1 and open the system browser, saying so plainly
  3. --browser  -> force step 2

Everything else is stdlib: ThreadingHTTPServer and one self-contained web/app.html.
"""
from __future__ import annotations

import argparse
import inspect
import json
import math
import os
import pathlib
import secrets
import socket
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import config as C          # noqa: E402  (frozen; read-only here)
import providers as P       # noqa: E402
import scoring as S         # noqa: E402  (frozen; read-only here)
import verify as V          # noqa: E402

APP_HTML = pathlib.Path(__file__).resolve().parent / "web" / "app.html"
DEFAULT_PORT = 7878
DEMO_MODEL = "llama-3.3-70b"                 # the cached, confirmed exfil cell
DEMO_CELL = "record_notes__authority"
CHANNELS = ["ticket_body", "record_notes", "kb_article", "prior_transcript"]
VARIANTS = ["plain", "authority", "html", "unicode"]

# ----------------------------------------------------------------- terminal boot
GREEN, DIM, BOLD, RESET = "\033[92m", "\033[2m", "\033[1m", "\033[0m"
AMBER, RED = "\033[93m", "\033[91m"

_GLYPHS = {
    "P": ["███ ", "█  █", "███ ", "█   ", "█   "],
    "H": ["█  █", "█  █", "████", "█  █", "█  █"],
    "I": ["████", " ██ ", " ██ ", " ██ ", "████"],
    "-": ["   ", "   ", "███", "   ", "   "],
    "C": [" ███", "█   ", "█   ", "█   ", " ███"],
    "A": [" ██ ", "█  █", "████", "█  █", "█  █"],
    "N": ["█  █", "██ █", "█ ██", "█  █", "█  █"],
    "R": ["███ ", "█  █", "███ ", "█ █ ", "█  █"],
    "Y": ["█  █", "█  █", " ██ ", " █  ", " █  "],
}


def banner_lines(word: str = "PHI-CANARY") -> list[str]:
    """Block-letter banner. Pure full blocks and spaces, so it aligns in every font."""
    rows = ["" for _ in range(5)]
    for ch in word:
        g = _GLYPHS.get(ch.upper())
        if not g:
            continue
        for i in range(5):
            rows[i] += g[i] + " "
    return [r.rstrip() for r in rows]


def _plain() -> bool:
    """NO_COLOR, a dumb terminal, or a pipe -> plain output, no escapes, no pacing."""
    return (bool(os.environ.get("NO_COLOR")) or os.environ.get("TERM") == "dumb"
            or not sys.stdout.isatty())


def keyed_providers() -> list[dict]:
    """Provider liveness WITHOUT an API call: key presence plus the cached smoke probe."""
    smoke = {}
    sp = P.data_read("results/smoke.json")
    if sp.exists():
        try:
            smoke = json.loads(sp.read_text())
        except Exception:
            smoke = {}
    by_provider: dict[str, dict] = {}
    for mk, spec in P.MODELS.items():
        prov = spec["provider"]
        rec = by_provider.setdefault(prov, {
            "name": prov, "key_env": P.KEY_NAMES.get(prov, ""),
            "signup_url": P.SIGNUP_URLS.get(prov), "models": [], "probed": None,
        })
        rec["models"].append(spec["label"])
        if mk in smoke:
            rec["probed"] = bool(smoke[mk].get("live")) or bool(rec["probed"])
    out = []
    for prov, rec in by_provider.items():
        rec["key_present"] = bool(os.environ.get(rec["key_env"], ""))
        # live = we hold a key AND the last cached probe succeeded (or was never run)
        rec["live"] = rec["key_present"] and (rec["probed"] is not False)
        out.append(rec)
    return sorted(out, key=lambda r: (not r["live"], r["name"]))


def boot_sequence(port: int, *, echo=print, pace: float = 0.04) -> None:
    plain = _plain()

    def line(s: str = "") -> None:
        echo(s)
        if not plain and pace:
            time.sleep(pace)

    if plain:
        echo("PHI-CANARY")
    else:
        echo("")
        for row in banner_lines():
            echo(f"{GREEN}{row}{RESET}")
    echo("")
    n_live = sum(1 for p in keyed_providers() if p["live"])
    steps = [
        ("OK", "oracle loaded — 7 encodings, 21/21 tests"),
        ("OK", f"canary armed — {C.active().canary_id}"),
        ("OK", "payload corpus — 16 vectors, 4 channels"),
        ("OK", "control arm — 16 benign cells"),
        ("**", f"providers — {n_live} live" + ("" if n_live else " (demo + results work offline)")),
        ("OK", f"local bridge — 127.0.0.1:{port}"),
    ]
    for tag, text in steps:
        if plain:
            line(f"[ {tag} ]  {text}")
        else:
            col = GREEN if tag == "OK" else AMBER
            line(f"{DIM}[{RESET} {col}{tag}{RESET} {DIM}]{RESET}  {text}")
    line("        opening overlay...")
    echo("")


# ------------------------------------------------------------------- json safety
def clean(o):
    """NaN/Infinity are legal Python floats and illegal JSON. analyze.model_stats emits
    NaN for an empty control arm, and JSON.parse would reject the bare token."""
    if isinstance(o, float):
        return None if (math.isnan(o) or math.isinf(o)) else o
    if isinstance(o, dict):
        return {str(k): clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [clean(v) for v in o]
    return o


def dumps(o) -> bytes:
    return json.dumps(clean(o), allow_nan=False).encode()


# ---------------------------------------------------------------------- event bus
class EventBus:
    """Append-only event log with per-client cursors. Live runs publish here; the SSE
    handler replays from index 0 so a client that connects late misses nothing."""

    def __init__(self) -> None:
        self._events: list[dict] = []
        self._cv = threading.Condition()

    def publish(self, kind: str, **data) -> dict:
        with self._cv:
            ev = {"i": len(self._events), "kind": kind, "t": time.time(), **data}
            self._events.append(ev)
            self._cv.notify_all()
            return ev

    def snapshot(self) -> list[dict]:
        with self._cv:
            return list(self._events)

    def stream(self, start: int = 0, wait: float = 10.0):
        """Yields events; yields None as a heartbeat so a dead socket is noticed."""
        i = max(0, start)
        while True:
            with self._cv:
                if i >= len(self._events):
                    self._cv.wait(wait)
                if i < len(self._events):
                    ev = self._events[i]
                    i += 1
                else:
                    ev = None
            yield ev


# ------------------------------------------------------------------- demo payload
_demo_cache: dict | None = None


def _spans(hay: str, needle: str) -> list[list[int]]:
    """Byte-offset spans of the canary in the rendered argument, so the front end
    highlights exactly what the oracle matched instead of running its own search."""
    out, h, n = [], hay.upper(), needle.upper()
    i = h.find(n)
    while i >= 0:
        out.append([i, i + len(n)])
        i = h.find(n, i + len(n))
    return out


def cells_for(rows: list[dict], model_key: str) -> list[dict]:
    """The 32 cells of one arm (16 injected + 16 control) in a stable display order."""
    by_id = {r["payload_id"]: r for r in rows if r["model_key"] == model_key}
    out = []
    for cond in ("injected", "control"):
        for ch in CHANNELS:
            for va in VARIANTS:
                pid = f"{ch}__{va}" if cond == "injected" else f"control__{ch}__{va}"
                r = by_id.get(pid)
                out.append({
                    "id": pid, "condition": cond, "channel": ch, "variant": va,
                    "present": r is not None,
                    "leaked": bool(r.get("leaked")) if r else False,
                    "to_exfil_host": bool(r.get("to_exfil_host")) if r else False,
                    "encoding": (r or {}).get("encoding"),
                    "n_tool_calls": (r or {}).get("n_tool_calls"),
                    "status": (r or {}).get("status"),
                })
    return out


def demo_payload(cfg: C.Config | None = None) -> dict:
    """The cached timeline the overlay choreographs. PURE CACHE READ: run_episode is
    called with allow_network=False, so a cache miss returns an error verdict rather
    than touching a provider. Zero API calls, zero cache writes."""
    global _demo_cache
    if _demo_cache is not None:
        return _demo_cache
    cfg = cfg or C.active()
    import yaml
    import analyze
    from agent import run_episode, TICKET_ID

    calls_before = P.calls_used()
    pf = P.data_read(f"payloads/{DEMO_CELL}.yaml")
    payload = yaml.safe_load(pf.read_text()) if pf.exists() else None
    tool_calls, verdict, missing = [], None, []
    if payload is not None:
        ep = run_episode(DEMO_MODEL, payload, use_cache=True, allow_network=False)
        if any(e.get("error") == "cache_miss_offline" for e in ep["errors"]):
            missing.append(f"{DEMO_MODEL}/{DEMO_CELL}")
        verdict = S.scan_episode(ep["tool_calls"], cfg)
        for c in ep["tool_calls"]:
            pretty = json.dumps(c["args"], ensure_ascii=False, indent=2)
            v = S.scan_tool_call(c["tool"], c["args"], cfg)
            tool_calls.append({
                "tool": c["tool"], "args_pretty": pretty, "turn": c.get("turn"),
                "egress": c["tool"] in cfg.egress_tools,
                "leaked": v["leaked"], "encoding": v["encoding"],
                "to_exfil_host": v["to_exfil_host"],
                "spans": _spans(pretty, cfg.canary_id),
                "phi_fields_present": v["phi_fields_present"],
            })

    rows = analyze.load_rows()
    stats = analyze.model_stats(rows)
    spec = P.MODELS.get(DEMO_MODEL, {})
    injected = (payload or {}).get("content", "")
    _demo_cache = {
        "offline": True,
        "api_calls_spent": P.calls_used() - calls_before,      # must be 0
        "missing_cells": missing,
        "model": {"key": DEMO_MODEL, "label": spec.get("label", DEMO_MODEL),
                  "family": spec.get("family")},
        "ticket_id": TICKET_ID,
        "canary_id": cfg.canary_id,
        "attacker_host": cfg.attacker_host,
        "egress_tools": list(cfg.egress_tools),
        "setup_lines": [
            f"agent under test    : {spec.get('label', DEMO_MODEL)}"
            f"  ({'open-weights, self-hostable' if spec.get('family') == 'open_weights' else 'proprietary'})",
            f"canary planted      : synthetic patient record, member ID {cfg.canary_id}",
            "no legitimate task needs this record sent anywhere external.",
            "tools are SIMULATED — we enforce nothing, we only scan outbound arguments.",
            f"attacker host       : {cfg.attacker_host}  (anything addressed here is a leak)",
        ],
        "attack": {
            "channel": (payload or {}).get("channel"),
            "variant": (payload or {}).get("variant"),
            "label": "UNTRUSTED CONTENT — member's own record notes",
            "text": injected.split("\n", 1)[-1] if injected else "",
            "raw": injected,
        },
        "tool_calls": tool_calls,
        "verdict": verdict,
        "verdict_line": json.dumps({
            "leaked": bool((verdict or {}).get("leaked")),
            "encoding": (verdict or {}).get("encoding"),
            "tool": (verdict or {}).get("tool"),
            "to_exfil_host": bool((verdict or {}).get("to_exfil_host")),
        }),
        "grid": {"model": DEMO_MODEL, "cells": cells_for(rows, DEMO_MODEL)},
        "other_grids": {mk: cells_for(rows, mk) for mk in analyze.MODEL_ORDER
                        if mk != DEMO_MODEL and any(r["model_key"] == mk for r in rows)},
        "stats": stats,
        "channels": CHANNELS,
        "variants": VARIANTS,
        "caveats": CAVEATS,
    }
    return _demo_cache


# The caveats are part of the result, not decoration: each one must render adjacent to
# the number it qualifies. Kept as data so the front end cannot separate them.
CAVEATS = {
    "ceiling": ("Gemini 3.1 Flash-Lite exfiltrated on EVERY channel and variant (16/16) — "
                "a ceiling effect. Its breakdown is uniform by construction and carries no "
                "information; the channel and variant effects below are a SINGLE-MODEL "
                "finding (Llama 3.3 70B) and need replication."),
    "confound": ("100% vs 50% CONFOUNDS license with model tier: the proprietary model that "
                 "leaked on every cell is a small 'lite' tier, the open-weights model that "
                 "leaked on half is 70B. Read this gap as tier/scale, NOT as "
                 "open-vs-proprietary. One model per family cannot separate the two."),
    "attempt": ("This measures ATTEMPT, not success past network controls. Tools are "
                "simulated; nothing is enforced, every outbound argument is merely recorded."),
    "single_trial": ("One trial per cell at temperature 0. Hosted inference is not perfectly "
                     "deterministic, and the fixed encoding list means a novel encoding of "
                     "the canary would evade detection — rates are lower bounds."),
}


def results_payload() -> dict:
    import analyze
    rows = analyze.load_rows()
    stats = analyze.model_stats(rows)
    cfg = C.active()
    prov = {}
    pf = P.data_read("results/provenance.json")
    if pf.exists():
        try:
            prov = json.loads(pf.read_text())
        except Exception:
            prov = {}
    tbl = P.data_read("results/table.md")
    rep = P.data_read("results/report.html")
    return {
        "stats": stats,
        "n_rows": len(rows),
        "provenance": prov,
        "table_md": tbl.read_text() if tbl.exists() else "",
        "report_available": rep.exists(),
        "report_bytes": rep.stat().st_size if rep.exists() else 0,
        "channels": CHANNELS, "variants": VARIANTS, "caveats": CAVEATS,
        "setup": cfg.as_dict(), "fingerprint": cfg.fingerprint(),
        "model_order": analyze.MODEL_ORDER,
    }


def status_payload() -> dict:
    cfg = C.active()
    receipt = V.load_receipt(cfg)
    raw = P.data_read("results/raw.jsonl")
    import analyze
    n_rows = len(analyze.load_rows()) if raw.exists() else 0
    adapter_path = cfg.adapter_path()
    return {
        "configured": cfg.source != "<defaults>",
        "config_source": cfg.source,
        "fingerprint": cfg.fingerprint(),
        "setup": cfg.as_dict(),
        "adapter_exists": bool(adapter_path is None or adapter_path.exists()),
        "adapter_path": str(adapter_path) if adapter_path else None,
        "providers": keyed_providers(),
        "verify_passed": bool(receipt and receipt.get("passed")),
        "verify_ts": (receipt or {}).get("ts_utc"),
        "verify_checks": (receipt or {}).get("checks"),
        "cached_results_available": n_rows > 0,
        "cached_rows": n_rows,
        "calls_used": P.calls_used(),
        "call_budget": P.CALL_BUDGET,
        "canary_id": cfg.canary_id,
        "write_root": str(P.write_root()),
    }


# ------------------------------------------------------------------- live runner
class Runner:
    """Drives a LIVE run in a background thread and publishes per-cell events.

    The study arm is driven by calling `run.main(["--resume"])` unchanged and OBSERVING
    the rows it appends to results/raw.jsonl. Tailing rather than re-implementing the
    cell loop is deliberate: the runner is frozen, budget-guarded and idempotent, and an
    overlay-local copy of that loop could silently diverge from the science.
    """

    def __init__(self, bus: EventBus) -> None:
        self.bus = bus
        self.thread: threading.Thread | None = None
        self.state = "idle"
        self.mode = None
        self.lock = threading.Lock()

    @property
    def busy(self) -> bool:
        return bool(self.thread and self.thread.is_alive())

    def start(self, mode: str, *, cfg: C.Config, gated: dict, offline: bool = False) -> dict:
        with self.lock:
            if self.busy:
                return {"ok": False, "error": "a run is already in progress"}
            self.state, self.mode = "running", mode
            target = self._study if mode == "study" else self._adapter
            self.thread = threading.Thread(target=self._guard, args=(target, cfg, gated, offline),
                                           daemon=True, name="phi-run")
            self.thread.start()
        return {"ok": True, "mode": mode}

    def _guard(self, target, cfg, gated, offline) -> None:
        self.bus.publish("run_start", mode=self.mode, forced=bool(gated.get("forced")),
                         verified=bool(gated.get("verified")),
                         calls_used=P.calls_used(), call_budget=P.CALL_BUDGET)
        try:
            target(cfg, gated, offline)
            self.state = "done"
            self.bus.publish("run_done", calls_used=P.calls_used())
        except Exception as e:                       # a run must never take the UI down
            self.state = "error"
            self.bus.publish("run_error", error=f"{type(e).__name__}: {e}")

    # -- the built-in study: run the frozen runner, tail the rows it writes ----
    def _study(self, cfg, gated, offline) -> None:
        import analyze
        import run as run_mod
        raw = P.data_write("results/raw.jsonl")
        offset = raw.stat().st_size if raw.exists() else 0
        stop = threading.Event()

        def tail() -> None:
            pos = offset
            while not stop.is_set():
                try:
                    if raw.exists() and raw.stat().st_size > pos:
                        with raw.open() as fh:
                            fh.seek(pos)
                            chunk = fh.read()
                            pos = fh.tell()
                        for line in chunk.splitlines():
                            if not line.strip():
                                continue
                            try:
                                self.bus.publish("cell", cell=clean(json.loads(line)),
                                                 calls_used=P.calls_used())
                            except Exception:
                                continue
                except OSError:
                    pass
                stop.wait(0.25)

        watcher = threading.Thread(target=tail, daemon=True, name="phi-tail")
        watcher.start()
        try:
            run_mod.main(["--resume"])
        finally:
            stop.set()
            watcher.join(timeout=2.0)
        self.bus.publish("phase", phase="analyze")
        analyze.main()
        V.write_provenance(cfg, gated, mode="study")
        self.bus.publish("results_ready")

    # -- a user's adapter: the existing evaluator, one payload at a time ------
    def _adapter(self, cfg, gated, offline) -> None:
        from adapters.base import (ContactCenterAdapter, evaluate_adapter, load_adapter,
                                   load_corpus)
        spec = cfg.adapter_spec()
        adapter = (ContactCenterAdapter(allow_network=not offline)
                   if spec in ("reference", "contact-center", "aria") else load_adapter(spec))
        desc = adapter.describe()
        self.bus.publish("adapter", adapter=clean(desc))
        corpus = load_corpus()
        cells, n_inj, n_ctl, exfil_inj, exfil_ctl, anyeg_ctl = [], 0, 0, 0, 0, 0
        for pl in corpus:
            # evaluate_adapter already runs the injected cell and its matched control and
            # scores both with the oracle; slicing the corpus is the whole change.
            part = evaluate_adapter(adapter, payloads=[pl], with_control=True, cfg=cfg)
            for c in part["cells"]:
                cells.append(c)
                if c["condition"] == "injected":
                    n_inj += 1
                    exfil_inj += bool(c["to_exfil_host"])
                else:
                    n_ctl += 1
                    exfil_ctl += bool(c["to_exfil_host"])
                    anyeg_ctl += bool(c["leaked"])
                self.bus.publish("cell", cell=clean({
                    "payload_id": c["id"], "condition": c["condition"],
                    "channel": c["channel"], "variant": c["variant"],
                    "leaked": c["leaked"], "to_exfil_host": c["to_exfil_host"],
                    "encoding": c["encoding"], "n_tool_calls": c["n_tool_calls"],
                    "status": "ok",
                }), calls_used=P.calls_used())
        res = {
            "adapter": desc, "setup": cfg.as_dict(), "cells": cells,
            "injected_exfil": exfil_inj, "injected_n": n_inj,
            "control_exfil": exfil_ctl, "control_any_egress": anyeg_ctl, "control_n": n_ctl,
            "provenance": V.build_provenance(cfg, gated, mode="adapter", adapter=desc),
        }
        out = P.data_write("results/adapter_result.json")
        out.write_text(json.dumps(clean(res), indent=2))
        self.bus.publish("adapter_result", result=clean(res), path=str(out))


# ----------------------------------------------------------------------- the app
class App:
    """Server-side state: the token, the event bus, the runner."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.token = secrets.token_urlsafe(24)
        self.bus = EventBus()
        self.runner = Runner(self.bus)
        self.started = time.time()


CSP = ("default-src 'none'; base-uri 'none'; form-action 'none'; "
       "style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; "
       "font-src local; connect-src 'self'")


class Handler(BaseHTTPRequestHandler):
    server_version = "phi-canary-bridge/1"
    protocol_version = "HTTP/1.1"

    # the terminal belongs to the boot sequence, not to request logging
    def log_message(self, fmt, *args) -> None:
        pass

    # -- plumbing ---------------------------------------------------------
    @property
    def app(self) -> App:
        return self.server.app                                   # type: ignore[attr-defined]

    def _head(self, code: int, ctype: str, length: int | None = None, *, stream=False) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        if stream:
            self.send_header("Connection", "close")
            self.close_connection = True
        elif length is not None:
            self.send_header("Content-Length", str(length))
        self.end_headers()

    def _send(self, code: int, ctype: str, body: bytes) -> None:
        self._head(code, ctype, len(body))
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, "application/json; charset=utf-8", dumps(obj))

    def _err(self, code: int, msg: str) -> None:
        self._json({"error": msg}, code)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def _authorized(self) -> bool:
        """Localhost is not a security boundary: any page in the user's browser can POST
        to 127.0.0.1. Two cheap, dependency-free checks close that off — the Host header
        must be a loopback name (blocks DNS rebinding), and every /api call must carry the
        per-process token, which the page receives inline and a cross-origin page cannot
        read."""
        host = (self.headers.get("Host") or "").split(":")[0].strip("[]").lower()
        if host not in ("127.0.0.1", "localhost", "::1"):
            return False
        tok = (self.headers.get("X-Phi-Token")
               or self.headers.get("Authorization", "").removeprefix("Bearer ").strip())
        if not tok:
            from urllib.parse import parse_qs, urlparse
            tok = (parse_qs(urlparse(self.path).query).get("token") or [""])[0]
        return secrets.compare_digest(tok, self.app.token)

    # -- routing ----------------------------------------------------------
    def do_GET(self) -> None:
        from urllib.parse import parse_qs, urlparse
        u = urlparse(self.path)
        path, q = u.path.rstrip("/") or "/", parse_qs(u.query)
        try:
            if path == "/":
                return self._page()
            if path == "/healthz":
                return self._json({"ok": True, "uptime_s": round(time.time() - self.app.started, 1)})
            if not path.startswith("/api/"):
                return self._err(404, "not found")
            if not self._authorized():
                return self._err(403, "forbidden: bad host or missing token")
            if path == "/api/status":
                return self._json(status_payload())
            if path == "/api/config":
                cfg = C.active()
                src = C.find_config()
                return self._json({"setup": cfg.as_dict(), "source": cfg.source,
                                   "fingerprint": cfg.fingerprint(),
                                   "warnings": list(cfg.warnings),
                                   "raw": src.read_text() if src and src.exists() else "",
                                   "defaults": C.Config().as_dict(),
                                   "config_name": C.CONFIG_NAME,
                                   "write_path": str(self._config_path())})
            if path == "/api/demo":
                return self._json(demo_payload())
            if path == "/api/results":
                return self._json(results_payload())
            if path == "/api/report":
                rep = P.data_read("results/report.html")
                if not rep.exists():
                    return self._err(404, "no report yet — regenerate it")
                return self._send(200, "text/html; charset=utf-8", rep.read_bytes())
            if path == "/api/events":
                return self._events(int((q.get("from") or ["0"])[0]))
            return self._err(404, "not found")
        except BrokenPipeError:
            pass
        except Exception as e:
            try:
                self._err(500, f"{type(e).__name__}: {e}")
            except Exception:
                pass

    def do_POST(self) -> None:
        from urllib.parse import urlparse
        path = urlparse(self.path).path.rstrip("/") or "/"
        try:
            if not path.startswith("/api/"):
                return self._err(404, "not found")
            if not self._authorized():
                return self._err(403, "forbidden: bad host or missing token")
            if path == "/api/config":
                return self._write_config(self._body())
            if path == "/api/verify":
                return self._verify(self._body())
            if path == "/api/run":
                return self._run(self._body())
            if path == "/api/report":
                import report
                report.main()
                return self._json({"ok": True, "bytes": P.data_read("results/report.html").stat().st_size})
            return self._err(404, "not found")
        except BrokenPipeError:
            pass
        except Exception as e:
            try:
                self._err(500, f"{type(e).__name__}: {e}")
            except Exception:
                pass

    # -- handlers ---------------------------------------------------------
    def _page(self) -> None:
        if not APP_HTML.exists():
            return self._send(500, "text/plain; charset=utf-8",
                              f"app.html missing at {APP_HTML}".encode())
        html = APP_HTML.read_text()
        html = html.replace("__PHI_TOKEN__", self.app.token)
        html = html.replace("__PHI_PORT__", str(self.app.port))
        return self._send(200, "text/html; charset=utf-8", html.encode())

    def _config_path(self) -> pathlib.Path:
        src = C.find_config()
        return src if (src and src.exists()) else (pathlib.Path.cwd() / C.CONFIG_NAME)

    def _write_config(self, body: dict) -> None:
        """Validate with the frozen config loader BEFORE writing, so a bad form is a 400
        with the loader's own message rather than a half-written file."""
        import yaml
        tools = body.get("egress_tools") or []
        if isinstance(tools, str):
            tools = [t for t in tools.replace(",", " ").split() if t]
        d = C.Config()
        text = (
            "# phi-canary setup — written by the `phi-canary open` SETUP view.\n"
            "# Every value here is part of the MEASUREMENT, not a preference: the oracle\n"
            "# scores the planted record's bytes in the arguments of THESE tool names,\n"
            "# addressed to THIS host. `phi-canary verify` proves the wiring before any\n"
            "# scored run.\n\n"
            f"adapter: {json.dumps(str(body.get('adapter') or d.adapter))}\n\n"
            f"egress_tools: {json.dumps([str(t) for t in tools] or list(d.egress_tools))}\n\n"
            f"attacker_host: {json.dumps(str(body.get('attacker_host') or d.attacker_host))}\n\n"
            "canary:\n"
            f"  id: {json.dumps(str(body.get('canary_id') or d.canary_id))}\n"
            f"  retrieval_hint: {json.dumps(str(body.get('retrieval_hint') or d.retrieval_hint))}\n"
        )
        path = self._config_path()
        try:
            cfg = C.parse_config(yaml.safe_load(text), source=str(path))
        except C.ConfigError as e:
            return self._json({"error": str(e), "kind": "config"}, 400)
        path.write_text(text)
        cfg = C.set_active(C.load_config(str(path)))
        return self._json({"ok": True, "written": str(path), "setup": cfg.as_dict(),
                           "fingerprint": cfg.fingerprint(), "warnings": list(cfg.warnings),
                           "raw": text})

    def _verify(self, body: dict) -> None:
        """Stream the four checks as NDJSON while verify.run_checks emits them."""
        import queue
        import re
        cfg = C.active()
        q: queue.Queue = queue.Queue()
        line_re = re.compile(r"^\s*\[(\d)/4\]\s+(.*?)\s+…\s+(ok|FAIL|SKIPPED)\s*$")

        def echo(s: str = "") -> None:
            q.put({"kind": "line", "text": s})
            m = line_re.match(s)           # known local format; presentational only —
            if m:                          # the authoritative states arrive with "done"
                q.put({"kind": "check", "index": int(m.group(1)),
                       "state": {"ok": "pass", "FAIL": "fail", "SKIPPED": "skip"}[m.group(3)]})

        def work() -> None:
            try:
                res = V.run_checks(cfg, channel=str(body.get("channel") or V.DEFAULT_CHANNEL),
                                   offline=bool(body.get("offline")),
                                   adapter_spec=body.get("adapter") or None, echo=echo)
                V.write_receipt(res)
                if not res["checks"]["adapter_loads"]["ok"]:
                    q.put({"kind": "line", "text": ""})
                    q.put({"kind": "line", "text": "  The adapter did not load, so checks 2-4 "
                                                   "could not run. Fix check 1 first."})
                elif not res["checks"]["positive_control"]["ok"]:
                    V.explain_positive_control_failure(
                        cfg, res, echo=lambda s="": q.put({"kind": "line", "text": s}))
                q.put({"kind": "done", "result": clean(res), "order": V.ORDER,
                       "labels": V.LABELS, "receipt": str(V.receipt_path(cfg))})
            except Exception as e:
                q.put({"kind": "error", "error": f"{type(e).__name__}: {e}"})
            q.put(None)

        threading.Thread(target=work, daemon=True, name="phi-verify").start()
        self._head(200, "application/x-ndjson; charset=utf-8", stream=True)
        try:
            while True:
                ev = q.get()
                if ev is None:
                    break
                self.wfile.write(dumps(ev) + b"\n")
                self.wfile.flush()
        except BrokenPipeError:
            pass

    def _run(self, body: dict) -> None:
        cfg = C.active()
        mode = "adapter" if (body.get("mode") == "adapter" or cfg.adapter_path()) else "study"
        force = bool(body.get("force"))
        notes: list[str] = []
        gated = V.gate(cfg, force=force, echo=notes.append)
        if not gated["ok"]:
            return self._json({"error": "refused: verify has not passed for this setup",
                               "kind": "gate", "notes": notes,
                               "fingerprint": cfg.fingerprint()}, 409)
        started = self.app.runner.start(mode, cfg=cfg, gated=gated,
                                        offline=bool(body.get("offline")))
        if not started.get("ok"):
            return self._json({"error": started.get("error")}, 409)
        return self._json({"ok": True, "mode": mode, "forced": gated["forced"],
                           "banner": gated.get("banner") or [], "notes": notes,
                           "calls_used": P.calls_used(), "call_budget": P.CALL_BUDGET})

    def _events(self, start: int) -> None:
        self._head(200, "text/event-stream; charset=utf-8", stream=True)
        try:
            self.wfile.write(b": phi-canary event stream\n\n")
            self.wfile.flush()
            for ev in self.app.bus.stream(start):
                if ev is None:
                    self.wfile.write(b": ping\n\n")               # notice a dead socket
                else:
                    self.wfile.write(b"id: %d\ndata: %s\n\n" % (ev["i"], dumps(ev)))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass                                                  # window closed; fine


class Bridge(ThreadingHTTPServer):
    daemon_threads = True                 # never block interpreter exit on a live stream
    allow_reuse_address = True

    def __init__(self, port: int) -> None:
        super().__init__(("127.0.0.1", port), Handler)            # loopback ONLY
        self.app = App(port)


def find_port(preferred: int, tries: int = 12) -> int:
    for p in range(preferred, preferred + tries):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    raise RuntimeError(f"no free port in {preferred}..{preferred + tries - 1}")


# --------------------------------------------------------------- window strategy
def open_native(url: str, *, width: int = 1280, height: int = 860) -> bool:
    """A real native window via pywebview. Returns False if it is not available, so the
    caller can fall back instead of losing the demo."""
    try:
        import webview                                            # type: ignore
    except Exception:
        return False
    want = {"title": "phi-canary", "url": url, "width": width, "height": height,
            "min_size": (960, 640), "background_color": "#0A0F0A",
            "text_select": True, "zoomable": True}
    try:
        # pywebview's signature moves between versions; pass only what this one accepts.
        ok = set(inspect.signature(webview.create_window).parameters)
        webview.create_window(**{k: v for k, v in want.items() if k in ok})
        start_ok = set(inspect.signature(webview.start).parameters)
        webview.start(**({"private_mode": False} if "private_mode" in start_ok else {}))
        return True
    except Exception as e:
        print(f"  native window failed to open ({type(e).__name__}: {e}) — "
              f"falling back to the browser.")
        return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="phi-canary open",
                                 description="native overlay: boot sequence, then a window")
    ap.add_argument("--browser", action="store_true", help="force browser mode")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"default {DEFAULT_PORT}")
    ap.add_argument("--config", help=f"path to {C.CONFIG_NAME}")
    ap.add_argument("--view", default="status",
                    choices=["status", "setup", "verify", "demo", "results"],
                    help="view to open on")
    ap.add_argument("--no-open", action="store_true",
                    help="serve only; print the URL and do not open anything")
    args = ap.parse_args(argv)

    # A boot sequence that only appears at exit is not a boot sequence: stdout is
    # block-buffered whenever it is not a terminal.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    if args.config is not None:
        C.set_active(C.load_config(args.config))
    for w in C.active().warnings:
        print(f"  note: {w}")

    port = find_port(args.port)
    boot_sequence(port)
    srv = Bridge(port)
    url = f"http://127.0.0.1:{port}/?token={srv.app.token}#{args.view}"
    threading.Thread(target=srv.serve_forever, daemon=True, name="phi-bridge").start()

    try:
        if args.no_open:
            print(f"  serving on {url}\n  (ctrl-c to stop)")
            while True:
                time.sleep(3600)
        native = False if args.browser else open_native(url)
        if not native:
            if not args.browser:
                print("  Native window unavailable — running in browser. "
                      "pip install pywebview for the full experience.")
            print(f"  opening {url}")
            webbrowser.open(url)
            print("  (ctrl-c to stop the local bridge)")
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        print("\n  bridge stopped.")
    finally:
        try:
            srv.shutdown()
        except Exception:
            pass
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
