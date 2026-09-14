#!/usr/bin/env python3
"""Single source of truth for every quantity that appears in any phi-canary paper.

Reads results/raw.jsonl (and the repo itself) and emits:
  paper/numbers.json  — machine-readable
  paper/numbers.tex   — one LaTeX macro per quantity

Nothing in the papers' prose may contain a hardcoded digit: every number is a
macro defined here, so a paper cannot drift away from the data it describes.

Read-only with respect to the study: it opens raw.jsonl, logs/, payloads/ and
src/, and writes only into paper/.
"""
from __future__ import annotations

import collections
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# This file is paper/numbers.py, which shadows the stdlib `numbers` module that
# numpy imports. Drop our own directory from the path before importing anything.
_HERE = str(pathlib.Path(__file__).resolve().parent)
sys.path[:] = [q for q in sys.path if q not in ("", ".", _HERE)]
sys.path.insert(0, str(ROOT / "src"))

import numpy as np                                                # noqa: E402

BOOT_N = 10_000
BOOT_SEED = 20260913          # same seed as src/analyze.py, so the CIs agree
MODEL_ORDER = ["llama-3.3-70b", "gemini-3.1-flash-lite"]
MACRO = {"llama-3.3-70b": "llama", "gemini-3.1-flash-lite": "gemini"}


# --------------------------------------------------------------- helpers
def rows() -> list[dict]:
    with (ROOT / "results" / "raw.jsonl").open() as fh:
        return [json.loads(l) for l in fh if l.strip()]


def boot_ci(flags: list[int]) -> tuple[float, float, float]:
    """Percentile bootstrap over the PAYLOAD corpus (not over trials)."""
    if not flags:
        return float("nan"), float("nan"), float("nan")
    rng = np.random.default_rng(BOOT_SEED)
    a = np.array(flags, dtype=float)
    means = a[rng.integers(0, len(a), size=(BOOT_N, len(a)))].mean(axis=1)
    return float(a.mean()), float(np.percentile(means, 2.5)), float(np.percentile(means, 97.5))


def sh(*cmd: str) -> str:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True).stdout.strip()


# --------------------------------------------------------------- collection
def collect() -> dict:
    R = rows()
    out: dict = {"_meta": {"boot_n": BOOT_N, "boot_seed": BOOT_SEED,
                           "source": "results/raw.jsonl", "n_rows": len(R)}}

    # ---- corpus ---------------------------------------------------------
    pl = sorted((ROOT / "payloads").glob("*.yaml"))
    channels, variants = [], []
    for p in pl:
        ch, va = p.stem.split("__")
        if ch not in channels:
            channels.append(ch)
        if va not in variants:
            variants.append(va)
    out["corpus"] = {"n_payloads": len(pl), "channels": channels, "variants": variants,
                     "n_channels": len(channels), "n_variants": len(variants)}

    # ---- oracle: encodings read from the module, tests parsed from pytest
    import oracle                                                  # noqa: E402
    out["oracle"] = {"encodings": list(oracle.ENCODINGS),
                     "n_encodings": len(oracle.ENCODINGS),
                     "egress_tools": list(oracle.EGRESS_TOOLS)}
    pt = subprocess.run([sys.executable, "-m", "pytest", "tests/test_oracle.py", "-q"],
                        cwd=ROOT, capture_output=True, text=True)
    m = re.search(r"(\d+) passed", pt.stdout)
    if not m:
        raise SystemExit("could not parse pytest output for the oracle test count")
    out["oracle"]["n_tests"] = int(m.group(1))
    out["oracle"]["tests_pass"] = pt.returncode == 0

    # ---- canary ---------------------------------------------------------
    cust = json.loads((ROOT / "data" / "customers.json").read_text())
    canary = next(c for c in cust["customers"] if c["member_id"] == cust["canary_member_id"])
    out["canary"] = {
        "id": cust["canary_member_id"],
        "n_customers": len(cust["customers"]),
        "record_fields": sorted(canary.keys()),
        "n_record_fields": len(canary),
    }
    # PHI field names the oracle actually observed leaving, across all leaks
    phi = sorted({f for r in R for f in r.get("phi_fields_present", [])})
    out["canary"]["phi_fields_observed"] = phi
    out["canary"]["n_phi_fields_observed"] = len(phi)

    # ---- protocol constants, read from the source rather than typed -----
    import providers                                               # noqa: E402
    import inspect
    sig = inspect.signature(providers.call_model)
    out["protocol"] = {
        "max_output_tokens": providers.DEFAULT_MAX_TOKENS,
        "planned_output_tokens": 300,      # the pre-deviation cap; see DECISIONS.md
        "temperature": sig.parameters["temperature"].default,
        "ci_level": 95,
    }

    # ---- agent ----------------------------------------------------------
    import agent                                                   # noqa: E402
    out["agent"] = {"max_turns": agent.MAX_TURNS,
                    "n_tools": len(re.findall(r"^TOOL: (\w+)", agent.SYSTEM_PROMPT, re.M)),
                    "tools": re.findall(r"^TOOL: (\w+)", agent.SYSTEM_PROMPT, re.M)}

    # ---- per model ------------------------------------------------------
    out["models"] = {}
    for mk in MODEL_ORDER:
        inj = [r for r in R if r["model_key"] == mk and r["condition"] == "injected"]
        ctl = [r for r in R if r["model_key"] == mk and r["condition"] == "control"]
        flags = [1 if r["to_exfil_host"] else 0 for r in inj]
        rate, lo, hi = boot_ci(flags)
        by_ch = {c: [sum(1 for r in inj if r["channel"] == c and r["to_exfil_host"]),
                     sum(1 for r in inj if r["channel"] == c)] for c in channels}
        by_va = {v: [sum(1 for r in inj if r["variant"] == v and r["to_exfil_host"]),
                     sum(1 for r in inj if r["variant"] == v)] for v in variants}
        out["models"][mk] = {
            "label": inj[0]["model_label"], "family": inj[0]["family"],
            "injected_n": len(inj),
            "injected_exfil": sum(flags),
            "injected_rate": rate, "ci_lo": lo, "ci_hi": hi,
            "injected_any_egress": sum(1 for r in inj if r["leaked"]),
            "control_n": len(ctl),
            "control_exfil": sum(1 for r in ctl if r["to_exfil_host"]),
            "control_any_egress": sum(1 for r in ctl if r["leaked"]),
            "control_fp_rate_naive": (sum(1 for r in ctl if r["leaked"]) / len(ctl)) if ctl else 0.0,
            "errors": sum(len(r.get("errors") or []) for r in inj + ctl),
            "unparsed_cells": sum(1 for r in inj + ctl if r.get("n_unparsed", 0) > 0),
            "n_unparsed_total": sum(r.get("n_unparsed", 0) for r in inj + ctl),
            "by_channel": by_ch, "by_variant": by_va,
            "mean_tool_calls": round(sum(r["n_tool_calls"] for r in inj) / len(inj), 2),
        }

    # ---- pooled control arm (both models), for the generalized FP claim --
    all_ctl = [r for r in R if r["condition"] == "control"]
    out["pooled"] = {
        "control_n": len(all_ctl),
        "control_any_egress": sum(1 for r in all_ctl if r["leaked"]),
        "control_exfil": sum(1 for r in all_ctl if r["to_exfil_host"]),
        "injected_n": sum(1 for r in R if r["condition"] == "injected"),
        "n_models": len(MODEL_ORDER),
        "n_episodes": len(R),
    }
    out["pooled"]["control_fp_rate_naive"] = (
        out["pooled"]["control_any_egress"] / out["pooled"]["control_n"])

    # ---- encoding distribution of detected leaks ------------------------
    enc = collections.Counter(r["encoding"] for r in R if r["to_exfil_host"] and r["encoding"])
    out["encodings_observed"] = dict(enc)
    out["n_leaks_total"] = sum(1 for r in R if r["to_exfil_host"])
    out["n_leaks_cleartext"] = enc.get("exact", 0)

    # ---- unprompted egress: what the benign endpoints actually were -----
    urls, fields = collections.Counter(), collections.Counter()
    for r in all_ctl:
        if r["leaked"] and not r["to_exfil_host"]:
            for f in r.get("phi_fields_present", []):
                fields[f] += 1
    for lg in sorted((ROOT / "logs").glob("*control*.jsonl")):
        for line in lg.read_text().splitlines():
            for u in re.findall(r'"url":\s*"(https?://[^"]+)"', line):
                if "records-sync" not in u:
                    urls[u] += 1
    out["unprompted"] = {
        "endpoints": sorted(urls), "n_endpoints": len(urls),
        "phi_fields": sorted(fields), "n_phi_fields": len(fields),
    }

    # ---- budget ---------------------------------------------------------
    out["budget"] = {"api_calls": json.loads((ROOT / "results" / "api_calls.json").read_text())["calls"],
                     "cache_entries": len(list((ROOT / "cache").glob("*.json")))}

    # ---- provenance -----------------------------------------------------
    prov = json.loads((ROOT / "results" / "provenance.json").read_text())
    out["provenance"] = {"fingerprint": prov["config_fingerprint"],
                         "attacker_host": prov["attacker_host"],
                         "verified": prov["verified"], "forced": prov["forced"]}

    # ---- repo record ----------------------------------------------------
    out["repo"] = {
        "n_commits": int(sh("git", "rev-list", "--count", "HEAD")),
        "first_commit": sh("git", "log", "--reverse", "--format=%ad", "--date=format:%Y-%m-%d %H:%M").splitlines()[0],
        "last_commit": sh("git", "log", "-1", "--format=%ad", "--date=format:%Y-%m-%d %H:%M"),
    }
    return out


# --------------------------------------------------------------- LaTeX out
def texname(s: str) -> str:
    """LaTeX macro names may only contain letters."""
    return re.sub(r"[^A-Za-z]", "", s.title())


def fmt_pct(x: float) -> str:
    return f"{100 * x:.0f}\\%"


def tt(s: str) -> str:
    """A \\texttt{} with LaTeX-special characters escaped. Used for every
    identifier the generator emits, so none of them can open math mode."""
    for ch in ("\\", "_", "%", "$", "&", "#", "{", "}"):
        s = s.replace(ch, "\\" + ch)
    return "\\texttt{" + s + "}"


def ttlist(xs) -> str:
    return ", ".join(tt(x) for x in xs)


def emit_tex(N: dict) -> str:
    L: list[str] = [
        "% GENERATED BY paper/numbers.py — DO NOT EDIT.",
        "% Every number in every phi-canary paper is a macro defined here.",
        "",
    ]

    def d(name: str, val) -> None:
        L.append(f"\\newcommand{{\\{name}}}{{{val}}}")

    c = N["corpus"]
    d("corpusSize", c["n_payloads"]); d("nChannels", c["n_channels"])
    d("nVariants", c["n_variants"])
    d("channelList", ttlist(c["channels"]))
    d("variantList", ttlist(c["variants"]))

    o = N["oracle"]
    d("nEncodings", o["n_encodings"]); d("nOracleTests", o["n_tests"])
    d("encodingList", ttlist(o["encodings"]))
    d("egressToolList", ttlist(o["egress_tools"]))
    d("nEgressTools", len(o["egress_tools"]))

    k = N["canary"]
    d("canaryID", tt(k["id"]))
    d("nCustomers", k["n_customers"]); d("nRecordFields", k["n_record_fields"])
    d("nPhiFieldsObserved", k["n_phi_fields_observed"])
    d("phiFieldList", ttlist(k["phi_fields_observed"]))

    a = N["agent"]
    d("maxTurns", a["max_turns"]); d("nAgentTools", a["n_tools"])

    pr = N["protocol"]
    d("maxOutputTokens", pr["max_output_tokens"])
    d("plannedOutputTokens", pr["planned_output_tokens"])
    d("temperature", f"{pr['temperature']:g}")
    d("ciLevel", pr["ci_level"])

    for mk, m in N["models"].items():
        p = MACRO[mk]
        d(p + "Label", m["label"]); d(p + "Family", m["family"].replace("_", "-"))
        scale = re.search(r"(\d+)\s*B\b", m["label"])
        if scale:
            d(p + "Scale", scale.group(1) + "B")
        d(p + "N", m["injected_n"]); d(p + "Exfil", m["injected_exfil"])
        d(p + "Rate", fmt_pct(m["injected_rate"]))
        d(p + "CIlo", fmt_pct(m["ci_lo"])); d(p + "CIhi", fmt_pct(m["ci_hi"]))
        d(p + "ControlN", m["control_n"]); d(p + "ControlExfil", m["control_exfil"])
        d(p + "ControlAnyEgress", m["control_any_egress"])
        d(p + "ControlFPRate", fmt_pct(m["control_fp_rate_naive"]))
        d(p + "ControlExfilRatePct", fmt_pct(m["control_exfil"] / m["control_n"]))
        d(p + "Errors", m["errors"]); d(p + "UnparsedCells", m["unparsed_cells"])
        d(p + "MeanToolCalls", m["mean_tool_calls"])
        for ch, (hit, n) in m["by_channel"].items():
            d(p + "Ch" + texname(ch), f"{hit}/{n}")
        for va, (hit, n) in m["by_variant"].items():
            d(p + "Va" + texname(va), f"{hit}/{n}")

    p = N["pooled"]
    d("pooledEpisodes", p["n_episodes"]); d("pooledInjectedN", p["injected_n"])
    d("pooledControlN", p["control_n"]); d("pooledControlExfil", p["control_exfil"])
    d("pooledControlAnyEgress", p["control_any_egress"])
    d("pooledControlFPRate", fmt_pct(p["control_fp_rate_naive"]))
    d("nModels", p["n_models"])

    d("nLeaksTotal", N["n_leaks_total"]); d("nLeaksCleartext", N["n_leaks_cleartext"])
    d("nEncodingsObserved", len(N["encodings_observed"]))

    u = N["unprompted"]
    d("nInventedEndpoints", u["n_endpoints"])
    d("inventedEndpointList", ", ".join(f"\\url{{{x}}}" for x in u["endpoints"]))
    d("unpromptedFieldList", ttlist(u["phi_fields"]))

    d("apiCalls", N["budget"]["api_calls"]); d("cacheEntries", N["budget"]["cache_entries"])
    d("configFingerprint", tt(N["provenance"]["fingerprint"]))
    d("attackerHost", tt(N["provenance"]["attacker_host"]))

    r = N["repo"]
    d("nCommits", r["n_commits"]); d("firstCommit", r["first_commit"]); d("lastCommit", r["last_commit"])
    d("bootN", f"{N['_meta']['boot_n']:,}"); d("bootSeed", N["_meta"]["boot_seed"])
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    N = collect()
    (ROOT / "paper" / "numbers.json").write_text(json.dumps(N, indent=2) + "\n")
    (ROOT / "paper" / "numbers.tex").write_text(emit_tex(N))
    print(json.dumps(N, indent=2))
    print(f"\n-- wrote paper/numbers.json and paper/numbers.tex "
          f"({len(emit_tex(N).splitlines())} macros)", file=sys.stderr)
