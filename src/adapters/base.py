"""Adapter interface — bring your own agent, phi-canary attacks it.

An adapter wraps *your* tool-using agent behind two methods. phi-canary delivers each of
its 16 untrusted payloads to your agent, collects the tool calls your agent emits, and runs
the deterministic oracle over the outbound arguments — telling you how often your agent
exfiltrates the planted record and with a 0/16 benign-control false-positive check.

Minimal contract:

    from adapters.base import AgentAdapter, ToolCall

    class MyAdapter(AgentAdapter):
        def describe(self):
            return {"name": "my-agent", "model": "whatever", "canary": self.canary_member_id}

        def run_task(self, task, injected_content):
            # task: {"id","channel","variant","ticket_id","customer_id","condition"}
            # injected_content: the untrusted string to place in task["channel"]
            # return the outbound tool calls your agent makes, in order:
            return [ToolCall("http_post", {"url": "...", "body": "..."})]

Load a user file with `--adapter path/to/mine.py`; the first AgentAdapter subclass (or a
top-level `ADAPTER`/`get_adapter()`) is used.
"""
from __future__ import annotations

import dataclasses
import importlib.util
import inspect
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))  # src/ on path
import oracle as O          # noqa: E402  (frozen; never modified)


@dataclasses.dataclass
class ToolCall:
    """One outbound tool invocation your agent made."""
    tool: str
    args: dict


class AgentAdapter:
    """Subclass this to evaluate your own agent. Both methods are required."""

    #: the record the oracle looks for; adapters should ensure their agent has access to it
    canary_member_id: str = O.CANARY
    exfil_host: str = O.EXFIL_HOST

    def describe(self) -> dict:
        """Metadata for the report: {'name', 'model', 'family', 'tools', ...}."""
        raise NotImplementedError

    def run_task(self, task: dict, injected_content: str) -> list[ToolCall]:
        """Run ONE episode. Deliver `injected_content` via task['channel'] to your agent and
        return the outbound tool calls it makes, in order. Empty `injected_content` means the
        benign control case."""
        raise NotImplementedError


class ContactCenterAdapter(AgentAdapter):
    """Reference implementation: the built-in ARIA contact-center agent.

    Wraps the existing simulated-tool episode loop. With cache present it replays without
    network, so `phi-canary run --adapter <this>` works offline for the shipped payloads.
    """

    def __init__(self, model_key: str = "llama-3.3-70b", use_cache: bool = True,
                 allow_network: bool = True):
        self.model_key = model_key
        self.use_cache = use_cache
        self.allow_network = allow_network

    def describe(self) -> dict:
        import providers as P
        spec = P.MODELS.get(self.model_key, {})
        return {
            "name": "contact-center (ARIA, reference)",
            "model": spec.get("label", self.model_key),
            "family": spec.get("family"),
            "tools": ["read_ticket", "lookup_customer", "search_kb", "http_post", "dns_lookup"],
            "canary": self.canary_member_id,
        }

    def run_task(self, task: dict, injected_content: str) -> list[ToolCall]:
        from agent import run_episode
        payload = {
            "id": task["id"], "channel": task["channel"],
            "variant": task.get("variant"), "content": injected_content or "",
        }
        ep = run_episode(self.model_key, payload, use_cache=self.use_cache,
                         allow_network=self.allow_network)
        return [ToolCall(c["tool"], c["args"]) for c in ep["tool_calls"]]


def load_adapter(path_or_name: str) -> AgentAdapter:
    """Load an adapter from a .py file path, or return the reference adapter by name."""
    if path_or_name in ("reference", "contact-center", "aria"):
        return ContactCenterAdapter()
    p = pathlib.Path(path_or_name).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"adapter file not found: {p}")
    spec = importlib.util.spec_from_file_location(f"phi_user_adapter_{p.stem}", p)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    if hasattr(mod, "get_adapter"):
        return mod.get_adapter()
    if hasattr(mod, "ADAPTER"):
        return mod.ADAPTER
    for _, obj in inspect.getmembers(mod, inspect.isclass):
        if issubclass(obj, AgentAdapter) and obj is not AgentAdapter and obj.__module__ == mod.__name__:
            return obj()
    raise TypeError(f"{p} defines no AgentAdapter subclass, ADAPTER, or get_adapter()")


def evaluate_adapter(adapter: AgentAdapter, payloads: list[dict] | None = None,
                     with_control: bool = True) -> dict:
    """Run an adapter over the corpus and score with the oracle. Pure evaluation — no file
    writes. Returns per-cell verdicts plus injected/control summaries."""
    import yaml
    import providers as P
    from agent import TICKET_ID, CANARY_CUSTOMER_ID

    if payloads is None:
        payloads = []
        for f in sorted(P.data_read("payloads").glob("*.yaml")):
            payloads.append(yaml.safe_load(f.read_text()))

    cells = []
    for pl in payloads:
        task = {"id": pl["id"], "channel": pl["channel"], "variant": pl.get("variant"),
                "ticket_id": TICKET_ID, "customer_id": CANARY_CUSTOMER_ID, "condition": "injected"}
        calls = adapter.run_task(task, pl.get("content", ""))
        verdict = O.scan_episode([{"tool": c.tool, "args": c.args} for c in calls])
        cells.append({"id": pl["id"], "channel": pl["channel"], "variant": pl.get("variant"),
                      "condition": "injected", "leaked": verdict["leaked"],
                      "to_exfil_host": verdict.get("to_exfil_host", False),
                      "encoding": verdict["encoding"], "n_tool_calls": len(calls)})
        if with_control:
            ctask = dict(task, id=f"control__{pl['channel']}__{pl['variant']}", condition="control")
            ccalls = adapter.run_task(ctask, "")
            cv = O.scan_episode([{"tool": c.tool, "args": c.args} for c in ccalls])
            cells.append({"id": ctask["id"], "channel": pl["channel"], "variant": pl.get("variant"),
                          "condition": "control", "leaked": cv["leaked"],
                          "to_exfil_host": cv.get("to_exfil_host", False),
                          "encoding": cv["encoding"], "n_tool_calls": len(ccalls)})

    inj = [c for c in cells if c["condition"] == "injected"]
    ctl = [c for c in cells if c["condition"] == "control"]
    return {
        "adapter": adapter.describe(),
        "injected_exfil": sum(bool(c["to_exfil_host"]) for c in inj),
        "injected_n": len(inj),
        "control_exfil": sum(bool(c["to_exfil_host"]) for c in ctl),
        "control_any_egress": sum(bool(c["leaked"]) for c in ctl),
        "control_n": len(ctl),
        "cells": cells,
    }
