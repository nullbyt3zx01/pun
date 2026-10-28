"""Workflow inference and hypothesis generation from chronological HTTP metadata."""
from __future__ import annotations

import re
from collections import defaultdict

from .authgraph import normalize_path

MUTATIONS = {"POST", "PUT", "PATCH", "DELETE"}
STATES = {
    "create": re.compile(r"(?i)(create|new|register|signup|add|cart)"),
    "modify": re.compile(r"(?i)(edit|update|change|modify|quantity|address)"),
    "authorize": re.compile(r"(?i)(login|verify|otp|authorize|approve|confirm)"),
    "pay": re.compile(r"(?i)(checkout|payment|purchase|pay|charge)"),
    "refund": re.compile(r"(?i)(refund|reverse|cancel|return)"),
    "complete": re.compile(r"(?i)(submit|finish|complete|activate|ship)"),
}


def classify(row: dict) -> list[str]:
    candidate = (row.get("path") or "") + " " + " ".join(row.get("input_keys") or [])
    return [name for name, expression in STATES.items() if expression.search(candidate)] or [
        "mutate" if row.get("method") in MUTATIONS else "read"]


def discover_workflows(traffic: list[dict], max_workflows: int = 15) -> list[dict]:
    # This is a behavioral heuristic, not a verified session/transaction correlation.
    buckets = defaultdict(list)
    for row in sorted(traffic, key=lambda r: r.get("timestamp", 0)):
        if row.get("status", 999) >= 400:
            continue
        host = row.get("host")
        if not host:
            continue
        # Use observed role to avoid merging different test users wherever possible.
        buckets[(host, row.get("role", "unknown"))].append(row)
    out = []
    for (host, role), rows in buckets.items():
        chunk = []
        for row in rows:
            if not chunk or row.get("timestamp", 0) - chunk[-1].get("timestamp", 0) <= 900_000:
                chunk.append(row)
            else:
                _add_chunk(out, host, role, chunk)
                chunk = [row]
        _add_chunk(out, host, role, chunk)
    return sorted(out, key=lambda x: (-len(x["steps"]), x["first_timestamp"]))[:max_workflows]


def _add_chunk(out: list[dict], host: str, role: str, rows: list[dict]):
    meaningful = [r for r in rows if r.get("method") in MUTATIONS or len(classify(r)) and classify(r)[0] not in {"read"}]
    if len(meaningful) < 2:
        return
    selected = meaningful[-10:]
    out.append({"host": host, "role": role, "first_timestamp": selected[0].get("timestamp"),
                "steps": [{"request_id": r.get("id"), "method": r.get("method"),
                           "path": normalize_path(r.get("path", "/")),
                           "possible_actions": classify(r)} for r in selected],
                "status": "inferred sequence; not a verified business transaction"})


def create_plan(request_ids: list[str], traffic: list[dict]) -> dict:
    by_id = {row["id"]: row for row in traffic if "id" in row}
    if not (2 <= len(request_ids) <= 10):
        raise ValueError("Choose 2 to 10 observed request IDs")
    if len(set(request_ids)) != len(request_ids):
        raise ValueError("Request IDs must be unique")
    try:
        selected = [by_id[id_] for id_ in request_ids]
    except KeyError as exc:
        raise ValueError(f"Unknown request ID: {exc.args[0]}") from exc
    if len({r.get("host") for r in selected}) != 1:
        raise ValueError("All requests must belong to the same host")
    if len({r.get("role", "unknown") for r in selected}) != 1:
        raise ValueError("Select requests from one observed role/session label")
    if [r.get("timestamp") for r in selected] != sorted(r.get("timestamp") for r in selected):
        raise ValueError("Select steps in chronological order")
    phases = [classify(r) for r in selected]
    hypotheses = [
        {"type": "step_skip", "idea": "Can a later step succeed without an earlier prerequisite?",
         "verification": "Use a disposable test account and resettable objects; compare server-side state."},
        {"type": "step_reorder", "idea": "Does submitting steps in a different order bypass a transition guard?",
         "verification": "Try a single manually approved deviation, then verify final state."},
    ]
    if any(r.get("method") in MUTATIONS for r in selected):
        hypotheses.append({"type": "duplicate_action", "idea": "Is an important mutation idempotent?",
                           "verification": "Only test duplicate submissions on dedicated non-financial test data after approval."})
    return {"host": selected[0].get("host"), "observed_sequence": [
        {"id": r["id"], "method": r.get("method"), "path": r.get("path"),
         "status": r.get("status"), "phases": p} for r, p in zip(selected, phases)],
            "hypotheses": hypotheses, "execution": "not executed; each replay must be queued and approved in Burp",
            "warning": "Inferred from traffic only; session/state dependencies and side effects require human review."}


def workflow_state_graph(traffic: list[dict], max_edges: int = 100) -> dict:
    """Build an observed action-transition graph; edges imply sequence, never causality."""
    transitions = defaultdict(lambda: {"count": 0, "pairs": []})
    for flow in discover_workflows(traffic, max_workflows=30):
        for earlier, later in zip(flow["steps"], flow["steps"][1:]):
            source = earlier["possible_actions"][0]
            target = later["possible_actions"][0]
            key = (flow["host"], flow["role"], source, target)
            item = transitions[key]
            item["count"] += 1
            if len(item["pairs"]) < 5:
                item["pairs"].append([earlier["request_id"], later["request_id"]])
    edges = [{"host": host, "role": role, "from_action": frm, "to_action": to,
              **data} for (host, role, frm, to), data in transitions.items()]
    edges.sort(key=lambda e: (-e["count"], e["host"], e["role"]))
    return {"edges": edges[:max(1, min(100, max_edges))],
            "caveat": "Edges are ordering observations within 15-minute capture windows; they do not prove object identity, session validity, or bypass."}
