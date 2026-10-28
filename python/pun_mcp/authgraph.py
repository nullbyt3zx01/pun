"""Conservative authorization inventory, never equates HTTP 200 with an IDOR."""
from __future__ import annotations

import re
from collections import defaultdict

ID_PATH = re.compile(r"(?i)^(?:[0-9]{2,}|[a-f0-9]{8}-[a-f0-9-]{20,}|[a-f0-9]{16,})$")
ID_KEY = re.compile(r"(?i)(?:^id$|_id$|Id$|owner|tenant|account|organi[sz]ation|user|project|invoice|order)")
SENSITIVE_HINTS = re.compile(r"(?i)(?:password|ssn|token|api.?key|secret|phone|email|address|payment|balance)")


def normalize_path(path: str) -> str:
    path = path.split("?", 1)[0] or "/"
    segments = path.split("/")
    return "/".join("{id}" if ID_PATH.fullmatch(seg) else seg for seg in segments)


def endpoints(traffic: list[dict]) -> list[dict]:
    groups = {}
    for row in traffic:
        key = (row.get("host", ""), row.get("method", ""), normalize_path(row.get("path", "/")))
        if key not in groups:
            groups[key] = {"host": key[0], "method": key[1], "path_pattern": key[2],
                           "request_ids": [], "observed_count": 0, "roles_observed": set(), "status_codes": set(),
                           "input_keys": set(), "output_keys": set()}
        item = groups[key]
        item["request_ids"].append(row.get("id"))
        item["observed_count"] += 1
        item["roles_observed"].add(row.get("role", "unknown"))
        item["status_codes"].add(row.get("status"))
        item["input_keys"].update(row.get("input_keys") or [])
        item["output_keys"].update(row.get("output_keys") or [])
    for item in groups.values():
        item["roles_observed"] = sorted(item["roles_observed"])
        item["status_codes"] = sorted(x for x in item["status_codes"] if x is not None)
        item["input_keys"] = sorted(item["input_keys"])
        item["output_keys"] = sorted(item["output_keys"])
        item["request_ids"] = item["request_ids"][-10:]
    return sorted(groups.values(), key=lambda e: (-e["observed_count"], e["path_pattern"]))


def authorization_graph(traffic: list[dict]) -> dict:
    inventory = endpoints(traffic)
    candidates = []
    roles = sorted(set(row.get("role", "unknown") for row in traffic))
    for route in inventory:
        path, method = route["path_pattern"], route["method"]
        keys = route["input_keys"] + route["output_keys"]
        object_ref = "{id}" in path or any(ID_KEY.search(k) for k in route["input_keys"])
        if not object_ref:
            continue
        hints = []
        if "{id}" in path:
            hints.append("object identifier in URL path")
        if any(ID_KEY.search(k) for k in route["input_keys"]):
            hints.append("ownership or tenant-like input field")
        if any(SENSITIVE_HINTS.search(k) for k in route["output_keys"]):
            hints.append("potentially sensitive output key (key name only)")
        candidates.append({"endpoint": method + " " + path, "host": route["host"],
                           "risk_hint": hints, "request_id": route["request_ids"][-1],
                           "suggested_test": "Compare owned and non-owned test objects across two authorized test accounts",
                           "classification": "untested authorization hypothesis", "confirmed": False})
    return {"observed_roles": roles, "endpoints": inventory, "test_candidates": candidates,
            "limitations": ["Traffic observation alone cannot establish vulnerability or ownership.",
                            "Replay results require manual interpretation and known test-account ownership."]}


def assess_replay(baseline: dict, job: dict) -> dict:
    """Produce a conservative comparison, not a vulnerability verdict."""
    if job.get("status") != "COMPLETED" or not job.get("result"):
        return {"job_status": job.get("status", "unknown"), "finding": "not evaluated"}
    result = job["result"]
    base_status = baseline.get("status")
    status = result.get("status")
    same_body = (bool(baseline.get("response_sha256")) and
                 baseline.get("response_sha256") == result.get("response_sha256"))
    same_shape = set(baseline.get("output_keys") or []) == set(result.get("output_keys") or [])
    accessible = isinstance(status, int) and 200 <= status < 300
    flags = []
    if accessible:
        flags.append("replayed response has 2xx status; this is not proof of unauthorized access")
    if same_body:
        flags.append("response digest matches the baseline")
    elif same_shape:
        flags.append("response field-name shape matches baseline; values may differ")
    return {"request_id": job.get("request_id"), "role_tested": job.get("role"),
            "baseline_status": base_status, "replayed_status": status,
            "response_sha256_equal": same_body, "field_names_equal": same_shape,
            "signals": flags, "confirmed": False,
            "verdict": "review_required" if accessible else "not_demonstrated",
            "next_step": "Use owned/non-owned test data and verify actual object content and permissions manually."}
