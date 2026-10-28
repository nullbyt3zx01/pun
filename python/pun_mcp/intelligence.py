"""Conservative cross-request intelligence using metadata only; no network actions."""
from __future__ import annotations

from collections import Counter, defaultdict
from .authgraph import endpoints, ID_KEY, SENSITIVE_HINTS
from .logichunter import classify, discover_workflows


def correlate_sessions(traffic: list[dict]) -> dict:
    """Pseudonymous per-Burp-restart cookie values correlate traffic, not identity."""
    by_fingerprint: dict[str, list[dict]] = defaultdict(list)
    cookie_types = Counter()
    alerts = []
    lifecycle = []
    for row in traffic:
        for item in row.get("cookie_insights") or []:
            name = item.get("name")
            if not name:
                continue
            cookie_types[(name, item.get("structure", "text"))] += 1
            fp = item.get("fingerprint")
            if fp:
                by_fingerprint[f"{name}:{fp}"].append(row)
            if (item.get("jwt") or {}).get("algorithm", "").lower() == "none":
                alerts.append({"request_id": row.get("id"), "cookie": name,
                               "hypothesis": "JWT alg=none observed; signature enforcement unknown",
                               "confirmed": False})
        # Compare same-named request and response cookies around login-like events.
        # This is an observation of re-issuance, NOT proof of session fixation.
        path = (row.get("path") or "").lower()
        if any(word in path for word in ("login", "signin", "authenticate", "session/refresh", "verify")):
            incoming = {e.get("name"): e.get("fingerprint") for e in (row.get("cookie_insights") or [])}
            for outgoing in row.get("set_cookie_insights") or []:
                name, new_fp = outgoing.get("name"), outgoing.get("fingerprint")
                if not name or not new_fp:
                    continue
                old_fp = incoming.get(name)
                if not old_fp:
                    state = "new_cookie_issued"
                elif old_fp == new_fp:
                    state = "same_cookie_reissued"
                else:
                    state = "cookie_value_changed"
                lifecycle.append({"request_id": row.get("id"), "cookie": name,
                                  "event": state,
                                  "review_hint": "Check expected session rotation on YOUR test accounts; observed cookie equality is not a session fixation finding"})
    pattern_rows = []
    for (name, structure), count in cookie_types.most_common(50):
        pattern_rows.append({"cookie_name": name, "structure": structure, "observations": count})
    correlations = []
    for label, rows in by_fingerprint.items():
        if len(rows) < 2:
            continue
        distinct_roles = sorted({r.get("role", "unknown") for r in rows})
        unique_hosts = sorted({r.get("host", "") for r in rows})
        correlations.append({"pseudonymous_cookie": label, "request_count": len(rows),
                             "roles": distinct_roles, "hosts": unique_hosts,
                             "review_hint": "Multiple observed role labels share a cookie fingerprint;"
                                            " may be a labeling issue, shared cookie, or session handling issue"
                                            if len(distinct_roles) > 1 else "Repeated cookie observation"})
    return {"cookie_types": pattern_rows, "correlations": correlations[:60], "alerts": alerts[:30],
            "session_lifecycle_hints": lifecycle[:40],
            "limitations": ["Fingerprints are short keyed HMAC aliases, not raw cookies.",
                            "Cookie equality across roles is not proof of session fixation or auth bypass."]}


def deep_security_analysis(traffic: list[dict]) -> dict:
    """Prioritize multi-request hypotheses with explicit evidence, never assert exploitation."""
    inventory = endpoints(traffic)
    flows = discover_workflows(traffic, max_workflows=25)
    by_host_pattern = defaultdict(list)
    for row in traffic:
        if not row.get("host"):
            continue
        from .authgraph import normalize_path
        key = (row["host"], row.get("method", ""), normalize_path(row.get("path", "/")))
        by_host_pattern[key].append(row)
    hypotheses = []
    matrices = []
    for route in inventory:
        key = (route["host"], route["method"], route["path_pattern"])
        rows = by_host_pattern[key]
        role_status: dict[str, dict] = {}
        for row in rows:
            entry = role_status.setdefault(row.get("role", "unknown"), {"observed": 0, "statuses": set(), "request_ids": []})
            entry["observed"] += 1
            entry["statuses"].add(row.get("status"))
            entry["request_ids"].append(row.get("id"))
        matrix = {role: {"observed": item["observed"], "statuses": sorted(s for s in item["statuses"] if isinstance(s, int)),
                         "request_ids": item["request_ids"][-5:]} for role, item in role_status.items()}
        matrices.append({"host": route["host"], "endpoint": route["method"] + " " + route["path_pattern"], "by_role": matrix})
        ids = [r.get('id') for r in rows if r.get('id')]
        keys = route["input_keys"] + route["output_keys"]
        owner = '{id}' in route['path_pattern'] or any(ID_KEY.search(k) for k in route['input_keys'])
        sensitive = any(SENSITIVE_HINTS.search(k) for k in route['output_keys'])
        denied = any(any(c in {401, 403} for c in item['statuses']) for item in matrix.values())
        allowed = any(any(200 <= c < 300 for c in item['statuses']) for item in matrix.values())
        cross_role = len(matrix) > 1
        if not owner and not (cross_role and denied and allowed):
            continue
        score = 20 + (25 if owner else 0) + (15 if sensitive else 0) + (15 if cross_role else 0) + (15 if denied and allowed else 0)
        hypotheses.append({"category": "authorization_boundary", "priority_score": min(score, 90),
                           "endpoint": route['method'] + ' ' + route['path_pattern'], "host": route['host'],
                           "observed_request_ids": ids[-6:], "role_evidence": matrix,
                           "why": [item for item, yes in [
                               ("Object identifier or owner-like parameter", owner),
                               ("Sensitive-looking output key names", sensitive),
                               ("Same route seen across different role labels", cross_role),
                               ("Both access-denied and success HTTP statuses seen", denied and allowed)] if yes],
                           "next_step": "Use two owned test objects to compare identity and server-side authorization; review exact response body locally",
                           "confirmed": False})
    for flow in flows:
        steps = flow['steps']
        phases = [set(s['possible_actions']) for s in steps]
        seen_authorize = any('authorize' in phases[j] for j in range(max(0, len(steps)-1)))
        if any('pay' in p or 'complete' in p or 'refund' in p for p in phases) and not seen_authorize:
            hypotheses.append({"category": "workflow_prerequisite", "priority_score": 60,
                               "host": flow['host'], "observed_request_ids": [s['request_id'] for s in steps],
                               "why": ["A high-impact workflow step is visible without an earlier verification step in the capture window"],
                               "next_step": "Review full server-side history and test on resettable staging data; missing traffic is not a missing check",
                               "confirmed": False})
        seen_complete = False
        for step in steps:
            types = set(step['possible_actions'])
            if seen_complete and (types & {'modify','refund','pay'}):
                hypotheses.append({"category": "post_completion_transition", "priority_score": 65,
                                   "host": flow['host'], "observed_request_ids": [s['request_id'] for s in steps],
                                   "why": ["Potential mutation follows a completion-like action in the observed timeline"],
                                   "next_step": "Determine if requests belong to the same object; confirm expected transition rules manually",
                                   "confirmed": False})
                break
            if 'complete' in types:
                seen_complete = True
    return {"hypotheses": sorted(hypotheses, key=lambda v: -v['priority_score'])[:80],
            "role_endpoint_matrix": matrices[:100], "inferred_workflows": flows,
            "session_intelligence": correlate_sessions(traffic),
            "limitations": ["Scores are heuristic triage priorities, not CVSS or severity.",
                            "Only metadata and bounded redacted cookie structure is available to MCP.",
                            "Unobserved workflow events cannot be treated as absent controls.",
                            "No replay is performed by this tool."]}
