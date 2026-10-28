"""Pun MCP stdio server; zero outbound test traffic originates in Python."""
from __future__ import annotations

from mcp.server import MCPServer

from .authgraph import authorization_graph, endpoints, assess_replay
from .bridge import PunBridge
from .logichunter import discover_workflows, create_plan, workflow_state_graph
from .intelligence import correlate_sessions, deep_security_analysis
from .reports import report_markdown

mcp = MCPServer("Pun — AuthGraph + LogicHunter")


def _snapshot() -> list[dict]:
    return PunBridge().traffic()["items"]


@mcp.tool()
def pun_health() -> dict:
    """Verify that the local Burp extension is running and scope is configured."""
    return PunBridge().health()


@mcp.tool()
def list_endpoints() -> list[dict]:
    """Inventory observed in-scope HTTP routes, methods and parameter names (no secrets)."""
    return endpoints(_snapshot())


@mcp.tool()
def list_observed_requests(limit: int = 50) -> list[dict]:
    """Get sanitized metadata from recent captured traffic; never returns raw HTTP bodies."""
    limit = max(1, min(100, limit))
    return _snapshot()[-limit:]


@mcp.tool()
def list_roles() -> list[str]:
    """List locally configured test role names, never their authentication secrets."""
    return PunBridge().roles()["roles"]


@mcp.tool()
def analyze_authgraph() -> dict:
    """Rank ownership and role-boundary test hypotheses, not confirmed security bugs."""
    return authorization_graph(_snapshot())


@mcp.tool()
def discover_logic_workflows(limit: int = 10) -> list[dict]:
    """Infer candidate workflows from chronological traffic without replaying them."""
    return discover_workflows(_snapshot(), max_workflows=max(1, min(20, limit)))


@mcp.tool()
def plan_logic_test(request_ids: list[str]) -> dict:
    """Suggest skip/reorder/duplicate tests for a known observed sequence; no requests sent."""
    return create_plan(request_ids, _snapshot())


@mcp.tool()
def queue_auth_replay(request_id: str, role: str, reason: str) -> dict:
    """Queue ONE unchanged-URL replay with a named local test session; requires Burp UI approval."""
    return PunBridge().prepare_replay(request_id, role, reason)


@mcp.tool()
def replay_status(job_id: str) -> dict:
    """Show queued or completed replay status, with a conservative comparison and no raw bodies."""
    jobs = PunBridge().jobs()["jobs"]
    job = next((j for j in jobs if j.get("id") == job_id), None)
    if job is None:
        return {"error": "Job not found"}
    base = next((r for r in _snapshot() if r.get("id") == job.get("request_id")), None)
    return {"job": job, "assessment": assess_replay(base or {}, job)}


@mcp.tool()
def draft_evidence_report(job_id: str) -> str:
    """Create unverified Markdown evidence for a completed manually approved replay."""
    jobs = PunBridge().jobs()["jobs"]
    job = next((j for j in jobs if j.get("id") == job_id), None)
    if not job:
        raise ValueError("Unknown job ID")
    baseline = next((r for r in _snapshot() if r.get("id") == job.get("request_id")), None)
    if not baseline:
        raise ValueError("Baseline request has been evicted")
    return report_markdown(baseline, job)


@mcp.tool()
def analyze_pun_deep() -> dict:
    """Cross-request role matrix, high-priority hypotheses, workflow gaps and cookie structure; passive only."""
    return deep_security_analysis(_snapshot())


@mcp.tool()
def inspect_cookie_metadata(request_id: str) -> dict:
    """Show redacted cookie encodings, hash-family hints and JWT claim NAMES, never decoded values."""
    row = next((r for r in _snapshot() if r.get("id") == request_id), None)
    if row is None:
        return {"error": "Unknown request ID"}
    return {"request_id": request_id,
            "request_cookies": row.get("cookie_insights") or [],
            "response_set_cookies": row.get("set_cookie_insights") or [],
            "decoded_values": "Not exposed by MCP. Select the traffic row and click 'Decode cookies locally' in Burp."}


@mcp.tool()
def correlate_cookie_sessions() -> dict:
    """Analyze pseudonymous HMAC cookie equality, encoding types and JWT review hints over observed traffic."""
    return correlate_sessions(_snapshot())


@mcp.tool()
def observed_workflow_graph(max_edges: int = 60) -> dict:
    """Observed state transitions from HTTP metadata only, without assuming causality."""
    return workflow_state_graph(_snapshot(), max_edges=max_edges)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
