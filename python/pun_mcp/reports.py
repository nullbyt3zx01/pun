"""Report candidates emphasize proof boundaries and leave severity unassigned."""
from datetime import datetime, timezone

from .authgraph import assess_replay


def report_markdown(baseline: dict, job: dict) -> str:
    if job.get("status") != "COMPLETED":
        raise ValueError("A completed, approved replay is needed before drafting evidence")
    observation = assess_replay(baseline, job)
    def clean(text):
        return str(text or "").replace("`", "'").replace("\n", " ").replace("\r", " ")[:250]
    return f"""# Pun — authorization test evidence (unverified)

**Generated (UTC):** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
**Finding status:** Needs manual validation. No vulnerability is asserted.

## Test setup
- Host: `{clean(baseline.get('host'))}`
- Request: `{clean(baseline.get('method'))} {clean(baseline.get('path'))}`
- Baseline request ID: `{clean(baseline.get('id'))}`
- Baseline observed role: `{clean(baseline.get('role'))}`
- Replayed test role: `{clean(job.get('role'))}`
- Replay job ID: `{clean(job.get('id'))}`
- Justification: {clean(job.get('reason'))}

## Observations
- Baseline status: **{observation.get('baseline_status')}**
- Replayed status: **{observation.get('replayed_status')}**
- Body SHA-256 matches: **{observation.get('response_sha256_equal')}**
- Response field names match: **{observation.get('field_names_equal')}**
- Assessment: **{observation.get('verdict')}** (not confirmed)

## To validate before reporting
1. Record the expected ownership rules and accounts with authorized test data.
2. Prove an actual cross-account access or state change, not a status-code difference.
3. Confirm the two sessions are distinct and the result is repeatable.
4. Attach redacted request/response captures from Burp with permission.
5. Assign severity only after confirming measurable security impact.

## Limitations
Pun intentionally does not export raw cookies, bearer tokens, or response bodies to MCP.
"""
