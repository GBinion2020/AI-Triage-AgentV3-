# Pipeline Loop Scratch Sheet

This is a step-by-step walkthrough of the operational loop, including the Jira automation feedback cycle.

## Main Triage Loop

1) Alert ingest
- Pull raw alerts from Elastic index `.alerts-security.alerts-*`.
- Map ECS fields into `NormalizedSecurityAlert`.

2) Pre-classification
- Reject empty or malformed alerts.
- Forward valid alerts to deterministic logic.

3) Signal engine
- Extract 50+ behavioral signals (execution, network, identity, defense evasion).
- Populate deterministic `analysis_signals`.

4) Governance checks
- Enforce tool permissions and investigation depth limits.
- Block disallowed tool calls.

5) MITRE RAG enrichment
- Search ATT&CK technique corpus via ChromaDB.
- Map techniques into context for planning.

6) Intake agent
- Gatekeeper for high-confidence benign cases.
- If benign with >95% confidence, auto-close.

7) Baseline queries (always first)
- Recent host alerts (last 24h).
- Host logs around alert timestamp (default +/- 3 minutes).

8) Investigation loop
- Investigation agent generates intent.
- Deterministic planner converts intent to narrow SIEM queries.
- Queries use quoted values and avoid duplicate calls.
- Tool executor runs SIEM/VT/CloudTrail tools.

9) Evidence capture
- Summarizer compresses tool outputs.
- Evidence appended to investigation state.
- Loop continues until confidence or token limits are met.

10) Reasoning + decision
- Reasoning agent synthesizes evidence.
- Risk scoring matrix calculates 0–100.
- Decision agent outputs summary, evidence table, score, classification, and action.

11) Reporting
- Email report sent via Resend.
- Audit trail saved to `audit_trail_[alert_id].json`.

## Jira Feedback Automation Loop

12) Analyst closure
- Analyst closes Jira issue with verdict and notes.
- Jira automation triggers webhook.

13) Feedback ingestion
- `feedback_api/app.py` accepts webhook.
- Payload is normalized into minimal feedback schema.

14) Feedback storage
- Normalized feedback stored in DB (SQLite by default).
- Keys: issue key, verdict, classification, close note.

15) Feedback retrieval on next alert
- Feedback RAG queries DB by alert name/description/host/user.
- `lessons_learned` injected into intake/investigation/reasoning agents.

16) Loop repeats
- Next alert starts at step 1 with additional historical context.
