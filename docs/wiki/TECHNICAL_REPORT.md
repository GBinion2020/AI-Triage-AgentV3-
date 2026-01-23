# Technical Report (Deep Dive)

This document is a highly technical, end-to-end description of the Enterprise Agentic SOC pipeline. It expands on the README with detailed data contracts, orchestration logic, deterministic scoring, and feedback retrieval.

## 1. System Goals

- Deterministic, reproducible triage with auditability.
- High-fidelity evidence collection under strict guardrails.
- LLM reasoning constrained by deterministic facts and policy enforcement.
- Feedback loop integration for analyst-driven continuous improvement.

## 2. Inputs and Normalization

### 2.1 Alert Ingestion

Source: Elastic `.alerts-security.alerts-*`.

The ingest layer maps ECS fields into a strict Pydantic schema to eliminate ambiguity and reduce prompt size:
- `alert`: ID, name, severity, timestamp, category, description.
- `detection`: rule ID/type, query logic, MITRE techniques, references.
- `execution`: process + PowerShell metadata.
- `entity`: host and user context.
- `analysis_signals`: deterministic behavioral flags.
- `raw_context`: selected ECS fields for evidence tracing.

### 2.2 Normalized Alert Contract

Primary contract is `NormalizedSecurityAlert` (`schemas/alert.py`).

Key fields surfaced to the LLM:
- `alert.name`, `alert.description`, `alert.severity`, `alert.timestamp`
- `execution.process.command_line`
- `entity.host.hostname`, `entity.user.name`/`entity.user.id`
- `analysis_signals.*` (boolean flags)
- `raw_context.*` (select ECS fields)

Raw data is stored for audit but not injected into prompts.

## 3. Deterministic Signal Engine

### 3.1 Purpose

Convert raw telemetry into deterministic, reproducible signals that the LLM can treat as ground truth.

### 3.2 Signal Taxonomy

Signals are derived via regex/heuristics across fields such as `process.command_line`, `message`, `event.code`, `winlog.channel`, `host.name`, and `host.ip`.

Signal groups:
- Execution & process anomalies
- Network/C2 patterns
- File staging and data handling
- Identity and authentication anomalies
- Cloud/API abuse
- Insider behavior
- Defense evasion
- Meta signals (kill chain progression, repeat offender)

Signals are immutable outputs of the deterministic engine: the LLM cannot override them.

## 4. Governance and Policy

### 4.1 Policy Engine

Policy enforcement (`control/policy_engine.py`) acts as a runtime guardrail:
- Enforces tool permissions
- Rejects forbidden actions
- Enforces depth and iteration limits
- Validates tool call eligibility

### 4.2 Token Guard

A hard iteration cap ensures bounded runtime. When the loop limit is hit, the system forces a decision phase.

## 5. RAG and MITRE Enrichment

### 5.1 MITRE RAG

`context/rag.py` and `rag/vectordb.py` run vector search over MITRE ATT&CK data (ChromaDB).

Outputs:
- Top techniques (IDs, names, descriptions)
- Enrichment for planner and reasoning agent

### 5.2 Technique Mapping

`context/mitre_map.py` resolves technique IDs from tags into human-readable tactics and procedures.

## 6. Multi-Agent Orchestration

### 6.1 Intake Agent

Gatekeeper with deterministic rules:
- Critical alerts always investigated.
- High-confidence benign calls can auto-close.
- Otherwise, investigation loop begins.

### 6.2 Investigation Agent

Generates intent based on evidence, signals, and feedback context.

### 6.3 Deterministic Planner

Translates intent to tool calls.

Planning strategy:
1. MITRE-based mapping
2. Intent keyword mapping
3. Signal-driven enforcement

Guardrails:
- Quoted values for fields
- Time window discipline
- Duplicate suppression
- Preference for `event.code` over free-text filters

### 6.4 Reasoning Agent

Synthesizes evidence into a coherent narrative, feeding the decision agent with an analytical summary.

## 7. SIEM Query Guardrails

### 7.1 Evidence-Anchored Queries

All queries must be tied to observed evidence. Free-form or overly broad queries are suppressed.

### 7.2 Time Window Discipline

Default window is `alert_timestamp +/- 3 minutes` with stepwise expansion when required.

### 7.3 Query Laddering

1. IOC-first
2. Host + narrow window
3. Process/command evidence
4. Message evidence
5. Broader host window as a last resort

### 7.4 Duplicate Suppression

Identical tool calls are blocked per loop to prevent wasted iterations.

## 8. Evidence and Summarization

### 8.1 Evidence Store

`InvestigationState` contains:
- `evidence`: collected facts
- `ioc_store`: normalized IOCs
- `lessons_learned`: feedback retrieval results
- `risk_score` and `evidence_table`

### 8.2 Summarizer

Tool outputs are compressed to retain factual content with minimal token usage.

## 9. Deterministic Risk Scoring

### 9.1 Scoring Equation

```
RiskScore = SUM(weight * confidence)
FinalScore = normalize(RiskScore, 0..100)
```

### 9.2 Classification Thresholds

- Benign: 0–20
- Suspicious: 21–60
- Malicious: 61–100

### 9.3 Output Contract

Decision agent output includes:
- Summary paragraph (4–6 sentences)
- Evidence table (category, evidence, weight, confidence, contribution)
- Final score (0–100)
- Final classification
- Recommended action

## 10. Feedback Loop

### 10.1 Jira Automation Webhook

FastAPI receiver (`feedback_api/app.py`) ingests Jira payloads:
- `issue.key`, `issue.summary`, `issue.status`
- `customfield_10101` (close note)
- `customfield_10100` (detection classification)
- `customfield_10099` (triage verdict)

### 10.2 Storage

Feedback is stored in SQLite by default (`feedback_api/feedback.db`) with an optional Postgres backend.

### 10.3 Retrieval

`context/feedback_rag.py` performs structured matching:
- alert name/description
- host
- user name/id

Results are injected into `lessons_learned` and surfaced to intake, investigation, and reasoning agents.

## 11. Output, Notification, and Audit

- Email report sent via Resend SDK.
- Audit trail written to `audit_trail_[alert_id].json`.
- Deterministic outputs ensure reproducibility and compliance.

## 12. Module Index

Key files:
- `intake/ingest.py`, `intake/logic.py`, `schemas/alert.py`
- `control/policy_engine.py`, `control/planner.py`
- `context/rag.py`, `rag/vectordb.py`, `context/feedback_rag.py`
- `agents/intake_agent.py`, `agents/investigation_agent.py`, `agents/reasoning_agent.py`, `agents/decision_agent.py`
- `tools/executor.py`, `tools/summarizer.py`
- `mcp_server/tools/siem.py`, `mcp_server/tools/virustotal.py`, `mcp_server/tools/cloudtrail.py`
- `feedback_api/app.py`, `feedback_api/db.py`

## 13. Future Extensions

- Cuckoo Sandbox MCP tool for detonation and behavioral IOCs.
- AbuseIPDB MCP tool for external IP reputation enrichment.
- Entra ID MCP tool when tenant is configured.
