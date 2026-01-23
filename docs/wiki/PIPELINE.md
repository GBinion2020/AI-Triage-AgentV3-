# Pipeline Deep Dive

This document describes the end-to-end pipeline in operational detail: inputs, normalization, query planning, evidence extraction, scoring, decisioning, notification, and analyst feedback retrieval.

## End-to-End Flow (Detailed)

```mermaid
flowchart TB
  subgraph Ingestion["Layer 1: Ingestion & Normalization"]
    A[Elastic SIEM Alert] --> B[Ingest + ECS Mapping]
    B --> C[Pre-Classifier]
    C --> D[Signal Engine]
    D --> E[NormalizedSecurityAlert]
  end

  subgraph Governance["Layer 2: Governance & Intel"]
    E --> F[Policy Engine]
    F --> G[MITRE RAG + Technique Map]
  end

  subgraph Orchestration["Layer 3: Multi-Agent Orchestration"]
    G --> H[LLM Selection]
    H --> I[Intake Agent]
    I -->|Benign Gate| X[Auto-Close]
    I -->|Suspicious| J[Investigation Loop]
    J --> K[Operational Confidence Gate]
    K -->|Low| L[Investigation Agent]
    K -->|High| M[Reasoning Agent]
    L --> N[Intent + Deterministic Planner]
    N --> O[Tool Plan + Policy Check]
    O --> P[Tool Executor]
    P --> Q[Tool Outputs]
    Q --> R[Summarizer + Evidence Store]
    R --> S[Token Guard]
    S -->|Continue| J
    S -->|Stop| M
  end

  subgraph Decision["Layer 4: Decision & Reporting"]
    M --> T[Decision Agent]
    T --> U[Risk Scoring Matrix 0-100]
    U --> V[Final Classification]
    V --> W[Email Report + Audit Trail]
  end

  subgraph Feedback["Feedback Loop"]
    Z[Jira Automation Webhook] --> AA[Normalize Feedback]
    AA --> AB[Feedback Store]
    AB --> AC[Feedback Retrieval]
    AC --> I
  end

  E --> AC
```

## Data Contracts

### Normalized Alert (`schemas/alert.py`)
Core fields used by agents and planners:
- `alert`: ID, name, severity, timestamp, category, description.
- `detection`: rule ID/type, query logic, MITRE techniques, references.
- `execution`: process, PowerShell context.
- `entity`: host and user context.
- `analysis_signals`: deterministic signals (process, network, identity, defense evasion).
- `raw_context`: selected ECS fields (message, event_code, winlog channel, host OS, process args).

### Investigation State (`schemas/state.py`)
Key fields used during orchestration:
- `evidence`: structured evidence items.
- `ioc_store`: normalized IOCs (hash, domain, IP).
- `lessons_learned`: feedback retrieval results.
- `risk_score`: numeric 0-100.
- `evidence_table`: risk scoring table entries.

## Deterministic Planning & Querying

### Evidence-Anchored Queries
Queries are built from observed evidence in the alert context:
- Process candidates use `process_args_contains` with quoted values.
- Event IDs use `event_code` instead of free-text fields.
- Message filtering uses `message_contains` with quoted values.

### Query Laddering
Each loop selects the next most specific query:
1. IOC-first (if known IP/domain/hash exists).
2. Host + narrow time window (baseline).
3. Process/command evidence.
4. Message evidence.
5. Broader host window (last resort).

### Time Windows
Queries avoid point-in-time timestamps:
- Default time window is `alert_timestamp +/- 3 minutes`.
- Planner can expand windows stepwise, but avoids high-volume ranges.

### Duplicate Avoidance
The system tracks prior tool arguments per loop and suppresses identical queries.

## Scoring & Classification

### Risk Scoring Matrix (`core/scoring.py`)
Evidence items map to weights and confidence values:
- `score = sum(weight * confidence)`
- normalized to 0–100
- thresholds:
  - 0–20 Benign
  - 21–60 Suspicious
  - 61–100 Malicious

### Deterministic Output
Decision agent produces:
- Summary (4–6 sentences)
- Evidence table
- Final score and classification
- Recommended action

## Feedback Loop

### Jira Webhook Ingestion
`feedback_api/app.py` accepts Jira payloads and normalizes:
- issue key/summary/status
- close note
- detection classification
- triage verdict

### Storage (SQLite/Postgres)
`feedback_api/db.py` supports:
- SQLite default (`feedback_api/feedback.db`)
- Postgres via `FEEDBACK_DB_URL`

### Retrieval
`context/feedback_rag.py` uses structured search:
- matches on `issue_summary`, `description`, `close_note`
- optional host/user keywords
- returns most recent N items
- injected into `lessons_learned` for LLM grounding

## Operational Notes

- Token pruning is disabled when using external LLMs.
- Entra query tool is disabled if not configured.
- Baseline queries always run first:
  - last 24h host alerts
  - host logs +/- 3 minutes
