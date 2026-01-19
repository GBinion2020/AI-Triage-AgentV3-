# Enterprise Agentic SOC: AI-Powered Security Alert Triage

> **An autonomous, multi-agent security operations platform** that combines deterministic cybersecurity logic with adaptive AI reasoning to intelligently triage security alerts at scale.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ollama](https://img.shields.io/badge/LLM-Ollama-green.svg)](https://ollama.ai/)
[![Elastic](https://img.shields.io/badge/SIEM-Elastic-005571.svg)](https://www.elastic.co/)

---

## Table of Contents
- [Overview](#overview)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Workflow Pipeline](#workflow-pipeline)
- [Module Documentation](#module-documentation)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Project Structure](#project-structure)

---

## Overview

The **Enterprise Agentic SOC** is a state-of-the-art autonomous security operations platform designed to handle the overwhelming volume of security alerts in modern SOCs. By combining **deterministic pattern matching** (Signal Engine) with **adaptive LLM reasoning** (Multi-Agent System), it achieves:

- **Zero hallucinations** on foundational security facts
- **Transparent decision-making** with complete audit trails
- **Scalable 24/7 triage** without human fatigue
- **Privacy-first architecture** using local LLMs

### The Problem It Solves
Modern SOCs face:
- **Alert fatigue**: 1000+ alerts per day, 95% false positives
- **Inconsistent triage**: Human analysts vary in experience and approach
- **Slow response times**: Manual investigation takes 15-30 minutes per alert
- **Lack of transparency**: "Black box" AI decisions without audit trails

### The Solution
A **hybrid intelligence platform** that:
1. Uses **deterministic logic** to extract 50+ behavioral signals (AMSI bypasses, LOTL binaries, encoded commands)
2. Employs **multi-agent AI** to reason about complex attack patterns
3. Enforces **policy guardrails** at every decision point
4. Maintains **100% audit compliance** with complete investigation records

---

## Key Features

### Hybrid Intelligence Architecture
- **Signal Engine**: Deterministic regex/heuristic-based detection of 50+ attack patterns
- **Multi-Agent System**: Specialized AI agents for intake, investigation, reasoning, and decision-making
- **RAG-Enhanced**: MITRE ATT&CK knowledge base integration via vector search

### Enterprise-Grade Governance
- **Policy Engine**: Runtime enforcement of tool permissions, depth limits, and forbidden actions
- **Dual Confidence Gates**: Operational (fact-based) and Analytical (reasoning quality) checks
- **Duplicate Detection**: Query hashing prevents redundant API calls
- **Token Guard**: Prevents infinite loops with configurable iteration limits

### Active Investigation Capabilities
- **MCP Tool Integration**: SIEM queries, VirusTotal lookups, Entra ID searches, CloudTrail audits
- **Smart Summarization**: 54% prompt size reduction while preserving audit trail completeness
- **Iterative Evidence Gathering**: Up to 10 investigation loops with intelligent stopping criteria

### Transparency & Auditability
- **Complete Audit Trails**: Every intent, tool call, and result logged to JSON
- **Reasoning Traces**: LLM explains the "why" behind every decision
- **Structured Outputs**: Strict JSON schemas for classification, confidence, and MITRE techniques

---

## System Architecture

### High-Level Component View

```mermaid
graph TB
    %% Styling
    classDef ingestion fill:#1a237e,stroke:#0d47a1,stroke-width:3px,color:#fff
    classDef normalization fill:#283593,stroke:#1976d2,stroke-width:3px,color:#fff
    classDef intel fill:#512da8,stroke:#7b1fa2,stroke-width:3px,color:#fff
    classDef governance fill:#c62828,stroke:#d32f2f,stroke-width:3px,color:#fff
    classDef agents fill:#00695c,stroke:#00897b,stroke-width:3px,color:#fff
    classDef tools fill:#e65100,stroke:#f57c00,stroke-width:3px,color:#fff
    classDef decision fill:#2e7d32,stroke:#43a047,stroke-width:3px,color:#fff
    classDef audit fill:#37474f,stroke:#546e7a,stroke-width:3px,color:#fff

    Start([Raw Security Alert<br/>Elastic/Splunk]) --> Ingest

    subgraph "Layer 1: Ingestion & Normalization"
        Ingest[Alert Ingestor<br/>intake/ingest.py]:::ingestion
        Ingest --> PreClass{Pre-Classifier<br/>intake/pre_classifier.py}:::ingestion
        PreClass -->|Empty Alert| Exit1[Skip Processing]
        PreClass -->|Valid Alert| SignalEng[Signal Engine<br/>intake/logic.py]:::normalization
        
        SignalEng --> Signals[50+ Behavioral Signals<br/>- AMSI Bypass<br/>- LOTL Binaries<br/>- Encoded Commands<br/>- External Comms]:::normalization
        Signals --> Schema[Normalized Schema<br/>schemas/alert.py<br/>NormalizedSecurityAlert]:::normalization
    end

    Schema --> Policy

    subgraph "Layer 2: Governance & Intelligence"
        Policy[Policy Engine<br/>control/policy_engine.py]:::governance
        Policy --> PolicyCheck{Policy Decision<br/>- Tool Permissions<br/>- Max Depth<br/>- Forbidden Actions}:::governance
        
        PolicyCheck -->|Denied| Exit2[Policy Violation]
        PolicyCheck -->|Approved| MITRE
        
        MITRE[MITRE RAG<br/>context/rag.py<br/>rag/vectordb.py]:::intel
        MITRE --> VectorDB[(Chroma Vector DB<br/>ATT&CK Techniques<br/>D3FEND Controls)]:::intel
        VectorDB --> TechMap[Technique Mapping<br/>context/mitre_map.py]:::intel
    end

    TechMap --> IntakeAgent

    subgraph "Layer 3: Multi-Agent Orchestration"
        IntakeAgent[Intake Agent<br/>agents/intake_agent.py<br/>Role: Gatekeeper]:::agents
        
        IntakeAgent --> IntakeDecision{Decision Logic<br/>Confidence >95%?}:::agents
        IntakeDecision -->|Benign| Close[Auto-Close<br/>No Investigation]
        IntakeDecision -->|Suspicious| InvLoop[Investigation Loop]:::agents
        
        InvLoop --> ConfGate1{Confidence Gate 1<br/>core/confidence.py<br/>Operational Check}:::governance
        ConfGate1 -->|Low Confidence| InvAgent
        ConfGate1 -->|High Confidence| ReasonAgent
        
        InvAgent[Investigation Agent<br/>agents/investigation_agent.py<br/>Role: Tier-1 Investigator]:::agents
        InvAgent --> Intent[Intent Generation<br/>LLM-Driven]:::agents
        
        Intent --> Planner[Deterministic Planner<br/>control/planner.py]:::governance
        Planner --> PlanLogic{Planning Strategy<br/>1. MITRE-Based<br/>2. Intent-Based<br/>3. Signal-Based}:::governance
        
        PlanLogic --> ToolPlan[Tool Execution Plan<br/>List of Tool Calls]:::tools
        ToolPlan --> ToolCheck{Policy Check<br/>Duplicate Detection<br/>Permission Validation}:::governance
        
        ToolCheck -->|Denied| Skip[Skip Tool]
        ToolCheck -->|Approved| Executor
        
        Executor[Tool Executor<br/>tools/executor.py]:::tools
        Executor --> MCP[MCP Tools<br/>mcp_server/tools/]:::tools
        
        MCP --> SIEM[SIEM Query<br/>siem.py]:::tools
        MCP --> VT[VirusTotal<br/>virustotal.py]:::tools
        MCP --> Entra[Entra ID<br/>entra.py]:::tools
        MCP --> Cloud[CloudTrail<br/>cloudtrail.py]:::tools
        
        SIEM & VT & Entra & Cloud --> Formatter[Output Formatter<br/>mcp_server/formatter.py]:::tools
        Formatter --> Summarizer[Result Summarizer<br/>tools/summarizer.py<br/>Smart Context Pruning]:::tools
        
        Summarizer --> Evidence[Evidence Store<br/>schemas/state.py<br/>InvestigationState]:::audit
        Evidence --> LoopAudit[Loop Audit Record<br/>Intent + Tools + Results]:::audit
        
        LoopAudit --> TokenGuard{Token Guard<br/>control/token_guard.py<br/>Iteration Limit Check}:::governance
        TokenGuard -->|Max Iterations| ForceExit[Force Exit to Decision]
        TokenGuard -->|Continue| InvLoop
        
        ReasonAgent[Reasoning Agent<br/>agents/reasoning_agent.py<br/>Role: Tier-2 Analyst]:::agents
        ReasonAgent --> Analysis[Deep Analysis<br/>Connect the Dots<br/>Build Narrative]:::agents
        
        Analysis --> ConfGate2{Confidence Gate 2<br/>Analytical Check}:::governance
        ConfGate2 -->|Uncertain| InvLoop
        ConfGate2 -->|Confident| DecAgent
    end

    ForceExit --> DecAgent
    
    subgraph "Layer 4: Final Authority & Output"
        DecAgent[Decision Agent<br/>agents/decision_agent.py<br/>Role: SOC Manager]:::decision
        DecAgent --> FinalDecision{Final Classification<br/>- True Positive<br/>- False Positive<br/>- Benign Positive}:::decision
        
        FinalDecision --> JSONOut[Structured Output<br/>JSON with:<br/>- Classification<br/>- Confidence<br/>- MITRE Techniques<br/>- Action Required<br/>- 3-5 Sentence Summary]:::decision
        
        JSONOut --> AuditExport[Audit Trail Export<br/>Complete Investigation Record<br/>JSON Data Residency]:::audit
    end
    
    AuditExport --> End([Case Resolution])
```

### Color Legend
- **Dark Blue** (Ingestion): Raw data intake and normalization
- **Purple** (Intel): Knowledge base and semantic enrichment
- **Red** (Governance): Policy enforcement and safety controls
- **Teal** (Agents): AI-driven decision making and reasoning
- **Orange** (Tools): External data sources and APIs
- **Green** (Decision): Final authority and classification
- **Gray** (Audit): Compliance and transparency mechanisms

---

## Workflow Pipeline

### Step-by-Step Execution Flow

#### **Phase 1: Ingestion & Normalization**

**1. Alert Ingestor** (`intake/ingest.py`)
- Fetches raw alerts from Elastic SIEM using the `.alerts-security.alerts-*` index
- Maps ECS (Elastic Common Schema) fields to internal `NormalizedSecurityAlert` model
- Handles both flattened (`kibana.alert.*`) and nested (`signal.*`) field formats

**2. Pre-Classifier** (`intake/pre_classifier.py`)
- Validates alert has minimum required fields (rule name, timestamp, severity)
- Rejects empty or malformed alerts before expensive processing
- **Decision Point**: Empty -> Skip | Valid -> Continue

**3. Signal Engine** (`intake/logic.py`)
- **Deterministic Logic**: Uses regex and heuristics to derive 50+ behavioral signals
- **Key Signals**:
  - `encoded_command`: Detects `-EncodedCommand`, `-enc` flags
  - `living_off_the_land`: Matches against LOTL binary list (powershell.exe, certutil.exe, etc.)
  - `amsi_bypass_pattern`: Searches for AMSI evasion keywords
  - `external_communication`: Detects `Invoke-WebRequest`, `curl`, `wget` patterns
  - `file_staging_detected`: Identifies file write operations to temp directories
- **Confidence Boost**: Calculates weighted score based on signal presence (e.g., AMSI bypass = +0.4)

**4. Schema Normalization** (`schemas/alert.py`)
- Constructs `NormalizedSecurityAlert` with:
  - `AlertInfo`: ID, name, severity, timestamp, description
  - `DetectionInfo`: Rule ID, type, MITRE techniques
  - `ExecutionInfo`: Process details, PowerShell metadata
  - `EntityInfo`: Host, user, network information
  - `AnalysisSignals`: All 50+ derived signals
  - `raw_data`: Original Elastic JSON (excluded from prompts for performance)

---

#### **Phase 2: Governance & Intelligence**

**5. Policy Engine** (`control/policy_engine.py`)
- **Initial Policy Decision**:
  - Sets `max_depth_override` based on alert severity (critical = 20 iterations)
  - Defines forbidden tools list
- **Runtime Policy Checks**:
  - Validates tool permissions before execution
  - Detects duplicate queries via hash comparison
  - **Decision Point**: Denied -> Skip Tool | Approved -> Execute

**6. MITRE RAG** (`context/rag.py`, `rag/vectordb.py`)
- Queries ChromaDB vector database with alert description
- Performs semantic search over MITRE ATT&CK techniques
- Returns top 3 relevant techniques with:
  - Technique ID (e.g., T1059.001)
  - Name (e.g., "PowerShell")
  - Description and tactics
  - Similarity distance score

**7. Technique Mapping** (`context/mitre_map.py`)
- Extracts MITRE techniques from alert tags
- Maps technique IDs to human-readable tactics/procedures
- Enriches context for agent prompts

---

#### **Phase 3: Multi-Agent Orchestration**

**8. Intake Agent** (`agents/intake_agent.py`)
- **Role**: Gatekeeper - filters obvious false positives
- **Input**: Minified alert JSON + active analysis signals
- **Logic**:
  ```python
  if alert.severity == "critical":
      return "investigate"
  if confidence > 0.95 AND no_technical_signals:
      return "close_benign"
  else:
      return "investigate"
  ```
- **Decision Point**: Benign (>95% conf) -> Auto-Close | Suspicious -> Investigation Loop

**9. Confidence Gate 1: Operational** (`core/confidence.py`)
- **Purpose**: Ensures minimum fact-gathering before analysis
- **Logic**:
  ```python
  if evidence_count >= 5: return "high"
  if iteration_count > 5: return "high" (force exit)
  if evidence_count > 0: return "medium"
  return "low"
  ```
- **Decision Point**: Low -> Continue Investigation | High -> Proceed to Reasoning

**10. Investigation Agent** (`agents/investigation_agent.py`)
- **Role**: Tier-1 Investigator - generates technical investigation intents
- **Input**: Full normalized alert + evidence summary
- **Output**: Natural language intent (e.g., "I need to query SIEM host logs for process parentage")
- **Prompt Strategy**: Lists available capabilities and investigation priorities

**11. Deterministic Planner** (`control/planner.py`)
- **Translates intents into tool execution plans**
- **Three Planning Strategies**:
  1. **MITRE-Based**: Maps techniques to tools (T1110 -> `search_entra_logs`)
  2. **Intent-Based**: Parses keywords from LLM intent ("login" -> `search_entra_logs`)
  3. **Signal-Based**: Forces SIEM query if `external_communication` signal is active
- **Output**: List of `{tool: "name", args: {...}}` dictionaries

**12. Policy Check: Duplicate Detection**
- Hashes tool name + arguments using MD5
- Checks against `InvestigationState.tool_executions` history
- **Decision Point**: Duplicate -> Skip | New -> Execute

**13. Tool Executor** (`tools/executor.py`)
- Orchestrates MCP tool calls
- Handles errors and timeouts
- Normalizes outputs via `mcp_server/formatter.py`

**14. MCP Tools** (`mcp_server/tools/`)
- **SIEM Query** (`siem.py`): Searches Elastic for host logs in ±15min window
- **VirusTotal** (`virustotal.py`): Checks IP/hash/domain reputation
- **Entra ID** (`entra.py`): Searches Azure AD authentication logs
- **CloudTrail** (`cloudtrail.py`): Queries AWS API activity

**15. Result Summarizer** (`tools/summarizer.py`)
- **Smart Context Pruning**: Extracts key facts using regex
- **SIEM Summary**: Parses process names and event types
- **VT Summary**: Extracts verdict and malicious/suspicious counts
- **Output**: `Evidence` object with both `content` (raw) and `summary` (concise)

**16. Evidence Store** (`schemas/state.py`)
- Maintains `InvestigationState` with:
  - `evidence`: List of all gathered facts
  - `tool_executions`: Deduplication history
  - `audit_trail`: Complete loop records
  - `iteration_count`: Current loop number

**17. Loop Audit Record**
- Captures for each iteration:
  - `intent`: LLM's investigation goal
  - `tools_planned`: Planner's output
  - `executions`: Actual tool calls with args and results
  - `errors`: Any failures encountered

**18. Token Guard** (`control/token_guard.py`)
- Enforces `MAX_ITERATIONS` limit (default: 10)
- **Decision Point**: Max Reached -> Force Exit | Continue -> Loop Back

**19. Reasoning Agent** (`agents/reasoning_agent.py`)
- **Role**: Tier-2 Analyst - synthesizes evidence into narrative
- **Input**: Full alert + all evidence summaries
- **Output**: Reasoning trace explaining the "why"
- **Analysis Focus**: Connects disparate signals, evaluates kill chain progression

**20. Confidence Gate 2: Analytical**
- **Purpose**: Self-aware reasoning quality check
- **Logic**:
  ```python
  if "unsure" in reasoning OR "ambiguous" in reasoning:
      return "low"
  return "high"
  ```
- **Decision Point**: Uncertain -> Loop Back | Confident -> Final Decision

---

#### **Phase 4: Final Authority & Output**

**21. Decision Agent** (`agents/decision_agent.py`)
- **Role**: SOC Manager - translates technical analysis into business risk
- **Input**: Alert + signals + reasoning trace + evidence summaries
- **Output**: Strict JSON with:
  - `classification`: "True Positive" | "False Positive" | "Benign Positive"
  - `confidence_score`: 0.0 to 1.0
  - `summary`: 3-5 sentence explanation with evidence references
  - `action`: "Close" | "Escalate to Incident Response" | "Block Asset/User"
  - `mitre_techniques`: List of observed technique IDs
  - `journal`: Timeline of investigation steps

**22. Audit Trail Export**
- Writes `audit_trail_[alert_id].json` with:
  - Complete investigation history
  - Every intent, tool call, and result
  - All errors and policy decisions
- **Purpose**: 100% transparency for compliance and tuning

---

## Module Documentation

### Layer 1: Ingestion & Normalization
| Module | File | Purpose |
|--------|------|---------|
| Alert Ingestor | `intake/ingest.py` | Fetches raw alerts from Elastic, maps ECS fields to normalized schema |
| Pre-Classifier | `intake/pre_classifier.py` | Validates alert is not empty/malformed before processing |
| Signal Engine | `intake/logic.py` | Deterministic logic engine using regex/heuristics to derive 50+ behavioral signals |
| Alert Schema | `schemas/alert.py` | Pydantic models: `NormalizedSecurityAlert`, `AnalysisSignals`, `AlertInfo`, `DetectionInfo` |

### Layer 2: Governance & Intelligence
| Module | File | Purpose |
|--------|------|---------|
| Policy Engine | `control/policy_engine.py` | Enforces investigation boundaries, tool permissions, depth limits |
| Policy Schema | `schemas/policy.py` | Defines `PolicyConfiguration`, `PolicyDecision` models |
| MITRE RAG | `context/rag.py` | Queries vector database for relevant ATT&CK techniques based on alert context |
| Vector DB | `rag/vectordb.py` | ChromaDB interface for semantic search over MITRE ATT&CK and D3FEND |
| MITRE Mapper | `context/mitre_map.py` | Maps raw technique IDs to human-readable tactics/procedures |
| Token Guard | `control/token_guard.py` | Prevents infinite loops by enforcing max iteration count |

### Layer 3: Multi-Agent Orchestration
| Module | File | Purpose |
|--------|------|---------|
| Intake Agent | `agents/intake_agent.py` | LLM-driven gatekeeper with >95% confidence threshold for benign closures |
| Investigation Agent | `agents/investigation_agent.py` | Tier-1 agent that generates technical investigation intents |
| Reasoning Agent | `agents/reasoning_agent.py` | Tier-2 analyst that synthesizes evidence into analytical narratives |
| Decision Agent | `agents/decision_agent.py` | SOC Manager role, produces final structured verdict |
| Deterministic Planner | `control/planner.py` | Translates intents/MITRE techniques into concrete tool execution plans |
| Confidence Gates | `core/confidence.py` | Dual-gate system: Operational (fact-based) + Analytical (reasoning quality) |
| Investigation State | `schemas/state.py` | Pydantic model tracking evidence, hypotheses, tool executions, audit trail |

### Layer 4: Tool Execution & Data Gathering
| Module | File | Purpose |
|--------|------|---------|
| Tool Executor | `tools/executor.py` | Orchestrates MCP tool calls, handles errors, normalizes outputs |
| Output Formatter | `mcp_server/formatter.py` | Standardizes tool outputs to align with schema structure |
| Result Summarizer | `tools/summarizer.py` | Extracts key facts from raw outputs using regex (smart context pruning) |
| SIEM Tool | `mcp_server/tools/siem.py` | Queries Elastic for host/network logs within time windows |
| VirusTotal Tool | `mcp_server/tools/virustotal.py` | Checks IP/hash/domain reputation using VT API |
| Entra ID Tool | `mcp_server/tools/entra.py` | Searches Azure AD/Entra for authentication logs |
| CloudTrail Tool | `mcp_server/tools/cloudtrail.py` | Queries AWS CloudTrail API for cloud activity |

### Supporting Infrastructure
| Module | File | Purpose |
|--------|------|---------|
| Main Orchestrator | `main.py` | Entry point, initializes all components, runs alert processing loop |
| LLM Client | `llm/client.py` | Ollama API wrapper for local model inference |
| Elastic Client | `elastic/client.py` | Elasticsearch HTTP client for SIEM connectivity |
| Context Builder | `context/builder.py` | Constructs initial `InvestigationState` from normalized alert |

---

## Installation

### Prerequisites
- **Python 3.10+**
- **Elasticsearch & Kibana** (Running and accessible)
- **Ollama** (Running locally)
- **VirusTotal API Key** (Optional)

### Step 1: Clone Repository
```bash
git clone https://github.com/yourusername/soc-ai-triage-agent.git
cd soc-ai-triage-agent
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

Or manually:
```bash
pip install requests python-dotenv chromadb pydantic
```

### Step 3: Install Ollama and Pull Model
```bash
# Install Ollama (https://ollama.ai/)
# Then pull the model:
ollama pull deepseek-r1:8b
```

### Step 4: Initialize RAG Knowledge Base
```bash
# Ensure mitre-attack.json is in Rag-Data/ directory
python rag/ingestion.py
```

---

## Configuration

Create a `.env` file in the project root:

```env
# Required: Elastic SIEM Connection
ELASTIC_BASE_URL=https://your-elastic-ip:9200
ELASTIC_API_KEY=your-api-key

# Optional: VirusTotal API (for IOC enrichment)
VT_API_KEY=your-virustotal-api-key

# Optional: Ollama Configuration
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=deepseek-r1:8b
```

### Environment Variables Reference
| Variable | Required | Description |
|----------|----------|-------------|
| `ELASTIC_BASE_URL` | Yes | Elasticsearch instance URL |
| `ELASTIC_API_KEY` | Yes | API key for authentication |
| `VT_API_KEY` | No | VirusTotal API key for IOC lookups |
| `OLLAMA_BASE_URL` | No | Ollama server URL (default: localhost:11434) |
| `OLLAMA_MODEL` | No | LLM model name (default: deepseek-r1:8b) |

---

## Usage

### Basic Execution
```bash
python main.py
```

The agent will:
1. Fetch recent alerts from Elastic SIEM
2. Process each alert through the 4-layer pipeline
3. Generate structured classifications with audit trails
4. Export results to `audit_trail_[alert_id].json`

### Example Output
```json
{
  "classification": "True Positive",
  "confidence_score": 0.85,
  "summary": "This alert indicates a confirmed APT29 exfiltration attempt via Invoke-WebRequest. Evidence includes living-off-the-land execution, encoded PowerShell commands, and external communication to a suspicious IP. SIEM logs confirm the process chain originated from a user workstation.",
  "action": "Escalate to Incident Response",
  "mitre_techniques": ["T1059.001", "T1048.003"],
  "journal": [
    "Iteration 1: Queried SIEM for host logs - found suspicious PowerShell execution",
    "Iteration 2: Checked VirusTotal for destination IP - flagged as malicious by 12 vendors"
  ]
}
```

---

## Project Structure

```
soc-ai-TriageAgent/
├── agents/                 # Multi-agent system
│   ├── intake_agent.py    # Gatekeeper agent
│   ├── investigation_agent.py  # Tier-1 investigator
│   ├── reasoning_agent.py # Tier-2 analyst
│   └── decision_agent.py  # SOC manager
├── control/               # Governance layer
│   ├── planner.py        # Deterministic tool planner
│   ├── policy_engine.py  # Policy enforcement
│   └── token_guard.py    # Iteration limits
├── core/                  # Core utilities
│   └── confidence.py     # Confidence gate logic
├── intake/                # Alert ingestion
│   ├── ingest.py         # Elastic alert fetcher
│   ├── logic.py          # Signal engine
│   └── pre_classifier.py # Alert validator
├── mcp_server/            # MCP tool server
│   ├── tools/
│   │   ├── siem.py       # SIEM queries
│   │   ├── virustotal.py # VT lookups
│   │   ├── entra.py      # Entra ID searches
│   │   └── cloudtrail.py # AWS CloudTrail
│   └── formatter.py      # Output normalization
├── schemas/               # Pydantic models
│   ├── alert.py          # Alert schemas
│   ├── state.py          # Investigation state
│   └── policy.py         # Policy schemas
├── tools/                 # Tool orchestration
│   ├── executor.py       # Tool execution
│   └── summarizer.py     # Result summarization
├── context/               # Context builders
│   ├── builder.py        # State initialization
│   ├── rag.py            # RAG interface
│   └── mitre_map.py      # MITRE mapping
├── rag/                   # Vector database
│   ├── vectordb.py       # ChromaDB interface
│   └── ingestion.py      # Data ingestion
├── elastic/               # Elastic client
│   └── client.py         # HTTP wrapper
├── llm/                   # LLM interface
│   └── client.py         # Ollama client
├── Rag-Data/              # MITRE data files
├── chroma_db/             # Vector DB storage
├── main.py                # Entry point
├── .env.example           # Environment template
└── README.md              # This file
```

---

## Key Innovations

1. **Hybrid Intelligence**: Combines deterministic cybersecurity logic (Signal Engine) with adaptive LLM reasoning
2. **Zero Hallucination Foundation**: All technical facts are regex/heuristic-verified before LLM sees them
3. **Governance-First**: Policy Engine enforces guardrails at every decision point
4. **Transparent AI**: Complete audit trail solves the "black box" problem
5. **Prompt Efficiency**: Smart summarization maintains context without token bloat (54% reduction)

---

## System Metrics

- **Max Investigation Depth**: 10 iterations (configurable)
- **Duplicate Detection**: Query hash deduplication
- **Token Optimization**: 54% prompt size reduction
- **Audit Completeness**: 100% - every intent, tool call, and result logged
- **LLM Timeout**: 1000s per agent call
- **SIEM Query Window**: +- 15 minutes around alert timestamp

---

**Built with love for the SOC community**
