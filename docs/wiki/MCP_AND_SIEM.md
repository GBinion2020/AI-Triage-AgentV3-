# MCP Tools and SIEM Guardrails

This page summarizes the MCP tool layer, SIEM query design, and guardrails used to keep evidence collection tight and reproducible.

## MCP Tooling (Current)

- **SIEM**: Elastic queries with structured filters and bounded time windows.
- **VirusTotal**: IOC reputation checks for hashes, domains, IPs.
- **CloudTrail**: Cloud audit log lookups (when configured).

## SIEM Query Guardrails

### Evidence-Anchored Queries
- Queries are derived from alert evidence (process args, event codes, message tokens).
- Values are quoted (e.g., `process_args: "powershell.exe"`).

### Time Window Discipline
- Default window is `alert_timestamp +/- 3 minutes`.
- Planner may expand windows in stepwise increments.
- No point-in-time queries.

### Query Laddering
1. IOC-first (if any IP/domain/hash exists).
2. Host + narrow time window.
3. Process/command evidence.
4. Message evidence.
5. Broader host window as last resort.

### Duplicate Suppression
- Identical tool calls are blocked per investigation loop.
- Prevents repeated high-cost queries.

### Noise Control
- Avoids broad, unbounded filters.
- Prefers precise `event.code` over free-text message filters.

## SIEM Field Examples

- `host.name`
- `process.args`
- `process.command_line`
- `event.code`
- `message`
- `source.ip`
- `destination.ip`

## Future MCP Tools (Planned)

### Cuckoo Sandbox
- Detonate suspicious binaries in a controlled environment.
- Extract behavior artifacts and PCAP indicators.

### AbuseIPDB
- IP reputation and abuse history scoring.
- Enrichment for outbound IPs and C2 candidates.

### Entra ID
- Identity and privilege audit in Azure AD.
- Login anomalies and role changes.
