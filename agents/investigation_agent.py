import json
from llm.client import LLMClient
from schemas.state import InvestigationState

class InvestigationAgent:
    """
    Tier-1 Agent: Hypothesis-Driven Evidence Gathering.
    """
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client
        
    def generate_intent(self, state: InvestigationState) -> str:
        """
        Analyze current state and determine next investigative step.
        """
        # Prepare Context (redact alert name/description to avoid anchoring)
        alert_payload = state.alert.model_dump(exclude_none=True, exclude={"raw_data"})
        if isinstance(alert_payload.get("alert"), dict):
            alert_payload["alert"]["name"] = "redacted"
            alert_payload["alert"]["description"] = "redacted"
        if isinstance(alert_payload.get("raw_context"), dict):
            alert_payload["raw_context"]["rule_name"] = "redacted"
            alert_payload["raw_context"]["rule_description"] = "redacted"
        alert_json = json.dumps(alert_payload, default=str) # Minified (no indent)
        evidence_summary = "\n".join([f"- {e.source_tool}: {e.summary}" for e in state.evidence])
        tool_history = "\n".join(
            [
                f"- {t.tool_name} {t.arguments}"
                for t in state.tool_history[-5:]
            ]
        )
        
        prompt = f"""
        ACT: SOC Tier-1 Investigator.
        ROLE: You are a forensic evidence gatherer. Your goal is NOT to decide the case, but to collect concrete technical facts.
        Your scope is broader than the specific detection: look for any additional malicious or suspicious activity around the alert timeframe.
        
        FULL NORMALIZED ALERT DATA:
        {alert_json}
        
        CURRENT EVIDENCE CLOUD:
        {evidence_summary if evidence_summary else "No evidence gathered yet."}

        RECENT TOOL EXECUTIONS (avoid duplicates unless window changes):
        {tool_history if tool_history else "No tools executed yet."}
        
        LESSONS LEARNED FROM SIMILAR PAST INCIDENTS:
        {state.lessons_learned if state.lessons_learned else "No relevant past incidents found."}

        INVESTIGATION OBJECTIVES:
        - Validate the alert AND look for any additional malicious or suspicious activity in the same timeframe.
        - Prioritize concrete facts: process lineage, authentication anomalies, network indicators, and verified IOCs.
        - Avoid fixation on the detection label; pivot if evidence is thin.
        - Treat the alert label as a weak hint; do not anchor to it.

        INVESTIGATION STRATEGY (7 DIMENSIONS):
        A. Threat Intel: Check IPs/Hashes/Domains for reputation hits.
        B. Behavioral Baseline: Compare current activity to host/user norms.
        C. MITRE ATT&CK: Map activity to TTPs and look for multi-step chains.
        D. Process Context: Analyze parent-child lineage and binary signing.
        E. Identity Context: Look for privilege escalation or auth anomalies.
        F. Network Context: Inspect outbound volume and lateral movement patterns.
        G. Detection Logic: Evaluate the rule's confidence (signature vs anomaly).

        DIMENSION COVERAGE:
        - Each loop should target a different dimension when possible.
        - If one dimension yields no new evidence, pivot to another (e.g., Process -> Identity -> Network).
        - Broad playbook order: Process -> Identity -> Network -> Threat Intel -> Behavior.
        - After covering those once, continue with the most promising dimension.

        AVAILABLE CAPABILITIES:
        - query_siem_host_logs: Search for process, network, and file events on a specific host.
        - query_recent_host_alerts: List recent alerts for the same host (last 24h).
        - check_virustotal: Get reputation info for IPs, Hashes, or Domains.
        - search_cloudtrail: Audit AWS/Cloud API activity.
        
        QUERY QUALITY RULES:
        - Anchor filters to evidence: only suggest process names or keywords that appear in the alert context or prior evidence.
        - Use query laddering: start narrow; only widen time windows or add filters after a no-result query.
        - Field-aware filters: prefer event.code, event.dataset, or event.provider from the alert context.
        - Evidence-driven process filters only; do not guess process names.
        - IOC-first: if you see an IP/domain/hash, prioritize VirusTotal before more SIEM queries.

        TIME WINDOW RULES:
        - Never request a single point-in-time. Always use a window relative to the alert timestamp.
        - Prefer narrow windows (15-30 minutes) unless strong evidence requires expansion.
        - CRITICAL: DO NOT REQUEST THE SAME SIEM QUERY TWICE. If it was already run, choose a different dimension/tool or a different SIEM query type (e.g., filtered by process name).

        INVESTIGATION EFFICIENCY:
        - Each loop is valuable. Avoid repeating the same request.
        - When applicable, prefer using the majority of available tools to corroborate evidence.
        - If a SIEM query already ran, pivot to a different SIEM filter (e.g., process.name, event.action, or message keyword) or another tool.
        - When you want a SIEM filter value, include the exact value in backticks so it can be extracted (e.g., `autoit3.exe`, `Start-Process`).
        - If you mention any filter value (process name, event action, message term), include it in double quotes, e.g., "powershell.exe" or "Provider Lifecycle".

        IOC RULES:
        - Only include verified, relevant IOCs tied to this alert.
        - Supported types: ip, domain, hash.
        - Format: [IOC: type value]
        Example: "[IOC: ip 1.2.3.4] discovered in powershell logs."
        
        TASK:
        Based on the technical signals and evidence so far, which evaluation dimension is most critical to address next? State your intent to gather evidence for it.
        
        OUTPUT:
        Text specificing the intent. Be technical and precise.
        Example: "I need to query SIEM host logs for process parentage and network outbound connections from powershell.exe."
        """
        
        print(f"DEBUG: Investigation Prompt Size: {len(prompt)} chars")
        try:
            return self.llm.generate(prompt)
        except Exception as e:
            print(f"Investigation LLM Error: {e}")
            return "Investigate further based on initial alert signals."
