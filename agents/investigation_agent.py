import json
from llm.client import LLMClient
from schemas.state import InvestigationState

class InvestigationAgent:
    """
    Tier-1 Agent: Hypothesis-Driven Evidence Gathering.
    """
    def __init__(self):
        self.llm = LLMClient()
        
    def generate_intent(self, state: InvestigationState) -> str:
        """
        Analyze current state and determine next investigative step.
        """
        # Prepare Context
        alert_json = json.dumps(state.alert.model_dump(exclude_none=True, exclude={"raw_data"}), default=str) # Minified (no indent)
        evidence_summary = "\n".join([f"- {e.source_tool}: {e.summary}" for e in state.evidence])
        
        prompt = f"""
        ACT: SOC Tier-1 Investigator.
        ROLE: You are a forensic evidence gatherer. Your goal is NOT to decide the case, but to collect concrete technical facts.
        
        FULL NORMALIZED ALERT DATA:
        {alert_json}
        
        CURRENT EVIDENCE CLOUD:
        {evidence_summary if evidence_summary else "No evidence gathered yet."}
        
        INVESTIGATION STRATEGY:
        1. If 'encoded_command' or 'powershell' is present, priority is to decode and check process history.
        2. If 'external_communication' is present, check network reputation and local socket logs.
        3. If 'file_staging' is present, check for unexpected archive creations or temp file writes.
        
        AVAILABLE CAPABILITIES:
        - query_siem_host_logs: Search for process, network, and file events on a specific host.
        - search_entra_logs: Search for authentication and identity anomalies.
        - check_virustotal: Get reputation info for IPs, Hashes, or Domains.
        - search_cloudtrail: Audit AWS/Cloud API activity.
        
        TASK:
        Based on the technical signals and evidence so far, what is the single most important technical detail missing? State your intent to find it.
        
        OUTPUT:
        Text specificing the intent. Be technical and precise.
        Example: "I need to query SIEM host logs for process parentage and network outbound connections from powershell.exe."
        """
        
        print(f"DEBUG: Investigation Prompt Size: {len(prompt)} chars")
        return self.llm.generate(prompt)
