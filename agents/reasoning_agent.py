import json
from llm.client import LLMClient
from schemas.state import InvestigationState, Hypothesis

class ReasoningAgent:
    """
    Tier-2 Agent: Deep Analysis.
    Resolves ambiguity without new tools.
    """
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client
        
    def analyze(self, state: InvestigationState) -> str:
        """
        Think through the evidence.
        """
        # Prepare Context
        alert_json = json.dumps(state.alert.model_dump(exclude_none=True, exclude={"raw_data"}), default=str)
        evidence_summary = "\n".join([f"- {e.source_tool}: {e.summary}" for e in state.evidence])
        
        prompt = f"""
        ACT: SOC Tier-2 Senior Analyst.
        ROLE: You are a senior expert in threat hunting and incident response. Your goal is to provide deep contextual analysis and 'connect the dots' between disparate evidence pieces.
        Consider whether there is any additional malicious or suspicious activity beyond the triggering detection.
        
        FULL NORMALIZED ALERT DATA:
        {alert_json}
        
        TECHNICAL SIGNALS (DETERMINISTIC):
        {json.dumps(state.alert.analysis_signals.model_dump(exclude_none=True), indent=2)}
        
        EVIDENCE LOGBOOK:
        {evidence_summary}
        
        LESSONS LEARNED FROM SIMILAR PAST INCIDENTS:
        {state.lessons_learned if state.lessons_learned else "No relevant past incidents found."}
        
        --- ENTERPRISE SOC TRIAGE RUBRIC ---
        
        REQUIRED EVALUATION DIMENSIONS:
        - Threat Intel: Documentation of hits and reputation sources.
        - Behavioral Baseline: Comparison to host/user norms and geo-velocity.
        - MITRE ATT&CK: Identification of linked TTP chains.
        - Process/Execution: Parent-child analysis and signature status.
        - Identity/Privilege: Account escalation or auth anomalies.
        - Network: Lateral movement and outbound volume.
        - Detection Logic: Signal-to-noise evaluation.

        DETERMINISTIC DECISION RULES:
        - BENIGN: No TI hits, matches baseline, no MITRE chain.
        - SUSPICIOUS: Moderate baseline deviation, single TTP, rare process.
        - MALICIOUS: Strong TI hits, multi-step TTP chain, Lateral Movement, or exfil.

        IOC RULES:
        - Only include verified, relevant IOCs tied to this alert.
        - Supported types: ip, domain, hash.
        - Format: [IOC: type value]
        Example: "The attacker used a stager hash [IOC: hash a1b2c3d4...] to establish persistence."
        
        TASK:
        Provide your expert reasoning following the 7 dimensions. Do not just summarize; explain the 'WHY'.
        Based on the thresholds, is this a confirmed True Positive (Malicious), a Benign Positive, or Suspicious?
        """
        
        try:
            return self.llm.generate(prompt)
        except Exception as e:
            print(f"Reasoning LLM Error: {e}")
            return "Analytical reasoning failed due to LLM error. Proceeding with caution based on evidentiary facts."
