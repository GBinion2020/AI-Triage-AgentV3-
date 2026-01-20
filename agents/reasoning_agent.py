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
        
        FULL NORMALIZED ALERT DATA:
        {alert_json}
        
        TECHNICAL SIGNALS (DETERMINISTIC):
        {json.dumps(state.alert.analysis_signals.model_dump(exclude_none=True), indent=2)}
        
        EVIDENCE LOGBOOK:
        {evidence_summary}
        
        THINKING PROCESS:
        - Analyze the sequence of events. Is there a logical progression (Kill Chain)?
        - Evaluate the source of the evidence. How reliable is it?
        - Identify contradictions. Does VT say a file is benign while SIEM shows it's beaconing?
        - Formulate a 'Ground Truth' conclusion.
        
        TASK:
        Provide your expert reasoning. Do not just summarize; explain the 'WHY'.
        Is this a confirmed True Positive, a Benign Positive (authorized admin activity), or a False Positive?
        """
        
        try:
            return self.llm.generate(prompt)
        except Exception as e:
            print(f"Reasoning LLM Error: {e}")
            return "Analytical reasoning failed due to LLM error. Proceeding with caution based on evidentiary facts."
