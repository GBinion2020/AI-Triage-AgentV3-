import json
from llm.client import LLMClient
from schemas.state import InvestigationState

class DecisionAgent:
    """
    Final Authority.
    Produces the final structured output.
    """
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client
        
    def decide(self, state: InvestigationState, reasoning_trace: str = "") -> dict:
        """
        Produce final verdict.
        """
        # Prepare Context
        alert_json = json.dumps(state.alert.model_dump(exclude_none=True, exclude={"raw_data"}), default=str)
        evidence_summary = "\n".join([f"- {e.source_tool}: {e.summary}" for e in state.evidence])
        
        prompt = f"""
        ACT: SOC Manager.
        ROLE: You are the final authority. You translate technical analysis into business risk and actionable outcomes.
        
        FULL NORMALIZED ALERT DATA (Minified):
        {alert_json}
        
        TECHNICAL SIGNALS (DETERMINISTIC):
        {json.dumps(state.alert.analysis_signals.model_dump(exclude_none=True), default=str)}
        
        FINAL ANALYTICAL REASONING:
        {reasoning_trace}
        
        EVIDENCE SUMMARIES:
        {evidence_summary}
        
        DECISION CRITERIA:
        - TRUE POSITIVE: Clear evidence of malicious intent or unauthorized access.
        - BENIGN POSITIVE: Legitimate admin/dev activity that triggered a rule (Tune/Whitlelist).
        - FALSE POSITIVE: Tool error or misparsed data.
        
        TASK:
        Provide a final decision in STRICT JSON format. 
        DO NOT include any conversational text, explanations, or headers outside the JSON block.
        DO NOT use markdown formatting outside the JSON block.
        
        OUTPUT FORMAT (STRICT JSON):
        {{
            "classification": "True Positive" | "False Positive" | "Benign Positive",
            "confidence_score": 0.0 to 1.0,
            "summary": "Provide EXACTLY 4-6 full, technical sentences outlining the reasoning, what evidence supported the decision, and any mitigating factors. Do not use bullet points here.",
            "action": "Close" | "Escalate to Incident Response" | "Block Asset/User",
            "mitre_techniques": ["TXXXX"],
            "journal": ["Timeline of investigation steps taken..."]
        }}
        """
        
        print(f"DEBUG: Decision Prompt Size: {len(prompt)} chars")
        try:
            resp = self.llm.generate(prompt)
            
            # Robust JSON extraction
            import re
            # Find the outermost { }
            match = re.search(r'(\{.*\})', resp, re.DOTALL)
            if match:
                json_str = match.group(1)
                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    # Final attempt: try to clean up common LLM artifacts like trailing commas or comments
                    # (Simplified for now)
                    json_str = re.sub(r',\s*\}', '}', json_str)
                    return json.loads(json_str)
            else:
                 # If no braces found, the model failed completely
                 raise ValueError("No JSON object found in response")
        except Exception as e:
             # Log the failure for debugging
             print(f"DECISION AGENT ERROR: {e}")
             print(f"RAW RESPONSE: {resp[:500]}...")
             return {
                 "classification": "Error", 
                 "summary": f"Failed to generate decision json. Error: {e}",
                 "action": "Escalate"
             }
