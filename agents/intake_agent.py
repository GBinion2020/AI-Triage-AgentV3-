import json
import re
from llm.client import LLMClient
from schemas.alert import NormalizedSecurityAlert

class IntakeAgent:
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client
        
    def evaluate(self, alert: NormalizedSecurityAlert) -> str:
        """
        Routing decision: 'investigate' or 'close_benign'.
        """
        
        # 1. Deterministic Overrides (Pre-LLM)
        if alert.alert.severity == "critical":
            return "investigate"
            
        signals = alert.analysis_signals
        
        # 2. Prepare Active Signals & Full Alert Context
        # Only show the signals that are TRUE/Present to concise context
        active_signals = []
        for field, value in signals.model_dump(exclude_none=True).items():
            if value is True:
                active_signals.append(f"- {field}: DETECTED")
            elif isinstance(value, str) and value:
                active_signals.append(f"- {field}: {value}")
            elif field == "confidence_boost" and value > 0:
                active_signals.append(f"- confidence_boost: {value}")
        
        signals_text = "\n".join(active_signals) if active_signals else "None detected."

        # Full Alert Context (Excluding Nulls and Huge Raw Data) - Minified
        alert_json = json.dumps(alert.model_dump(exclude_none=True, exclude={"raw_data"}), default=str)

        # 3. LLM Evaluation
        prompt = f"""
        ACT: SOC Intake Analyst.
        ROLE: You are the gatekeeper. Your job is to filter out OBVIOUS false positives.
        
        FULL NORMALIZED ALERT DATA:
        {alert_json}
        
        active_analysis_signals (SUMMARY):
        {signals_text}
        
        CRITICAL RULES:
        1. You are ONLY allowed to close alerts as 'close_benign' if you are >95% confident they are harmless.
        2. Inspect the 'active_analysis_signals'. If ANY technical signal is present (e.g., encoded_command, external_communication), you MUST default to 'investigate' unless you can prove it is business-as-usual.
        3. If 'confidence_boost' is high (>0.3), assume it is malicious.
        
        TASK:
        Decide whether to investigate or close.
        
        OUTPUT: JSON only. {{ "decision": "investigate" | "close_benign", "reason": "..." }}
        """
        print(f"DEBUG: Intake Prompt Size: {len(prompt)} chars")
        
        try:
            resp = self.llm.generate(prompt)
            match = re.search(r'(\{.*\})', resp, re.DOTALL)
            if match:
                data = json.loads(match.group(1))
                return data.get("decision", "investigate")
            else:
                return "investigate"
                
        except Exception as e:
            print(f"Intake LLM Error: {e}")
            return "investigate"
