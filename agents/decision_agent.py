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
        
    def decide(self, state: InvestigationState, reasoning_trace: str = "", scoring: dict = None) -> dict:
        """
        Produce final verdict.
        """
        scoring = scoring or {}
        risk_score = scoring.get("risk_score", 0.0)
        classification = scoring.get("classification", "Suspicious")
        evidence_table = scoring.get("evidence_table", [])

        # Prepare Context
        alert_json = json.dumps(state.alert.model_dump(exclude_none=True, exclude={"raw_data"}), default=str)
        evidence_summary = "\n".join([f"- {e.source_tool}: {e.summary}" for e in state.evidence])
        lessons = state.lessons_learned if state.lessons_learned else "No relevant past incidents found."
        feedback_override = self._detect_feedback_override(lessons)

        prompt = f"""
        ACT: SOC Manager.
        ROLE: You are the final authority. You translate technical analysis into business risk and actionable outcomes using the ENTERPRISE TRIAGE RUBRIC.
        
        FULL NORMALIZED ALERT DATA (Minified):
        {alert_json}
        
        TECHNICAL SIGNALS (DETERMINISTIC):
        {json.dumps(state.alert.analysis_signals.model_dump(exclude_none=True), default=str)}
        
        FINAL ANALYTICAL REASONING:
        {reasoning_trace}
        
        EVIDENCE SUMMARIES:
        {evidence_summary}

        FEEDBACK LOOP (AUTHORITATIVE CONTEXT):
        {lessons}

        FEEDBACK OVERRIDE FLAG:
        {feedback_override}

        --- DETERMINISTIC RISK OUTPUTS ---
        Final Risk Score (0-100): {risk_score}
        Final Classification: {classification}
        Evidence Table (authoritative):
        {json.dumps(evidence_table, indent=2, default=str)}

        TASK:
        Provide only the narrative summary and recommended action.
        The final score and classification are already determined. Do not change them.
        If FEEDBACK OVERRIDE FLAG is true, you MUST state in the summary that the activity is likely benign/known testing based on prior analyst feedback, while keeping the same score/classification.
        Write like a SOC L2/L3 analyst close note with relevant timestamps, IOCs, and findings.
        Avoid listing internal host IPs unless they are directly tied to malicious activity.
        Do not mention scoring, weights, or rubric mechanics.

        OUTPUT FORMAT (STRICT JSON):
        {{
            "summary": "4-6 sentences explaining the why, SOC L2/L3 close note style with timestamps and IOCs.",
            "action": "Close" | "Escalate to Incident Response" | "Block Asset/User",
            "mitre_techniques": ["TXXXX"],
            "journal": ["Step 1: ...", "Step 2: ..."]
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
                    parsed = json.loads(json_str)
                    return {
                        "classification": classification,
                        "final_score": risk_score,
                        "summary": parsed.get("summary", "Summary unavailable."),
                        "action": parsed.get("action", "Escalate to Incident Response"),
                        "evidence_table": evidence_table,
                        "mitre_techniques": parsed.get("mitre_techniques", []),
                        "journal": parsed.get("journal", []),
                    }
                except json.JSONDecodeError:
                    # Final attempt: try to clean up common LLM artifacts like trailing commas or comments
                    # (Simplified for now)
                    json_str = re.sub(r',\s*\}', '}', json_str)
                    parsed = json.loads(json_str)
                    return {
                        "classification": classification,
                        "final_score": risk_score,
                        "summary": parsed.get("summary", "Summary unavailable."),
                        "action": parsed.get("action", "Escalate to Incident Response"),
                        "evidence_table": evidence_table,
                        "mitre_techniques": parsed.get("mitre_techniques", []),
                        "journal": parsed.get("journal", []),
                    }
            else:
                 # If no braces found, the model failed completely
                 raise ValueError("No JSON object found in response")
        except Exception as e:
             # Log the failure for debugging
             print(f"DECISION AGENT ERROR: {e}")
             print(f"RAW RESPONSE: {resp[:500]}...")
             return {
                 "classification": classification,
                 "final_score": risk_score,
                 "summary": f"Failed to generate decision json. Error: {e}",
                 "action": "Escalate to Incident Response",
                 "evidence_table": evidence_table,
                 "mitre_techniques": [],
                 "journal": [],
             }

    def _detect_feedback_override(self, lessons: str) -> bool:
        if not lessons:
            return False
        lowered = lessons.lower()
        return "false positive" in lowered or "benign" in lowered or "not malicious" in lowered
