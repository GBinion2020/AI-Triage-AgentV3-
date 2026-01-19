from typing import List, Dict, Any
from schemas.state import InvestigationState

class DeterministicPlanner:
    """
    Step 8: Deterministic Tool Planner.
    Translates High-Level Intent or MITRE Techniques into concrete Tool Calls.
    """
    
    def plan_by_technique(self, techniques: List[str], state: InvestigationState) -> List[Dict[str, Any]]:
        """
        Initial Plan based on MITRE techniques found in the alert.
        """
        plan = []
        host_name = state.alert.entity.host.hostname if state.alert.entity.host else None
        user = state.alert.entity.user.name if state.alert.entity.user else None
        timestamp = state.alert.alert.timestamp.isoformat()
        
        for tech in techniques:
            # Brute Force / Password Spray
            if tech.startswith("T1110"):
                 if user:
                     plan.append({
                         "tool": "search_entra_logs",
                         "args": {"user_email": user} # Assuming name is email for now
                     })
                 if host_name:
                     plan.append({
                         "tool": "query_siem_host_logs",
                         "args": {"host_name": host_name, "alert_timestamp": timestamp}
                     })
                     
            # PowerShell / Command Line
            if tech.startswith("T1059"):
                if host_name:
                    plan.append({
                         "tool": "query_siem_host_logs",
                         "args": {"host_name": host_name, "alert_timestamp": timestamp}
                     })
        
        # New Rule: If Network Signal is strong, add host logs check even if no MITRE
        if state.alert.analysis_signals.external_communication and host_name:
             plan.append({
                 "tool": "query_siem_host_logs",
                 "args": {"host_name": host_name, "alert_timestamp": timestamp}
             })

        return plan

    def plan_from_intent(self, intent: str, state: InvestigationState) -> List[Dict[str, Any]]:
        """
        Translate LLM Intent ("Check if user logged in") to Tool ("search_entra_logs").
        """
        intent = intent.lower()
        plan = []
        user = state.alert.entity.user.name if state.alert.entity.user else "target_user"
        host = state.alert.entity.host.hostname if state.alert.entity.host else "target_host"
        ts = state.alert.alert.timestamp.isoformat()
        
        if "login" in intent or "signin" in intent or "auth" in intent:
            plan.append({"tool": "search_entra_logs", "args": {"user_email": user}})
            
        if any(w in intent for w in ["process", "execution", "network", "traffic", "exfiltration", "connection", "siem"]):
             plan.append({"tool": "query_siem_host_logs", "args": {"host_name": host, "alert_timestamp": ts}})
             
        if any(w in intent for w in ["reputation", "malicious", "virustotal", "check ip", "check hash"]):
            # Check for IOCs in alert
            # This is simplified - in prod we would parse IOCs from intent or state
            plan.append({"tool": "check_virustotal", "args": {"indicator": "1.1.1.1", "type": "ip"}})
            
        return plan
