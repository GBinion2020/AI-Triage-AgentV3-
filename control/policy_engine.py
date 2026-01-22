from typing import List, Dict, Any
from schemas.policy import PolicyConfiguration, PolicyDecision
from schemas.state import InvestigationState

class PolicyEngine:
    """
    Step 6: Policy Engine.
    Governs what the agent can do.
    """
    def __init__(self):
        self.config = PolicyConfiguration()
        # Disable Entra until configured
        if "search_entra_logs" not in self.config.forbidden_tools:
            self.config.forbidden_tools.append("search_entra_logs")
        
    def get_initial_policy(self, state: InvestigationState) -> PolicyDecision:
        """
        Determine investigation scope/tools based on alert.
        """
        severity = state.alert.severity.lower()
        
        # Default Logic
        decision = PolicyDecision()
        
        if severity == "critical":
            decision.max_depth_override = 20
        
        return decision
        
    def check_tool_permission(self, state: InvestigationState, tool_name: str, args: Dict[str, Any]) -> PolicyDecision:
        """
        Runtime check before tool execution.
        """
        # Guardrail: keep SIEM time windows narrow to avoid noisy returns.
        if tool_name == "query_siem_host_logs":
            back = args.get("window_back_minutes")
            forward = args.get("window_forward_minutes")
            window = args.get("window_minutes")
            if back is not None or forward is not None:
                back_val = 15 if back is None else int(back)
                fwd_val = 15 if forward is None else int(forward)
                if back_val > 120 or fwd_val > 120 or (back_val + fwd_val) > 180:
                    return PolicyDecision(
                        allowed=False,
                        reason="SIEM time window too broad; reduce back/forward minutes.",
                    )
            elif window is not None and int(window) > 120:
                return PolicyDecision(
                    allowed=False,
                    reason="SIEM time window too broad; reduce window_minutes.",
                )

        # 1. Check Forbidden
        if tool_name in self.config.forbidden_tools:
            return PolicyDecision(allowed=False, reason=f"Tool {tool_name} is forbidden by policy.")
            
        # 2. Check Duplicates (Explicit Policy Rule)
        if state.is_duplicate(tool_name, args):
            return PolicyDecision(
                allowed=False, 
                reason=f"Duplicate Query: Tool {tool_name} with args {args} has already been run successfully."
            )
            
        return PolicyDecision(allowed=True)
