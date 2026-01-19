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
