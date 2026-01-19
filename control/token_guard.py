from schemas.state import InvestigationState

class TokenBudgetController:
    """
    Step 7: Token Budget Controller.
    Prevents context explosion.
    """
    def __init__(self, max_tokens: int = 50000):
        self.max_tokens = max_tokens
        
    def check_budget(self, state: InvestigationState) -> bool:
        """
        Returns True if budget OK, False if pruning needed.
        """
        # Simplified token estimation (char / 4)
        current_est = len(state.model_dump_json()) / 4
        return current_est < self.max_tokens
        
    def prune(self, state: InvestigationState) -> InvestigationState:
        """
        Aggressive pruning.
        """
        # 1. Summarize tool results (truncate large strings)
        for ev in state.evidence:
            if len(ev.content) > 1000:
                ev.content = ev.content[:1000] + "... [TRUNCATED]"
                
        # 2. Limit history
        if len(state.tool_history) > 10:
             state.tool_history = state.tool_history[-10:]
             
        return state
