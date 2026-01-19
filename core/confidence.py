from schemas.state import InvestigationState

def check_operational_confidence(state: InvestigationState) -> str:
    """
    Gate 1: Do we have enough FACTS?
    Returns: 'low', 'medium', 'high'
    """
    # 1. If we have lots of evidence, High.
    if len(state.evidence) >= 5:
        return "high"
        
    # 2. If we looped too much without result, Force High to exit (fail open/close).
    if state.iteration_count > 5:
        return "high"
        
    # 3. If we have some evidence but not enough
    if len(state.evidence) > 0:
        return "medium"
        
    return "low"

def check_analytical_confidence(state: InvestigationState, reasoning: str) -> str:
    """
    Gate 2: Do we understand the narrative?
    Returns: 'low', 'high'
    """
    # Simplified logic: If reasoning is long and detailed, assume high confidence?
    # Or strict: if reasoning contains "Unknown" or "Unsure", Low.
    
    if "unsure" in reasoning.lower() or "ambiguous" in reasoning.lower():
        return "low"
        
    return "high"
