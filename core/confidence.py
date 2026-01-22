from schemas.state import InvestigationState

def check_operational_confidence(state: InvestigationState) -> float:
    """
    Gate 1: Do we have enough FACTS?
    Returns a numeric confidence score (0-100).
    """
    score = 0.0

    # Evidence volume is the primary driver.
    if len(state.evidence) >= 5:
        score = 95.0
    elif len(state.evidence) >= 3:
        score = 75.0
    elif len(state.evidence) >= 1:
        score = 55.0

    # If we looped too much without result, boost to allow exit conditions.
    if state.iteration_count > 5:
        score = max(score, 90.0)

    return score

def label_operational_confidence(score: float) -> str:
    """
    Converts numeric operational confidence to a label for logging.
    """
    if score >= 90:
        return "high"
    if score >= 60:
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
