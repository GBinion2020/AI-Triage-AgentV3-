from schemas.alert import NormalizedSecurityAlert
from schemas.state import InvestigationState
from context.feedback_rag import FeedbackRAG

def build_initial_state(alert: NormalizedSecurityAlert) -> InvestigationState:
    """
    Step 3: Builds the initial InvestigationState from the alert.
    Augments the state with historical lessons learned from past incidents.
    """
    state = InvestigationState(alert=alert)
    
    # --- Analyst Feedback Loop Integration ---
    try:
        feedback_rag = FeedbackRAG()
        # Search for past incidents based on alert description
        query_text = f"{alert.alert.name} {alert.alert.description}"
        host = alert.entity.host.hostname if alert.entity.host else None
        user = None
        if alert.entity.user:
            user = alert.entity.user.name or alert.entity.user.id
        lessons = feedback_rag.get_related_lessons(query_text, n_results=2, host=host, user=user)
        state.lessons_learned = lessons
    except Exception as e:
        # User requirement: "ignore if error" so the pipeline doesn't break
        print(f"Non-critical error fetching feedback lessons: {e}")
        state.lessons_learned = "No past incident context available. Proceeding with fresh investigation."
    
    return state
