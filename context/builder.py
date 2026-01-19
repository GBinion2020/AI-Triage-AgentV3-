from schemas.alert import NormalizedSecurityAlert
from schemas.state import InvestigationState

def build_initial_state(alert: NormalizedSecurityAlert) -> InvestigationState:
    """
    Step 3: Builds the initial InvestigationState from the alert.
    Ensures state is fresh and minimal.
    """
    state = InvestigationState(alert=alert)
    return state
