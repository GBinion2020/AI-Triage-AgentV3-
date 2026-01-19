from typing import Tuple
from schemas.alert import NormalizedSecurityAlert

class PreClassifier:
    """
    Step 2: Deterministic Pre-Classification.
    Filters out benign alerts or duplicates before Agent engagement.
    """
    
    def __init__(self):
        # TODO: Load feedback DB and Rules
        pass
        
    def classify(self, alert: NormalizedSecurityAlert) -> Tuple[str, str]:
        """
        Returns (Decision, Reason).
        Decisions: 'close_benign', 'close_duplicate', 'investigate'
        """
        
        # 1. Check Rules (e.g. "Always ignore scanner X")
        # Placeholder
        if "Scanner" in alert.alert.name and alert.alert.severity == "low":
             return "close_benign", "Ignored by static rule: Low severity Scanner"

        # 2. Check Feedback History (Hashes)
        # User Instruction: Skip for now as DB is empty
        # if self.db.is_known_fp(alert):
        #    return "close_benign", "Known False Positive (Feedback DB)"
            
        return "investigate", "New alert requiring triage"
