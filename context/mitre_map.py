from typing import List

def get_mitre_techniques(rule_name: str, rule_id: str) -> List[str]:
    """
    Step 4: Deterministic MITRE Mapping.
    Maps rule names/IDs to MITRE Technique IDs (e.g. T1059).
    """
    # Simple keyword mapping for demo purposes
    # In prod, this would use a lookup table or existing mappings in the alert
    
    rule_lower = rule_name.lower()
    techniques = []
    
    if "phish" in rule_lower:
        techniques.append("T1566") # Phishing
    
    if "powershell" in rule_lower:
        techniques.append("T1059.001") # PowerShell
        
    if "password" in rule_lower and "spray" in rule_lower:
        techniques.append("T1110.003") # Password Spraying
        
    if "logon" in rule_lower and "failed" in rule_lower:
        techniques.append("T1110") # Brute Force
        
    return techniques
