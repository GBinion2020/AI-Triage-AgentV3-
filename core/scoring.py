from typing import List, Dict, Any
import logging

logger = logging.getLogger("EnterpriseSOC.Scoring")

class RiskScoringMatrix:
    """
    Enterprise-grade Risk Scoring Engine.
    Implements a weighted matrix across 7 security categories.
    Calculation: RiskScore = SUM(weight * confidence)
    """
    
    # 1. Threat Intelligence (TI)
    TI_WEIGHTS = {
        "known_malicious_hash": 50,
        "known_c2": 45,
        "medium_risk_hit": 25,
        "low_risk_hit": 10
    }
    
    # 2. Baseline & Behavioral Deviation
    BEHAVIOR_WEIGHTS = {
        "severe_deviation": 40,
        "moderate_deviation": 25,
        "minor_deviation": 10,
        "matches_baseline": -20
    }
    
    # 3. MITRE ATT&CK Alignment
    MITRE_WEIGHTS = {
        "multi_step_chain": 40,
        "high_risk_ttp": 35,
        "medium_risk_ttp": 20,
        "low_risk_ttp": 10
    }
    
    # 4. Process & Execution Signals
    PROCESS_WEIGHTS = {
        "unsigned_binary": 35,
        "suspicious_parent_child": 30,
        "rare_process": 20,
        "known_good_signed": -30
    }
    
    # 5. Privilege & Identity Indicators
    IDENTITY_WEIGHTS = {
        "privilege_escalation": 50,
        "admin_anomaly": 30,
        "auth_pattern_anomaly": 25,
        "normal_auth": -15
    }
    
    # 6. Network Indicators
    NETWORK_WEIGHTS = {
        "exfiltration_pattern": 60,
        "lateral_movement": 50,
        "unusual_outbound": 25,
        "trusted_internal": -10
    }
    
    # 7. Detection Logic Confidence
    DETECTION_WEIGHTS = {
        "high_confidence_detection": 40,
        "medium_confidence_detection": 20,
        "low_confidence_detection": 10
    }

    @classmethod
    def calculate_score(cls, factors: List[Dict[str, Any]]) -> float:
        """
        Calculates normalized risk score from a list of factors.
        Each factor: { "category": str, "type": str, "confidence": float }
        Returns: Score normalized to 0-100.
        """
        total_score = 0
        
        category_map = {
            "threat_intel": cls.TI_WEIGHTS,
            "behavior": cls.BEHAVIOR_WEIGHTS,
            "mitre": cls.MITRE_WEIGHTS,
            "process": cls.PROCESS_WEIGHTS,
            "identity": cls.IDENTITY_WEIGHTS,
            "network": cls.NETWORK_WEIGHTS,
            "detection": cls.DETECTION_WEIGHTS
        }
        
        for factor in factors:
            category = factor.get("category")
            weight_type = factor.get("type")
            confidence = factor.get("confidence", 1.0)
            
            if category in category_map:
                weights = category_map[category]
                if weight_type in weights:
                    weight = weights[weight_type]
                    contribution = weight * confidence
                    total_score += contribution
                    logger.debug(f"Scoring: {category}/{weight_type} | Weight: {weight} * Conf: {confidence} = {contribution}")
                else:
                    logger.warning(f"Unknown weight type '{weight_type}' in category '{category}'")
            else:
                logger.warning(f"Unknown scoring category '{category}'")
        
        # Normalize to 0-100 range (Max theoretical score can be high, we clamp and scale)
        # Note: Negative scores (baselines) can bring it down.
        normalized_score = max(0, min(100, total_score))
        return normalized_score

    @classmethod
    def get_weight(cls, category: str, weight_type: str) -> Any:
        """
        Fetch a deterministic weight for a category/type pair.
        Returns None if not found.
        """
        category_map = {
            "threat_intel": cls.TI_WEIGHTS,
            "behavior": cls.BEHAVIOR_WEIGHTS,
            "mitre": cls.MITRE_WEIGHTS,
            "process": cls.PROCESS_WEIGHTS,
            "identity": cls.IDENTITY_WEIGHTS,
            "network": cls.NETWORK_WEIGHTS,
            "detection": cls.DETECTION_WEIGHTS,
        }
        weights = category_map.get(category, {})
        return weights.get(weight_type)

    @classmethod
    def get_classification(cls, score: float) -> str:
        """Determines final classification based on score thresholds."""
        if score <= 20:
            return "Benign"
        elif score <= 60:
            return "Suspicious"
        else:
            return "Malicious"
