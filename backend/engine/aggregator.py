from typing import Dict, Any


class HybridAggregator:
    """Aggregates SWE Heuristic findings with ML Model probabilities into a 3-tier risk system."""

    def __init__(
        self,
        heuristic_weight: float = 0.6,
        ml_weight: float = 0.4,
        suspicious_threshold: float = 0.35,
        critical_threshold: float = 0.65,
    ):
        self.heuristic_weight = heuristic_weight
        self.ml_weight = ml_weight
        self.suspicious_threshold = suspicious_threshold
        self.critical_threshold = critical_threshold

    def aggregate(self, heuristic_res: Dict[str, Any], ml_res: Dict[str, Any]) -> Dict[str, Any]:
        h_score = heuristic_res.get("heuristic_score", 0.0)
        ml_prob = ml_res.get("malware_probability", 0.0)
        triggered_rules = heuristic_res.get("triggered_rules", [])

        combined_score = (h_score * self.heuristic_weight) + (ml_prob * self.ml_weight)
        combined_score = round(combined_score, 4)

        # Count critical static signals rather than overriding on a single soft heuristic
        critical_static_hits = sum(
            1 for rule in triggered_rules
            if rule.get("severity") == "CRITICAL" or rule.get("is_critical", False)
        )
        high_static_hits = sum(
            1 for rule in triggered_rules
            if rule.get("severity") in ["CRITICAL", "HIGH"]
        )

        has_critical_trigger = (
            high_static_hits >= 2 or (critical_static_hits >= 1 and ml_prob >= 0.35)
        )

        # Classification: 1 (Malware), -1 (Suspicious), 0 (Benign/Safe)
        if has_critical_trigger or combined_score >= self.critical_threshold:
            risk_tier = "HIGHLY CRITICAL"
            is_malware = 1
            verdict_label = (
                "HIGHLY CRITICAL (Flagged by Multi-Signal Security Override)"
                if has_critical_trigger
                else "HIGHLY CRITICAL (Confirmed Malware Pattern)"
            )
        elif combined_score >= self.suspicious_threshold:
            risk_tier = "SUSPICIOUS"
            is_malware = -1
            verdict_label = "SUSPICIOUS (Requires Dynamic Verification / Manual Review)"
        else:
            risk_tier = "SAFE"
            is_malware = 0
            verdict_label = "SAFE (Low Risk Application)"

        return {
            "verdict": verdict_label,
            "risk_tier": risk_tier,
            "is_malware": is_malware,
            "threat_scores": {
                "total_score": combined_score,
                "ml_score": ml_prob,
                "static_score": h_score,
            },
            "thresholds": {
                "suspicious_cutoff": self.suspicious_threshold,
                "critical_cutoff": self.critical_threshold,
            },
            "audit_trail": {
                "critical_override_triggered": has_critical_trigger,
                "total_heuristic_rules_fired": len(triggered_rules),
                "ml_confidence": ml_res.get("confidence", 0.0),
            },
            "detailed_rule_triggers": triggered_rules,
        }