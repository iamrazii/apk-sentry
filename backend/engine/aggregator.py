# engine/aggregator.py
from typing import Dict, Any

class HybridAggregator:
    """Aggregates SWE Heuristic findings with ML Model probabilities."""

    def __init__(self, heuristic_weight: float = 0.4, ml_weight: float = 0.6, final_threshold: float = 0.50):
        self.heuristic_weight = heuristic_weight
        self.ml_weight = ml_weight
        self.final_threshold = final_threshold

    def aggregate(self, heuristic_res: Dict[str, Any], ml_res: Dict[str, Any]) -> Dict[str, Any]:
        h_score = heuristic_res.get("heuristic_score", 0.0)
        ml_prob = ml_res.get("malware_probability", 0.0)
        triggered_rules = heuristic_res.get("triggered_rules", [])

        combined_score = (h_score * self.heuristic_weight) + (ml_prob * self.ml_weight)
        combined_score = round(combined_score, 4)

        has_critical_trigger = any(rule.get("severity") in ["CRITICAL", "HIGH"] for rule in triggered_rules)

        is_malware = (combined_score >= self.final_threshold) or has_critical_trigger

        verdict_label = "SAFE"
        if is_malware:
            if has_critical_trigger and ml_res["is_malware_ml"]:
                verdict_label = "MALWARE (Confirmed by Rules & ML)"
            elif has_critical_trigger:
                verdict_label = "MALWARE (Flagged by Rule Engine Override)"
            else:
                verdict_label = "MALWARE (Flagged by ML Model Probabilities)"

        return {
            "verdict": verdict_label,
            "is_malware": is_malware,
            "threat_scores": {
                "combined_score": combined_score,
                "ml_probability": ml_prob,
                "heuristic_score": h_score
            },
            "audit_trail": {
                "critical_override_triggered": has_critical_trigger,
                "total_heuristic_rules_fired": len(triggered_rules),
                "ml_confidence": ml_res["confidence"]
            },
            "detailed_rule_triggers": triggered_rules
        }