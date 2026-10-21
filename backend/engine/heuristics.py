# engine/heuristics.py
import yara
from typing import Dict, List, Any, Tuple

class HeuristicEngine:
    """Deterministic Software Engineering rule engine for malware detection."""

    def __init__(self, yara_rules_path: str):
        
        # Compile YARA rules once during initialization
        self.yara_rules = yara.compile(filepath=yara_rules_path)

    def analyze(self, manifest_data: Dict[str, Any], dex_bytes: List[Tuple[str, bytes]]) -> Dict[str, Any]:
        triggered_rules = []
        heuristic_score = 0.0

        permissions = set(manifest_data.get("permissions", []))
        intent_filters = manifest_data.get("intent_filters", {})

        sms_perms = {"android.permission.SEND_SMS", "android.permission.RECEIVE_SMS"}
        if sms_perms.intersection(permissions) and "android.permission.RECEIVE_BOOT_COMPLETED" in permissions:
            heuristic_score += 0.35
            triggered_rules.append({
                "rule_id": "HEUR_SMS_BOOT",
                "severity": "HIGH",
                "message": "App requests SMS access paired with Boot Persistence."
            })

        if "android.permission.SYSTEM_ALERT_WINDOW" in permissions and "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions:
            heuristic_score += 0.40
            triggered_rules.append({
                "rule_id": "HEUR_OVERLAY_ACCESSIBILITY",
                "severity": "CRITICAL",
                "message": "System Alert Window paired with Accessibility Service (Overlay Attack Risk)."
            })

        if "android.permission.REQUEST_INSTALL_PACKAGES" in permissions and "android.permission.INTERNET" in permissions:
            heuristic_score += 0.25
            triggered_rules.append({
                "rule_id": "HEUR_DROPPER",
                "severity": "MEDIUM",
                "message": "App requests explicit package installation permissions and internet access."
            })

        for dex_name, content in dex_bytes:
            matches = self.yara_rules.match(data=content)
            for match in matches:
                severity = match.meta.get("severity", "MEDIUM")
                weight = 0.35 if severity in ["HIGH", "CRITICAL"] else 0.20
                
                heuristic_score += weight
                triggered_rules.append({
                    "rule_id": f"YARA_{match.rule}",
                    "severity": severity,
                    "message": f"YARA signature '{match.rule}' matched in {dex_name}: {match.meta.get('description')}"
                })

        final_heuristic_score = round(min(1.0, heuristic_score), 4)

        return {
            "heuristic_score": final_heuristic_score,
            "triggered_rules": triggered_rules,
            "is_flagged_by_heuristics": final_heuristic_score >= 0.50
        }