# engine/heuristics.py
import yara
from typing import Dict, Any
from extractors.manifest_extractor import ManifestExtractor
from extractors.dex_extractor import ExtendedExtractor

class HeuristicEngine:
    """Probabilistic rule engine using multiplicative risk decay (saturation model)."""

    def __init__(self, yara_rules_path: str):
        self.yara_rules = yara.compile(filepath=yara_rules_path)

    def analyze(self, apk_path: str) -> Dict[str, Any]:
        manifest = ManifestExtractor.extract(apk_path)
        artifacts = ExtendedExtractor.extract_all(apk_path)

        risk_factors = []
        permissions = set(manifest.get("permissions", []))
        triggers = manifest.get("intent_triggers", {})

        # Rule 1: SMS Persistence Combo
        sms_perms = {"android.permission.SEND_SMS", "android.permission.RECEIVE_SMS"}
        if sms_perms.intersection(permissions) and triggers.get("boot_completed"):
            risk_factors.append({
                "rule": "HEUR_SMS_BOOT",
                "weight": 0.45,
                "message": "SMS permissions combined with BOOT_COMPLETED persistence trigger."
            })

        # Rule 2: Overlay + Accessibility (Tapjacking / Banking Trojan Vector)
        if "android.permission.SYSTEM_ALERT_WINDOW" in permissions and "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions:
            risk_factors.append({
                "rule": "HEUR_OVERLAY_ACCESSIBILITY",
                "weight": 0.60,
                "message": "System Alert Window and Accessibility Service requested (Overlay Risk)."
            })

        # Rule 3: Packed Asset Detection via Shannon Entropy
        if artifacts["high_entropy_assets"]:
            risk_factors.append({
                "rule": "HEUR_HIGH_ENTROPY_ASSETS",
                "weight": 0.35,
                "message": f"Detected {len(artifacts['high_entropy_assets'])} high-entropy (>7.2) asset payload(s)."
            })

        # Rule 4: YARA Binary Matches across DEX and .so files
        all_binaries = artifacts["dex_payloads"] + artifacts["native_libs"]
        for bin_name, bin_bytes in all_binaries:
            matches = self.yara_rules.match(data=bin_bytes)
            for match in matches:
                severity = match.meta.get("severity", "MEDIUM")
                w = 0.50 if severity in ["HIGH", "CRITICAL"] else 0.25
                risk_factors.append({
                    "rule": f"YARA_{match.rule}",
                    "weight": w,
                    "message": f"YARA match '{match.rule}' in {bin_name}: {match.meta.get('description', '')}"
                })

        # Compute bounded probabilistic threat score: 1 - Product(1 - w_i)
        non_risk_prob = 1.0
        for rf in risk_factors:
            non_risk_prob *= (1.0 - rf["weight"])

        final_score = round(1.0 - non_risk_prob, 4)

        return {
            "heuristic_score": final_score,
            "triggered_rules": risk_factors,
            "is_flagged_by_heuristics": final_score >= 0.50
        }