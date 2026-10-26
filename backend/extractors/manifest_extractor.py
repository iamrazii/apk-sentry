# extractors/manifest_extractor.py
from androguard.core.apk import APK
from typing import Dict, Any

class ManifestExtractor:
    """Extracts structural metadata, component exposures, and intent triggers from AndroidManifest.xml."""
    
    @staticmethod
    def extract(apk_path: str) -> Dict[str, Any]:
        apk_obj = APK(apk_path)
        
        raw_permissions = apk_obj.get_permissions()
        permissions = [p.strip() for p in raw_permissions if p]

        # Extract structural components
        receivers = apk_obj.get_receivers()
        services = apk_obj.get_services()
        activities = apk_obj.get_activities()

        # Parse structural intent actions accurately without string casting
        intent_actions = set()
        for component_type in ["receiver", "service", "activity"]:
            getter = getattr(apk_obj, f"get_{component_type}s")
            for comp in getter():
                filters = apk_obj.get_intent_filters(component_type, comp)
                if filters and "action" in filters:
                    intent_actions.update(filters["action"])

        # Check for persistence and interception triggers
        intent_triggers = {
            "boot_completed": "android.intent.action.BOOT_COMPLETED" in intent_actions,
            "sms_received": "android.provider.Telephony.SMS_RECEIVED" in intent_actions,
            "package_added": "android.intent.action.PACKAGE_ADDED" in intent_actions,
        }

        return {
            "package_name": apk_obj.get_package(),
            "target_sdk": apk_obj.get_target_sdk_version(),
            "permissions": permissions,
            "receivers_count": len(receivers),
            "services_count": len(services),
            "activities_count": len(activities),
            "intent_triggers": intent_triggers
        }