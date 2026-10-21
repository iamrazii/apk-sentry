# extractors/manifest_extractor.py
from androguard.core.apk import APK
from typing import Dict, List, Any

class ManifestExtractor:
    """Extracts structural metadata and declared permissions from AndroidManifest.xml."""

    @staticmethod
    def extract(apk_path: str) -> Dict[str, Any]:
        apk_obj = APK(apk_path)
        
        raw_permissions = apk_obj.get_permissions()
        permissions = [p.strip() for p in raw_permissions if p]

        # Extract declared components
        receivers = apk_obj.get_receivers()
        services = apk_obj.get_services()
        activities = apk_obj.get_activities()

        # Check for critical intent filters 
        intent_filters = {
            "boot_completed": "android.intent.action.BOOT_COMPLETED" in str(apk_obj.get_intent_filters("receiver", "*")),
            "sms_received": "android.provider.Telephony.SMS_RECEIVED" in str(apk_obj.get_intent_filters("receiver", "*"))
        }

        return {
            "package_name": apk_obj.get_package(),
            "permissions": permissions,
            "receivers": receivers,
            "services": services,
            "activities": activities,
            "intent_filters": intent_filters
        }