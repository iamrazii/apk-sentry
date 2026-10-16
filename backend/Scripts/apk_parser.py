import os
import pandas as pd
from androguard.core.apk import APK
# Alternative lightweight parser if AXML module varies by version
import xml.etree.ElementTree as ET

class AndroidPermissionExtractor:

    # Comprehensive mapping between raw Android Permission constants and dataset text tokens
    KEYWORD_MAPPING = {
        "INTERNET": ["internet", "full internet access"],
        "READ_SMS": ["read sms", "read sms or mms"],
        "RECEIVE_SMS": ["receive sms"],
        "SEND_SMS": ["send sms"],
        "READ_CONTACTS": ["read contact data", "contacts data"],
        "WRITE_CONTACTS": ["write contact data"],
        "RECORD_AUDIO": ["record audio"],
        "CAMERA": ["take pictures and videos", "camera"],
        "ACCESS_FINE_LOCATION": ["fine (gps) location", "fine location"],
        "ACCESS_COARSE_LOCATION": ["coarse (network-based) location", "coarse location"],
        "READ_PHONE_STATE": ["read phone state and identity"],
        "CALL_PHONE": ["directly call phone numbers", "call phone"],
        "RECEIVE_BOOT_COMPLETED": ["automatically start at boot"],
        "WAKE_LOCK": ["prevent device from sleeping"],
        "SYSTEM_ALERT_WINDOW": ["display system-level alerts"],
        "READ_EXTERNAL_STORAGE": ["modify/delete usb storage contents", "sd card contents"],
        "WRITE_EXTERNAL_STORAGE": ["modify/delete usb storage contents", "sd card contents"],
        "BLUETOOTH": ["bluetooth administration", "create bluetooth connections"],
        "ACCESS_NETWORK_STATE": ["view network state"],
        "ACCESS_WIFI_STATE": ["view wi-fi state"],
        "CHANGE_WIFI_STATE": ["change wi-fi state"],
        "READ_HISTORY_BOOKMARKS": ["read browser's history and bookmarks"],
        "WRITE_HISTORY_BOOKMARKS": ["write browser's history and bookmarks"],
        "INSTALL_PACKAGES": ["directly install applications"],
    }

    def __init__(self, dataset_permission_cols: list):
        self.dataset_permission_cols = dataset_permission_cols

    def extract_permissions_from_apk(self, file_path: str) -> list:
        """Parses requested permissions from .apk files."""
        if APK is None:
            raise ImportError("Neither androguard nor pyaxmlparser is installed.")

        ext = os.path.splitext(file_path)[1].lower()
        if ext != ".apk":
            raise ValueError(f"Unsupported file format: {ext}. Upload a valid .apk file.")

        apk_obj = APK(file_path)
        return apk_obj.get_permissions()

    def map_to_feature_vector(
        self,
        extracted_permissions: list,
        category: str = "Tools",
        rating: float = 4.0,
        number_of_ratings: float = 1000.0,
        price: float = 0.0
    ) -> pd.DataFrame:
        """Maps extracted Android permissions (e.g. ['android.permission.INTERNET', ...])

        to the 173 binary flag columns expected by the trained model pipeline.
        """
        feature_dict = {
            'Category': category,
            'Rating': rating,
            'Number of ratings': number_of_ratings,
            'Price': price
        }

        # Normalize extracted permissions (convert to upper short-names like 'INTERNET', 'READ_SMS')
        extracted_short_names = [p.split('.')[-1].upper() for p in extracted_permissions]
        extracted_full_lower = [p.lower() for p in extracted_permissions]

        for col in self.dataset_permission_cols:
            col_lower = col.lower()
            is_present = False

            # 1. Match via KEYWORD_MAPPING dictionary
            for perm_key, phrases in self.KEYWORD_MAPPING.items():
                if perm_key in extracted_short_names:
                    if any(phrase in col_lower for phrase in phrases):
                        is_present = True
                        break

            # 2. Fallback Direct Substring Matching for unmapped permissions
            if not is_present:
                for short_name in extracted_short_names:
                    # Clean up short name for matching (e.g., ACCESS_FINE_LOCATION -> FINE LOCATION)
                    clean_name = short_name.replace("ACCESS_", "").replace("_", " ").lower()
                    if len(clean_name) > 3 and clean_name in col_lower:
                        is_present = True
                        break

            feature_dict[col] = 1 if is_present else 0

        return pd.DataFrame([feature_dict])

    def extract_suspicious_permissions(self, input_df: pd.DataFrame, model_feature_importances: dict = None) -> list:
        """Identifies active dangerous permissions in the sample that contributed to the alert."""
        row = input_df.iloc[0]
        # Ignore metadata columns
        metadata_fields = ['Category', 'Rating', 'Number of ratings', 'Price']
        active_cols = [c for c in row[row == 1].index if c not in metadata_fields]

        suspicious_list = []
        sensitive_keywords = ['sms', 'location', 'gps', 'camera', 'audio', 'contacts', 'phone', 'boot', 'system', 'storage', 'internet']

        for col in active_cols:
            col_lower = col.lower()
            if any(keyword in col_lower for keyword in sensitive_keywords):
                importance_score = model_feature_importances.get(col, 0.0) if model_feature_importances else 0.0
                suspicious_list.append({
                    "permission": col,
                    "risk_level": "High" if importance_score > 0.01 else "Medium",
                    "feature_importance": round(float(importance_score), 4)
                })

        return sorted(suspicious_list, key=lambda x: x['feature_importance'], reverse=True)