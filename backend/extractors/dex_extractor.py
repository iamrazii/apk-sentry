# extractors/dex_extractor.py
from androguard.core.apk import APK
from typing import Dict, List, Tuple

class DexExtractor:
    """Extracts binary components (DEX files, native libraries) from APK archives."""

    @staticmethod
    def extract_dex_bytes(apk_path: str) -> List[Tuple[str, bytes]]:
        apk_obj = APK(apk_path)
        dex_payloads = []

        # Iterate over all compiled DEX files 
        for dex_name in apk_obj.get_dex_names():
            dex_data = apk_obj.get_file(dex_name)
            if dex_data:
                dex_payloads.append((dex_name, dex_data))

        return dex_payloads