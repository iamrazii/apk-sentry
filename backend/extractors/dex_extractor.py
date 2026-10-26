# extractors/dex_extractor.py
import math
from androguard.core.apk import APK
from typing import Dict, Any

class DexExtractor:
    """Extracts DEX bytecode, native binaries (.so), and measures payload entropy."""

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculates Shannon Entropy (0.0 to 8.0) to detect packed/encrypted blobs."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for x in range(256):
            p_x = data.count(bytes([x])) / length
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return round(entropy, 4)

    @classmethod
    def extract_all(cls, apk_path: str) -> Dict[str, Any]:
        apk_obj = APK(apk_path)
        dex_payloads = []
        high_entropy_assets = []
        native_libs = []

        # Iterate through all files inside the APK ZIP archive
        for file_path in apk_obj.get_files():
            file_bytes = apk_obj.get_file(file_path)
            if not file_bytes:
                continue

            # 1. DEX Bytecode
            if file_path.endswith('.dex'):
                dex_payloads.append((file_path, file_bytes))
            
            # 2. Native C/C++ Libraries
            elif file_path.endswith('.so'):
                native_libs.append((file_path, file_bytes))

            # 3. Encrypted/Packed Asset Payloads (Models, Droppers, Encrypted DEX)
            elif file_path.startswith('assets/'):
                entropy = cls.calculate_entropy(file_bytes)
                if entropy > 7.2:  # Mathematical threshold for encrypted/compressed content
                    high_entropy_assets.append({
                        "path": file_path,
                        "size": len(file_bytes),
                        "entropy": entropy
                    })

        return {
            "dex_payloads": dex_payloads,
            "native_libs": native_libs,
            "high_entropy_assets": high_entropy_assets
        }