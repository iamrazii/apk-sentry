import joblib
import pandas as pd
from typing import List, Dict, Any
from Scripts.apk_parser import AndroidPermissionExtractor


class MLClassifier:

    def __init__(self,model_path: str,feature_cols: List[str] = None,default_threshold: float = None):
        loaded_data = joblib.load(model_path)

        if isinstance(loaded_data, dict):
            self.pipeline = loaded_data["pipeline"]
            self.threshold = default_threshold if default_threshold is not None else loaded_data.get("threshold", 0.35)
        else:
            self.pipeline = loaded_data
            self.threshold = default_threshold if default_threshold is not None else 0.35

        if feature_cols:
            self.dataset_permission_cols = feature_cols
        else:
            self.dataset_permission_cols = self._extract_feature_columns()

        self.extractor = AndroidPermissionExtractor(self.dataset_permission_cols)

    def _extract_feature_columns(self) -> List[str]:
        try:
            preprocessor = self.pipeline.named_steps["preprocessor"]
            
            if hasattr(preprocessor, "permission_cols"):
                return list(preprocessor.permission_cols)
            elif hasattr(preprocessor, "feature_names_in_"):
                return list(preprocessor.feature_names_in_)
            else:
                raise AttributeError("Could not find feature columns in preprocessor.")
        except Exception as e:
            raise AttributeError(
                f"Failed to auto-detect feature columns from model pipeline: {str(e)}\n"
                "Please pass `feature_cols` explicitly when initializing MLClassifier."
            )

    def predict( self, extracted_permissions: List[str], threshold = None) -> Dict[str, Any]:
        input_df: pd.DataFrame = self.extractor.map_to_feature_vector(extracted_permissions)
        if threshold:
            self.threshold = threshold
        probabilities = self.pipeline.predict_proba(input_df)[0]
        malware_probability = float(probabilities[1])


        is_malware = malware_probability >= self.threshold
        confidence = ( malware_probability if is_malware else (1.0 - malware_probability))

        return {
            "malware_probability": round(malware_probability, 4),
            "confidence": round(confidence, 4),
            "threshold_used": self.threshold,
            "is_malware_ml": bool(is_malware),
            "feature_df": input_df,
        }