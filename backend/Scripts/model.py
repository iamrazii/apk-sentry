import os
import joblib
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_recall_curve


class Model:

    SUPPORTED_MODELS = {'random_forest': RandomForestClassifier, 'xgboost': XGBClassifier}
    
    def __init__(self, model_type: str, preprocessor, threshold: float = 0.5, **kwargs):
        if model_type not in self.SUPPORTED_MODELS:
            raise ValueError(
                f"Model type '{model_type}' not supported. Choose from {list(self.SUPPORTED_MODELS.keys())}"
            )
        self.model_type = model_type
        self.preprocessor = preprocessor
        self.threshold = threshold

        self.classifier = self._init_classifier(model_type, **kwargs)
        self.pipeline = Pipeline(
            steps=[
                ('preprocessor', self.preprocessor),
                ('classifier', self.classifier),
            ]
        )

    def _init_classifier(self, model_type: str, **kwargs):
        """Instantiates the specific ML algorithm with optimized default hyperparameters."""
        if model_type == 'random_forest':
            defaults = {
                'n_estimators': 150,
                'max_depth': 25,
                'max_features': 'sqrt',
                'class_weight': 'balanced',
                'random_state': 42,
                'n_jobs': -1
            }
            defaults.update(kwargs)
            return RandomForestClassifier(**defaults)

        elif model_type == 'xgboost':
            defaults = {
                'n_estimators': 150,
                'learning_rate': 0.1,
                'max_depth': 8,
                'subsample': 0.8,
                'scale_pos_weight': 1.0,
                'random_state': 42,
                'n_jobs': -1,
            }
            defaults.update(kwargs)
            return XGBClassifier(**defaults)

    def cross_validate(
        self, X_train: pd.DataFrame, y_train: pd.Series, cv_splits: int = 3
    ) -> dict:
        skf = StratifiedKFold(
            n_splits=cv_splits, shuffle=True, random_state=42
        )
        scores = cross_val_score(
            self.pipeline, X_train, y_train, cv=skf, scoring='f1'
        )
        return {'mean_f1': scores.mean(), 'std_f1': scores.std()}

    def fit(self, X_train: pd.DataFrame, y_train: pd.Series):
        self.pipeline.fit(X_train, y_train)

    def find_optimal_threshold(self, X_test: pd.DataFrame, y_test: pd.Series) -> float:
        """Finds the probability threshold that maximizes F1-Score."""
        y_probs = self.pipeline.predict_proba(X_test)[:, 1]
        precisions, recalls, thresholds = precision_recall_curve(y_test, y_probs)
        
        f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-10)
        best_idx = np.argmax(f1_scores)
        best_thresh = float(thresholds[best_idx])
        
        print(f"\n[{self.model_type.upper()}] Best F1 Threshold Found: {best_thresh:.4f}")
        return best_thresh

    def evaluate(self, X_test: pd.DataFrame, y_test: pd.Series, threshold: float = None):
        eval_thresh = threshold if threshold is not None else self.threshold
        y_prob = self.pipeline.predict_proba(X_test)[:, 1]
        y_pred = (y_prob >= eval_thresh).astype(int)

        print(
            f"\n================ Evaluation: {self.model_type.upper()} (Threshold: {eval_thresh:.2f}) ================"
        )
        print(classification_report(y_test, y_pred, digits=4))
        print(f"ROC-AUC Score: {roc_auc_score(y_test, y_prob):.4f}")
        print("Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred))

    def predict(self, X_input: pd.DataFrame, threshold: float = None) -> dict:
        eval_thresh = threshold if threshold is not None else self.threshold
        prob = float(self.pipeline.predict_proba(X_input)[0][1])
        prediction = 1 if prob >= eval_thresh else 0
        return {
            'is_malware': prediction,
            'confidence': round(prob if prediction == 1 else 1 - prob, 4),
            'malware_probability': round(prob, 4),
            'threshold_used': eval_thresh
        }

    def save(self, output_dir: str = 'artifacts'):
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(
            output_dir, f'android_malware_{self.model_type}.joblib'
        )
        payload = {
            'pipeline': self.pipeline,
            'threshold': self.threshold
        }
        joblib.dump(payload, filepath)
        print(f"Pipeline saved to: {filepath}")

    @classmethod
    def load(cls, filepath: str):
        instance = cls.__new__(cls)
        data = joblib.load(filepath)
        if isinstance(data, dict):
            instance.pipeline = data['pipeline']
            instance.threshold = data.get('threshold', 0.5)
        else:
            instance.pipeline = data
            instance.threshold = 0.5
        return instance