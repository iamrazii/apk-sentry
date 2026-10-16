import os
import joblib
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score



class Model:

    SUPPORTED_MODELS = {'random_forest': RandomForestClassifier, 'xgboost': XGBClassifier}
    def __init__(self,model_type,preprocessor,**kwargs):
        if model_type not in self.SUPPORTED_MODELS:
            raise ValueError(
                f"Model type '{model_type}' not supported. Choose from {list(self.SUPPORTED_MODELS.keys())}"
            )
        self.model_type = model_type
        self.preprocessor = preprocessor

        self.classifier = self._init_classifier(model_type, **kwargs)
        self.pipeline = Pipeline(
            steps=[
                ('preprocessor', self.preprocessor),
                ('classifier', self.classifier),
            ]
        )


    def _init_classifier(self, model_type: str, **kwargs):

        """Instantiates the specific ML algorithm with hyperparameters."""

        if model_type == 'random_forest':
            defaults = {'n_estimators': 100, 'random_state': 42, 'n_jobs': -1}
            defaults.update(kwargs)
            return RandomForestClassifier(**defaults)

        elif model_type == 'xgboost':
            defaults = {
                'n_estimators': 100,
                'learning_rate': 0.1,
                'max_depth': 6,
                'random_state': 42,
                'n_jobs': -1,
            }
            defaults.update(kwargs)
            return XGBClassifier(**defaults)

    def cross_validate(
        self, X_train: pd.DataFrame, y_train: pd.Series, cv_splits: int = 5
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

    def evaluate(self, X_test: pd.DataFrame, y_test: pd.Series):
        y_pred = self.pipeline.predict(X_test)
        y_prob = self.pipeline.predict_proba(X_test)[:, 1]

        print(
            f"\n================ Evaluation: {self.model_type.upper()} ================"
        )
        print(classification_report(y_test, y_pred, digits=4))
        print(f"ROC-AUC Score: {roc_auc_score(y_test, y_prob):.4f}")
        print("Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred))

    def predict(self, X_input: pd.DataFrame) -> dict:
        prediction = self.pipeline.predict(X_input)[0]
        confidence = self.pipeline.predict_proba(X_input)[0][prediction]
        return {'is_malware': int(prediction), 'confidence': float(confidence)}

    def save(self, output_dir: str = 'artifacts'):

        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(
            output_dir, f'android_malware_{self.model_type}.joblib'
        )
        joblib.dump(self.pipeline, filepath)
        print(f"Pipeline saved to: {filepath}")

    @classmethod
    def load(cls, filepath: str):   # static method for getting instance of model
        """Loads a pre-trained pipeline artifact directly from disk."""
        instance = cls.__new__(cls)
        instance.pipeline = joblib.load(filepath)
        return instance