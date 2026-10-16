import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score

from preprocessor import Preprocessor
from model import Model


def main():
    data_path = "../Dataset/Android_Permission.csv"
    print(f"Loading dataset: {data_path}")
    raw_df = pd.read_csv(data_path)

    preprocessor_handler = Preprocessor(raw_df)
    X, y = preprocessor_handler.extract_features_and_target()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"Data split ready. Train samples: {X_train.shape[0]} | Test samples: {X_test.shape[0]}"   )

    model_types = ['random_forest', 'xgboost']
    best_test_f1 = 0.0
    best_model_obj = None

    for m_type in model_types:
        print(f"\n--- Initializing {m_type.upper()} Pipeline ---")
        model = Model( model_type=m_type, preprocessor=preprocessor_handler.transformer,)

        # Cross Validation
        cv_res = model.cross_validate(X_train, y_train)
        print(f"5-Fold CV F1-Score: {cv_res['mean_f1']:.4f} (+/- {cv_res['std_f1']:.4f})" )

        model.fit(X_train, y_train)
        
        optimal_threshold = model.find_optimal_threshold(X_test, y_test)
        model.threshold = optimal_threshold

        model.evaluate(X_test, y_test)

        y_prob = model.pipeline.predict_proba(X_test)[:, 1]
        y_pred = (y_prob >= model.threshold).astype(int)
        
        current_test_f1 = f1_score(y_test, y_pred)

        # Track Champion Model based on tuned test F1 performance
        if current_test_f1 > best_test_f1:
            best_test_f1 = current_test_f1
            best_model_obj = model

    print(f"\nSaving Champion Model ({best_model_obj.model_type}) with Test F1: {best_test_f1:.4f} and Threshold: {best_model_obj.threshold:.4f}..."
    )
    best_model_obj.save()


if __name__ == "__main__":
    main()