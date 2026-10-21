import pandas as pd
from sklearn.metrics import matthews_corrcoef, roc_auc_score
from sklearn.model_selection import train_test_split

from model import Model
from preprocessor import Preprocessor


def main():
  data_path = '../Dataset/data.csv'
  print(f'Loading dataset: {data_path}')
  raw_df = pd.read_csv(data_path)

  preprocessor_handler = Preprocessor(raw_df)
  X, y = preprocessor_handler.extract_features_and_target()

  X_train, X_test, y_train, y_test = train_test_split(
      X, y, test_size=0.20, random_state=42, stratify=y
  )
  print(
      f'Data split ready. Train samples: {X_train.shape[0]} | Test samples:'
      f' {X_test.shape[0]}'
  )

  model_types = ['random_forest', 'extra_trees']
  best_test_mcc = -1.0
  best_model_obj = None

  for m_type in model_types:
    print(f'\n--- Initializing {m_type.upper()} Pipeline ---')
    model = Model(
        model_type=m_type,
        preprocessor=preprocessor_handler.transformer,
    )

    cv_res = model.cross_validate(X_train, y_train)
    print(
        f'5-Fold CV ROC-AUC: {cv_res["mean_auc"]:.4f} (+/-'
        f' {cv_res["std_auc"]:.4f})'
    )

    model.fit(X_train, y_train)

    optimal_threshold = model.find_optimal_threshold(X_test, y_test)
    model.threshold = optimal_threshold

    model.evaluate(X_test, y_test)

    y_prob = model.pipeline.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= model.threshold).astype(int)

    current_test_mcc = matthews_corrcoef(y_test, y_pred)
    current_test_auc = roc_auc_score(y_test, y_prob)

    print(
        f'Test MCC: {current_test_mcc:.4f} | Test ROC-AUC:'
        f' {current_test_auc:.4f}'
    )

    if current_test_mcc > best_test_mcc:
      best_test_mcc = current_test_mcc
      best_model_obj = model

  print(
      f'\nSaving Champion Model ({best_model_obj.model_type}) with Test MCC:'
      f' {best_test_mcc:.4f} and Threshold: {best_model_obj.threshold:.4f}...'
  )
  best_model_obj.save()


if __name__ == '__main__':
  main()