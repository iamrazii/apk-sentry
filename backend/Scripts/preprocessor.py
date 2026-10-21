import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_selection import VarianceThreshold
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline


class Preprocessor:
  """Handles data pipeline transformation for pure-permission dataset."""

  TARGET_COL = 'Result'

  def __init__(self, raw_df: pd.DataFrame):
    self.raw_df = raw_df.copy()
    self.permission_cols = [
        c for c in self.raw_df.columns if c != self.TARGET_COL
    ]
    self.transformer = self._build_column_transformer()

  def _build_column_transformer(self) -> ColumnTransformer:
    permission_transformer = Pipeline(
        steps=[
            ('imputer', SimpleImputer(strategy='most_frequent')),
            ('variance_selector', VarianceThreshold(threshold=0.0)),
        ]
    )

    return ColumnTransformer(
        transformers=[
            ('perm', permission_transformer, self.permission_cols),
        ]
    )

  def extract_features_and_target(self) -> tuple[pd.DataFrame, pd.Series]:
    X = self.raw_df.drop(columns=[self.TARGET_COL])
    y = self.raw_df[self.TARGET_COL]
    return X, y