import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_selection import VarianceThreshold
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


class Preprocessor:
  """Handles feature categorization, security interaction engineering, and Scikit-Learn transformer pipelines."""

  METADATA_COLS = ['App', 'Package', 'Description', 'Related apps']
  TARGET_COL = 'Class'
  CATEGORICAL_COLS = ['Category']
  NUMERIC_COLS = ['Rating', 'Number of ratings', 'Price']
  EXCLUDED_COLS = METADATA_COLS + [
      TARGET_COL,
      'Dangerous permissions count',
      'Safe permissions count',
  ]

  def __init__(self, raw_df: pd.DataFrame):
    self.raw_df = self._add_security_interaction_features(raw_df.copy())
    self.permission_cols = self._extract_permission_columns()
    self.transformer = self._build_column_transformer()

  def _add_security_interaction_features(
      self, df: pd.DataFrame
  ) -> pd.DataFrame:
    """Engineers explicit domain-specific permission combinations for malware detection."""
    #  SMS Exfiltration / Banking Trojan: Read/Receive SMS + Full Internet
    sms_cols = [  col for col in df.columns if 'SMS' in col or 'receive SMS' in col or 'read SMS' in col]
    internet_cols = [ col for col in df.columns if 'full Internet access' in col]

    if sms_cols and internet_cols:
      df['feature_combo_sms_exfiltration'] = ( (df[sms_cols].sum(axis=1) > 0) & (df[internet_cols].sum(axis=1) > 0) ).astype(int)

    # 2. Spyware / Location Exfiltration: Fine/Coarse Location + Full Internet
    location_cols = [ col for col in df.columns if 'GPS' in col or 'coarse' in col]
    if location_cols and internet_cols:
      df['feature_combo_location_tracking'] = ((df[location_cols].sum(axis=1) > 0)& (df[internet_cols].sum(axis=1) > 0)).astype(int)

    # 3. Persistent Trojan / Ransomware: Start at Boot + Prevent Sleeping / Display System Alerts
    boot_cols = [ col for col in df.columns if 'automatically start at boot' in col]
    overlay_cols = [ col for col in df.columns if 'display system-level alerts' in col or 'prevent device from sleeping' in col ]
    if boot_cols and overlay_cols:
      df['feature_combo_persistence_overlay'] = ( (df[boot_cols].sum(axis=1) > 0) & (df[overlay_cols].sum(axis=1) > 0)).astype(int)

    #  Privilege Escalation / Sensitive Logs: Read Contact/Logs + Write External Storage
    sensitive_cols = [ col for col in df.columns if 'contact data' in col or 'sensitive log data' in col]
    storage_cols = [col for col in df.columns if 'modify/delete' in col]
    if sensitive_cols and storage_cols:
      df['feature_combo_data_harvesting'] = ( (df[sensitive_cols].sum(axis=1) > 0) & (df[storage_cols].sum(axis=1) > 0) ).astype(int)

    if 'Number of ratings' in df.columns:
      df['Number of ratings'] = np.log1p(df['Number of ratings'].fillna(0))

    return df

  def _extract_permission_columns(self) -> list:
    """Identifies all binary permission columns including engineered interaction flags."""
    non_perm = (
        self.EXCLUDED_COLS + self.CATEGORICAL_COLS + self.NUMERIC_COLS
    )
    return [col for col in self.raw_df.columns if col not in non_perm]

  def _build_column_transformer(self) -> ColumnTransformer:
    """Constructs the Scikit-Learn ColumnTransformer pipeline."""
    numeric_transformer = Pipeline(
        steps=[
            ('imputer', SimpleImputer(strategy='median')),
            ('scaler', StandardScaler()),
        ]
    )

    categorical_transformer = Pipeline(
        steps=[
            ('imputer', SimpleImputer(strategy='most_frequent')),
            (
                'encoder',
                OneHotEncoder(handle_unknown='ignore', sparse_output=False),
            ),
        ]
    )

    permission_transformer = Pipeline(
        steps=[
            ('imputer', SimpleImputer(strategy='most_frequent')),
            ('variance_selector', VarianceThreshold(threshold=0.0)),
        ]
    )

    return ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, self.NUMERIC_COLS),
            ('cat', categorical_transformer, self.CATEGORICAL_COLS),
            ('perm', permission_transformer, self.permission_cols),
        ]
    )

  def extract_features_and_target(self) -> tuple[pd.DataFrame, pd.Series]:
    """Splits dataframe into feature matrix X and target vector y."""
    X = self.raw_df.drop(columns=self.EXCLUDED_COLS)
    y = self.raw_df[self.TARGET_COL]
    return X, y