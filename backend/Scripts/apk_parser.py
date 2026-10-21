import os
import pandas as pd

try:
  from androguard.core.apk import APK
except ImportError:
  APK = None


class AndroidPermissionExtractor:
  """Parses APK permissions and builds feature vectors matching dataset columns."""

  def __init__(self, dataset_permission_cols: list):
    self.dataset_permission_cols = dataset_permission_cols

  def extract_permissions_from_apk(self, file_path: str) -> list:
    """Parses requested permissions from .apk file using androguard."""
    if APK is None:
      raise ImportError(
          'androguard is not installed. Run `pip install androguard`.'
      )

    ext = os.path.splitext(file_path)[1].lower()
    if ext != '.apk':
      raise ValueError(
          f'Unsupported file format: {ext}. Upload a valid .apk file.'
      )

    apk_obj = APK(file_path)
    return apk_obj.get_permissions()

  def map_to_feature_vector(
      self, extracted_permissions: list
  ) -> pd.DataFrame:
    """Maps extracted APK permission list directly into dataset column format."""
    # Convert extracted permissions to lower case for exact and suffix matching
    extracted_perms_lower = set([p.lower() for p in extracted_permissions])
    extracted_short_names = set(
        [p.split('.')[-1].upper() for p in extracted_permissions]
    )

    feature_dict = {}

    for col in self.dataset_permission_cols:
      col_lower = col.lower()
      col_short = col.split('.')[-1].upper()

      # Direct full name match or short-name match
      if (
          col_lower in extracted_perms_lower
          or col_short in extracted_short_names
      ):
        feature_dict[col] = 1
      else:
        feature_dict[col] = 0

    return pd.DataFrame([feature_dict])

  def extract_suspicious_permissions(
      self,
      input_df: pd.DataFrame,
      model_feature_importances: dict = None,
  ) -> list:
    """Identifies active permissions in the APK and assigns risk level based on model feature importances."""
    row = input_df.iloc[0]
    active_cols = [c for c in row[row == 1].index]

    suspicious_list = []

    for col in active_cols:
      importance_score = (
          model_feature_importances.get(col, 0.0)
          if model_feature_importances
          else 0.0
      )

      if importance_score >= 0.050:
        risk = 'Critical'
      elif importance_score >= 0.015:
        risk = 'High'
      elif importance_score >= 0.005:
        risk = 'Medium'
      else:
        risk = 'Low'

      suspicious_list.append({
          'permission': col,
          'risk_level': risk,
          'feature_importance': round(float(importance_score), 4),
      })

    return sorted(
        suspicious_list, key=lambda x: x['feature_importance'], reverse=True
    )