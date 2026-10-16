import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.feature_selection import VarianceThreshold


class Preprocessor:
    """Handles feature categorizations, cleaning, and Scikit-Learn pipeline construction

    for Android APK permission & store metadata.
    """

    METADATA_COLS = ['App', 'Package', 'Description', 'Related apps']
    TARGET_COL = 'Class'
    CATEGORICAL_COLS = ['Category']
    NUMERIC_COLS = ['Rating', 'Number of ratings', 'Price']
    EXCLUDED_COLS = METADATA_COLS + [TARGET_COL] + [
        'Dangerous permissions count',
        'Safe permissions count',
    ]

    def __init__(self, raw_df: pd.DataFrame):
        self.raw_df = raw_df
        self.permission_cols = self._extract_permission_columns()
        self.transformer = self._build_column_transformer()

    def _extract_permission_columns(self) -> list:

        non_perm = ( self.EXCLUDED_COLS + self.CATEGORICAL_COLS + self.NUMERIC_COLS)
        return [col for col in self.raw_df.columns if col not in non_perm]

    def _build_column_transformer(self) -> ColumnTransformer:
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
        X = self.raw_df.drop(columns=self.EXCLUDED_COLS)
        y = self.raw_df[self.TARGET_COL]
        return X, y