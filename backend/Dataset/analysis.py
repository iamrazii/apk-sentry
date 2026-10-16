import pandas as pd
import numpy as np
from sklearn.feature_selection import mutual_info_classif
df = pd.read_csv("Android_Permission.csv")

print(f"Dataset Shape: {df.shape}")

print("\n--- Target Class Distribution ---")
print(df['Class'].value_counts(dropna=False))
print(df['Class'].value_counts(normalize=True) * 100)

# 3. Separate Metadata vs. Feature Columns
metadata_cols = ['App', 'Package', 'Description', 'Related apps']
target_col = 'Class'

permission_cols = [col for col in df.columns if col not in metadata_cols + [target_col, 'Category', 'Rating', 'Number of ratings', 'Price', 'Dangerous permissions count', 'Safe permissions count']]

print(f"\nNumber of permission flag features: {len(permission_cols)}")

# 4. Check missing values across feature columns
missing_counts = df.isna().sum()
print("\n--- Columns with Missing Values ---")
print(missing_counts[missing_counts > 0])

# 5. Permission Sparsity Check (How frequently are permissions requested?)
permission_sum = df[permission_cols].sum().sort_values(ascending=False)
print("\n--- Top 10 Most Frequently Requested Permissions ---")
print(permission_sum.head(10))

print("\n--- Zero-Variance Permissions (Never requested in dataset) ---")
zero_var_permissions = permission_sum[permission_sum == 0].index.tolist()
print(f"Count of zero-variance permission columns: {len(zero_var_permissions)}")


X_temp = df.drop(columns=metadata_cols + ['Class', 'Category']).fillna(0)
y_temp = df['Class']

# Calculate Mutual Information Scores for binary permission features
mi_scores = mutual_info_classif(X_temp, y_temp, random_state=42)
mi_series = pd.Series(mi_scores, index=X_temp.columns).sort_values(ascending=False)

print("--- Top 15 Most Informative Features for Detecting Malware ---")
print(mi_series.head(15))