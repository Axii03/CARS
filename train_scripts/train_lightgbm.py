import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from lightgbm import LGBMClassifier
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

# Load the data
df = pd.read_csv('combined.csv')
df = df.drop_duplicates()
df['Ware Type'] = (df['Ware Type'] == 'ransom').astype(int)

# Separate features and target
X = df.drop('Ware Type', axis=1)
y = df['Ware Type']

# Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Train LightGBM
lgbm_classifier = LGBMClassifier(
    random_state=42,
    class_weight='balanced',
    n_estimators=100
)
lgbm_classifier.fit(X_train, y_train)

# Evaluate
y_pred = lgbm_classifier.predict(X_test)
print("LightGBM Classification Report:")
print(classification_report(y_test, y_pred))

# Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
plt.title('Confusion Matrix (LightGBM)')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.show()

# Feature Importance
feature_importances = lgbm_classifier.feature_importances_
feature_names = X.columns

plt.figure(figsize=(12, 6))
sorted_idx = feature_importances.argsort()
plt.barh(feature_names[sorted_idx], feature_importances[sorted_idx], align='center')
plt.xlabel('Feature Importance')
plt.title('LightGBM Feature Importance')
plt.tight_layout()
plt.show()

# Save the model
joblib.dump(lgbm_classifier, 'lgbm_detector.joblib', compress=0, protocol=4)