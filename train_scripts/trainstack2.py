import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.ensemble import StackingClassifier, ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import numpy as np
from lightgbm import LGBMClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier

# Load the data
df = pd.read_csv('combined.csv')
df = df.drop_duplicates()
df['Ware Type'] = (df['Ware Type'] == 'ransom').astype(int)

# Separate features and target
X = df.drop('Ware Type', axis=1)
y = df['Ware Type']

# Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Calculate class weights
class_counts = y_train.value_counts()
scale_pos_weight = class_counts[0] / class_counts[1]

# Define base models
xgb_classifier = XGBClassifier(
    use_label_encoder=False,
    eval_metric='logloss',
    random_state=42,
    scale_pos_weight=scale_pos_weight
)
lgbm_classifier = LGBMClassifier(random_state=42, class_weight='balanced')
et_classifier = ExtraTreesClassifier(random_state=42, class_weight='balanced')

# Stacking Classifier
stacking_classifier = StackingClassifier(
    estimators=[
        ('xgb', xgb_classifier),
        ('et', et_classifier)
    ],
    final_estimator=SVC(probability=True, random_state=42)
)
stacking_classifier.fit(X_train, y_train)

# Evaluate
y_pred = stacking_classifier.predict(X_test)
print("Stacking Classifier Classification Report:")
print(classification_report(y_test, y_pred))

# Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
plt.title('Confusion Matrix (Stacking)')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.show()

# Access the fitted base models from the stacking classifier
lgbm_fitted = stacking_classifier.named_estimators_['lgbm']
xgb_fitted = stacking_classifier.named_estimators_['xgb']

# Get feature importances from the fitted base models
lgbm_feature_importances = lgbm_fitted.feature_importances_
xgb_feature_importances = xgb_fitted.feature_importances_
feature_names = X.columns

# Combine feature importances (average them for simplicity)
combined_feature_importances = (lgbm_feature_importances + xgb_feature_importances) / 2

# Plot feature importance
sorted_idx = np.argsort(combined_feature_importances)
plt.figure(figsize=(12, 6))
plt.barh(feature_names[sorted_idx], combined_feature_importances[sorted_idx], align='center')
plt.xlabel('Feature Importance')
plt.title('Feature Importance (Stacking: LGBM + XGBoost + Extra Trees)')
plt.tight_layout()
plt.show()

# Save the model
joblib.dump(stacking_classifier, 'stacking_detector.joblib', compress=0, protocol=4)