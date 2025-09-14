import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from xgboost import XGBClassifier
import shap


df = pd.read_csv('combined.csv')


df = df.drop_duplicates()


df['Ware Type'] = (df['Ware Type'] == 'ransom').astype(int)


X = df.drop('Ware Type', axis=1)
y = df['Ware Type']


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)


class_counts = np.bincount(y_train)
scale_pos_weight = class_counts[0] / class_counts[1] 


xgb_classifier = XGBClassifier(
    use_label_encoder=False,
    eval_metric='logloss',
    random_state=42,
    scale_pos_weight=scale_pos_weight
)

xgb_classifier.fit(X_train, y_train)

y_pred = xgb_classifier.predict(X_test)


print("Classification Report:")
print(classification_report(y_test, y_pred))


cm = confusion_matrix(y_test, y_pred)


plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
plt.title('Confusion Matrix')
plt.xlabel('Predicted Class')
plt.ylabel('Actual Class')
plt.show()


feature_importance = xgb_classifier.feature_importances_
feature_names = X.columns
sorted_idx = np.argsort(feature_importance)
pos = np.arange(sorted_idx.shape[0]) + .5

plt.figure(figsize=(12, 6))
plt.barh(pos, feature_importance[sorted_idx], align='center')
plt.yticks(pos, feature_names[sorted_idx])
plt.xlabel('Feature Importance')
plt.title('XGBoost Feature Importance')
plt.tight_layout()
plt.show()

''' SHAP values and summary plot
explainer = shap.TreeExplainer(xgb_classifier)
shap_values = explainer.shap_values(X_test)
shap.summary_plot(shap_values, X_test)
'''
#joblib.dump(xgb_classifier, 'xgb_detector.joblib', compress=0, protocol=4)
