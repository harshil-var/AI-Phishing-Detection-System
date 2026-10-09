import os
import sys
import json
import time
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score

# Ensure backend modules can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from backend.app.ml.feature_extractor import extract_url_features, FEATURE_COLUMNS

def main():
    print("=" * 60)
    print("AI Phishing Detection System - Model Training Pipeline")
    print("=" * 60)

    dataset_path = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "Dataset", "phiusiil+phishing+url+dataset", "PhiUSIIL_Phishing_URL_Dataset.csv"
    ))
    
    output_dir = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "backend", "app", "ml", "model"
    ))
    os.makedirs(output_dir, exist_ok=True)
    model_save_path = os.path.join(output_dir, "phishing_model.pkl")

    if not os.path.exists(dataset_path):
        print(f"Error: Dataset file not found at {dataset_path}")
        sys.exit(1)

    print(f"Loading dataset from: {dataset_path} ...")
    start_time = time.time()
    
    # Read subset or full dataset efficiently
    df = pd.read_csv(dataset_path, usecols=["URL", "label"])
    print(f"Dataset loaded ({len(df):,} total rows) in {time.time() - start_time:.2f}s")

    # Sample balanced dataset if large for optimal training speed & high accuracy
    sample_size = min(50000, len(df))
    print(f"Sampling {sample_size:,} balanced records for training...")
    
    df_sample = df.groupby("label", group_keys=False).apply(
        lambda x: x.sample(min(len(x), sample_size // 2), random_state=42)
    ).reset_index(drop=True)

    print(f"Sample label distribution:\n{df_sample['label'].value_counts()}")

    print("\nExtracting URL features...")
    features_list = []
    labels_list = []

    for idx, row in df_sample.iterrows():
        url_str = str(row["URL"])
        label_val = int(row["label"])  # 1 = SAFE, 0 = PHISHING
        feat_dict = extract_url_features(url_str)
        features_list.append(feat_dict)
        labels_list.append(label_val)

        if (idx + 1) % 10000 == 0:
            print(f" Processed {idx + 1}/{len(df_sample)} URLs...")

    X = pd.DataFrame(features_list)[FEATURE_COLUMNS]
    y = np.array(labels_list)

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\nTraining Random Forest Model (X_train shape: {X_train.shape})...")
    clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=20,
        min_samples_split=4,
        n_jobs=-1,
        random_state=42
    )
    clf.fit(X_train, y_train)

    # Evaluate
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred).tolist()

    print("\n" + "=" * 40)
    print("Model Evaluation Metrics:")
    print("=" * 40)
    print(f" Accuracy:  {acc * 100:.2f}%")
    print(f" Precision: {prec * 100:.2f}%")
    print(f" Recall:    {rec * 100:.2f}%")
    print(f" F1-Score:  {f1 * 100:.2f}%")
    print(f" ROC-AUC:   {roc_auc:.4f}")
    print(f" Confusion Matrix: {cm}")
    print("=" * 40)

    # Feature Importance Top 10
    importances = clf.feature_importances_
    feat_imp = sorted(zip(FEATURE_COLUMNS, importances), key=lambda x: x[1], reverse=True)
    print("\nTop 10 Feature Importances:")
    for feat, imp in feat_imp[:10]:
        print(f"  - {feat:25s}: {imp:.4f}")

    # Save model artifact
    model_data = {
        "model": clf,
        "feature_columns": FEATURE_COLUMNS,
        "label_map": {1: "SAFE", 0: "PHISHING"},
        "metrics": {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1": round(float(f1), 4),
            "roc_auc": round(float(roc_auc), 4),
            "sample_size": sample_size
        }
    }

    joblib.dump(model_data, model_save_path)
    print(f"\nSaved model artifact successfully to: {model_save_path}")

    # Save metrics JSON for documentation/API
    metrics_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "model_metrics.json"))
    with open(metrics_path, "w") as f:
        json.dump(model_data["metrics"], f, indent=2)
    print(f"Saved evaluation metrics to: {metrics_path}")

if __name__ == "__main__":
    main()
