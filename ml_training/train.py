import os
import sys
import json
import time
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, brier_score_loss,
    precision_recall_curve, auc
)

# Ensure backend modules can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from app.ml.feature_extractor import extract_url_features, FEATURE_COLUMNS

def compute_metrics(y_true, y_probs, threshold=0.5):
    """Compute comprehensive classification and probability metrics for phishing class (label=1)."""
    preds = (y_probs >= threshold).astype(int)
    acc = accuracy_score(y_true, preds)
    prec = precision_score(y_true, preds, zero_division=0)
    rec = recall_score(y_true, preds, zero_division=0)
    f1 = f1_score(y_true, preds, zero_division=0)
    roc_auc = roc_auc_score(y_true, y_probs)
    brier = brier_score_loss(y_true, y_probs)
    cm = confusion_matrix(y_true, preds)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    p_curve, r_curve, _ = precision_recall_curve(y_true, y_probs)
    pr_auc = auc(r_curve, p_curve)

    return {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1": round(float(f1), 4),
        "false_positive_rate": round(float(fpr), 4),
        "false_negative_rate": round(float(fnr), 4),
        "roc_auc": round(float(roc_auc), 4),
        "pr_auc": round(float(pr_auc), 4),
        "brier_score": round(float(brier), 4),
        "confusion_matrix": cm.tolist()
    }

def main():
    print("=" * 70)
    print("AI Phishing Detection System - Production Training & Calibration")
    print("=" * 70)

    dataset_path = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "Dataset", "phiusiil+phishing+url+dataset", "PhiUSIIL_Phishing_URL_Dataset.csv"
    ))
    
    output_dir = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "backend", "app", "ml", "model"
    ))
    os.makedirs(output_dir, exist_ok=True)
    model_save_path = os.path.join(output_dir, "phishing_model.pkl")
    baseline_model_path = os.path.join(output_dir, "phishing_model.pkl.bak")

    if not os.path.exists(dataset_path):
        print(f"Error: Dataset file not found at {dataset_path}")
        sys.exit(1)

    print(f"Loading dataset from: {dataset_path} ...")
    start_time = time.time()
    df_raw = pd.read_csv(dataset_path, usecols=["URL", "label"])
    print(f"Dataset loaded ({len(df_raw):,} total rows) in {time.time() - start_time:.2f}s")

    # Sample balanced dataset for training
    sample_per_class = 20000
    print(f"\nSampling {sample_per_class:,} legitimate and {sample_per_class:,} phishing URLs...")

    df_legit = df_raw[df_raw["label"] == 1].sample(n=sample_per_class, random_state=42).copy()
    df_phish = df_raw[df_raw["label"] == 0].sample(n=sample_per_class, random_state=42).copy()

    # Data augmentation for legitimate URLs:
    # 50% keep 'www.', 50% strip 'www.' so model generalizes cleanly across apex and www hosts
    legit_urls = df_legit["URL"].values
    for i in range(len(legit_urls) // 2):
        legit_urls[i] = legit_urls[i].replace("://www.", "://")
    df_legit["URL"] = legit_urls

    df_combined = pd.concat([df_legit, df_phish], ignore_index=True)
    # Remove any duplicate URLs
    df_combined = df_combined.drop_duplicates(subset=["URL"]).sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"Final training candidate size: {len(df_combined):,} records")
    print(f"Class distribution in raw dataset:\n{df_combined['label'].value_counts()}")

    # Target definition: 0 = SAFE, 1 = PHISHING
    # In PhiUSIIL raw labels: 1 = Legitimate, 0 = Phishing
    # We map to canonical ML binary: 0 = Safe, 1 = Phishing
    y = (df_combined["label"] == 0).astype(int).values

    cache_path = os.path.join(output_dir, "dataset_features_cache.joblib")
    if os.path.exists(cache_path):
        print(f"\nLoading cached feature matrix from: {cache_path} ...")
        cache_data = joblib.load(cache_path)
        X = cache_data["X"]
        y = cache_data["y"]
        print(f"Loaded cached features successfully: X shape {X.shape}, y balance: {np.bincount(y)}")
    else:
        print("\nExtracting feature vectors using enhanced lexical & structural parser...")
        feat_start = time.time()
        features_list = []
        for idx, url_str in enumerate(df_combined["URL"]):
            feat_dict = extract_url_features(url_str)
            features_list.append(feat_dict)
            if (idx + 1) % 10000 == 0:
                print(f"  Extracted {idx + 1:,} / {len(df_combined):,} URLs ({time.time() - feat_start:.1f}s)...")

        X = pd.DataFrame(features_list)[FEATURE_COLUMNS]
        print(f"Feature matrix shape: {X.shape} extracted in {time.time() - feat_start:.2f}s")
        joblib.dump({"X": X, "y": y}, cache_path)
        print(f"Saved feature cache to: {cache_path}")

    # 70% Train, 15% Validation, 15% Test
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )

    print(f"Dataset partitions -> Train: {X_train.shape[0]:,}, Validation: {X_val.shape[0]:,}, Test: {X_test.shape[0]:,}")

    # ==========================================
    # 1. Evaluate Baseline Model First
    # ==========================================
    baseline_metrics = None
    if os.path.exists(baseline_model_path):
        print("\nEvaluating baseline model on held-out test split...")
        try:
            old_data = joblib.load(baseline_model_path)
            old_clf = old_data.get("model")
            old_cols = old_data.get("feature_columns", FEATURE_COLUMNS)
            # Reconstruct baseline feature columns on test set
            X_test_base = X_test[[c for c in old_cols if c in X_test.columns]]
            old_probs = old_clf.predict_proba(X_test_base)
            # In old model, class 0 was phishing
            old_phish_prob = old_probs[:, 0]
            baseline_metrics = compute_metrics(y_test, old_phish_prob, threshold=0.5)
            print("Baseline Evaluation Metrics:")
            for k, v in baseline_metrics.items():
                print(f"  {k:22s}: {v}")
        except Exception as e:
            print(f"Notice: Could not evaluate baseline model: {e}")

    # ==========================================
    # 2. Model Selection on Validation Set
    # ==========================================
    print("\nComparing candidate models on validation set...")
    candidates = {
        "LogisticRegression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=600, random_state=42, C=1.0))
        ]),
        "HistGradientBoosting": HistGradientBoostingClassifier(
            max_iter=120, max_depth=12, random_state=42
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=120, max_depth=18, min_samples_split=4,
            random_state=42, n_jobs=-1
        )
    }

    val_results = {}
    best_model_name = None
    best_val_f1 = -1.0

    for name, clf in candidates.items():
        t_clf = time.time()
        clf.fit(X_train, y_train)
        val_probs = clf.predict_proba(X_val)[:, 1]
        m = compute_metrics(y_val, val_probs, threshold=0.5)
        fit_time = time.time() - t_clf
        val_results[name] = m
        print(f"  [{name:20s}] ROC-AUC: {m['roc_auc']:.4f} | F1: {m['f1']:.4f} | Prec: {m['precision']:.4f} | Rec: {m['recall']:.4f} | FPR: {m['false_positive_rate']:.4f} ({fit_time:.1f}s)")
        if m["f1"] > best_val_f1:
            best_val_f1 = m["f1"]
            best_model_name = name

    print(f"\nBest performing candidate: {best_model_name} (Val F1: {best_val_f1:.4f})")
    print(f"\nFitting calibrated {best_model_name} with 3-fold cross-validation (sigmoid calibration)...")
    if best_model_name == "RandomForest":
        base_model = RandomForestClassifier(
            n_estimators=120, max_depth=18, min_samples_split=4,
            random_state=42, n_jobs=-1
        )
    elif best_model_name == "HistGradientBoosting":
        base_model = HistGradientBoostingClassifier(
            max_iter=120, max_depth=12, random_state=42
        )
    else:
        base_model = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=600, random_state=42, C=1.0))
        ])

    calibrated_clf = CalibratedClassifierCV(
        estimator=base_model,
        method="sigmoid",
        cv=3
    )
    calibrated_clf.fit(X_train, y_train)

    # ==========================================
    # 4. Decision Threshold Selection on Validation Set
    # ==========================================
    val_cal_probs = calibrated_clf.predict_proba(X_val)[:, 1]
    
    # Evaluate thresholds from 0.40 to 0.70 to minimize false positives while maintaining >= 95% recall
    best_thresh = 0.50
    lowest_fpr_with_high_recall = 1.0
    for t_cand in np.arange(0.40, 0.75, 0.05):
        m_t = compute_metrics(y_val, val_cal_probs, threshold=t_cand)
        if m_t["recall"] >= 0.95 and m_t["false_positive_rate"] < lowest_fpr_with_high_recall:
            lowest_fpr_with_high_recall = m_t["false_positive_rate"]
            best_thresh = round(float(t_cand), 2)

    print(f"Optimal decision threshold selected: {best_thresh} (Val FPR: {lowest_fpr_with_high_recall:.4f})")

    # ==========================================
    # 5. Final Evaluation on Held-Out Test Set
    # ==========================================
    print("\n" + "=" * 50)
    print("FINAL EVALUATION ON UNTOUCHED HELD-OUT TEST SET")
    print("=" * 50)
    test_probs = calibrated_clf.predict_proba(X_test)[:, 1]
    test_metrics = compute_metrics(y_test, test_probs, threshold=best_thresh)

    for k, v in test_metrics.items():
        print(f"  {k:22s}: {v}")
    print("=" * 50)

    # Feature Importances (from tree-based model if available)
    try:
        best_cand = candidates[best_model_name]
        if hasattr(best_cand, "feature_importances_"):
            importances = best_cand.feature_importances_
        elif hasattr(best_cand, "named_steps") and hasattr(best_cand.named_steps.get("clf"), "feature_importances_"):
            importances = best_cand.named_steps["clf"].feature_importances_
        else:
            importances = None

        if importances is not None:
            feat_imp = sorted(zip(FEATURE_COLUMNS, importances), key=lambda x: x[1], reverse=True)
            print("\nTop 12 Most Significant Features:")
            for feat, imp in feat_imp[:12]:
                print(f"  - {feat:25s}: {imp:.4f}")
    except Exception:
        pass

    # ==========================================
    # 6. Save Model Artifact & Metrics
    # ==========================================
    model_artifact = {
        "model": calibrated_clf,
        "feature_columns": FEATURE_COLUMNS,
        "classes_": np.array([0, 1]),
        "target_mapping": {0: "SAFE", 1: "PHISHING"},
        "phishing_class_index": 1,
        "thresholds": {
            "suspicious": 0.35,
            "phishing": best_thresh
        },
        "metrics": test_metrics,
        "baseline_metrics": baseline_metrics,
        "model_version": f"2.0.0-calibrated-{best_model_name.lower()}",
        "sample_size": len(df_combined)
    }

    joblib.dump(model_artifact, model_save_path)
    print(f"\nSaved optimized model artifact to: {model_save_path}")

    metrics_save_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "model_metrics.json"))
    with open(metrics_save_path, "w") as f:
        json.dump({
            "final_model": test_metrics,
            "baseline_model": baseline_metrics,
            "validation_comparison": val_results,
            "selected_model": best_model_name,
            "threshold": best_thresh,
            "feature_count": len(FEATURE_COLUMNS),
            "sample_size": len(df_combined)
        }, f, indent=2)
    print(f"Saved evaluation comparison to: {metrics_save_path}")

    # ==========================================
    # 7. Benchmark Real-World Regression Tests
    # ==========================================
    print("\n" + "=" * 50)
    print("REAL-WORLD BENCHMARK VERIFICATION (WITHOUT WHITELIST)")
    print("=" * 50)
    test_urls = [
        "https://leetcode.com",
        "https://www.leetcode.com",
        "https://youtube.com",
        "https://www.youtube.com",
        "https://google.com",
        "https://www.google.com",
        "https://github.com",
        "https://microsoft.com",
        "https://www.microsoft.com",
        "http://phishing-site.xyz/login/verify.php",
        "http://192.168.1.1/update",
        "https://f1ipkart.com",
        "http://paypal-verification-update.com/account"
    ]

    for u in test_urls:
        u_feat = extract_url_features(u)
        df_u = pd.DataFrame([u_feat])[FEATURE_COLUMNS]
        prob_phish = float(calibrated_clf.predict_proba(df_u)[0][1])
        prob_safe = 1.0 - prob_phish
        if prob_phish >= best_thresh:
            verdict = "PHISHING"
        elif prob_phish >= 0.35:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"
        print(f"  {u:45s} -> Phishing: {prob_phish * 100:5.1f}% | Safe: {prob_safe * 100:5.1f}% => {verdict}")
    print("=" * 50)

if __name__ == "__main__":
    main()
