"""
AI-Based Malicious URL Detection System
Independent Model Evaluation & Diagnostic Script

Evaluates a saved RandomForest model against an un-seen test set,
computes detailed metrics, analyzes False Negatives (missed threats),
and prints actionable threat detection diagnostics.
"""

import os
import sys
import json
import csv
from typing import List, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import extract_url_vector, FEATURE_NAMES

MODEL_PATH = "models/url_classifier.joblib"
CONFIG_PATH = "models/feature_config.json"
DEFAULT_TEST_PATH = "data/processed/test.csv"

def evaluate(test_csv_path: str = DEFAULT_TEST_PATH):
    if not os.path.exists(MODEL_PATH):
        print(f"❌ Trained model not found at '{MODEL_PATH}'. Please run 'python train_model.py' first.")
        return

    if not os.path.exists(test_csv_path):
        print(f"❌ Test dataset not found at '{test_csv_path}'.")
        return

    try:
        import joblib
        from sklearn.metrics import (
            accuracy_score,
            precision_score,
            recall_score,
            f1_score,
            confusion_matrix,
            classification_report
        )
    except ImportError:
        print("❌ Please ensure scikit-learn and joblib are installed.")
        return

    print("=" * 70)
    print("AI-BASED MALICIOUS URL DETECTION SYSTEM - MODEL EVALUATION")
    print(f"Loading model: {MODEL_PATH}")
    print(f"Test dataset:  {test_csv_path}")
    print("=" * 70)

    # 1. Load model and config
    model = joblib.load(MODEL_PATH)
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        config = json.load(f)

    label_encoding = config.get("label_encoding", {"LEGITIMATE": 0, "MALICIOUS": 1})

    # 2. Load test records
    urls = []
    y_true = []
    with open(test_csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            u = (row.get("url") or "").strip()
            lbl = (row.get("label") or "").strip().upper()
            if u and lbl in label_encoding:
                urls.append(u)
                y_true.append(label_encoding[lbl])

    # 3. Extract features
    X_test = []
    valid_urls = []
    valid_y = []
    for u, y in zip(urls, y_true):
        try:
            vec = extract_url_vector(u)
            X_test.append(vec)
            valid_urls.append(u)
            valid_y.append(y)
        except Exception:
            continue

    # 4. Predict
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    # 5. Metrics
    acc = accuracy_score(valid_y, y_pred)
    prec = precision_score(valid_y, y_pred, zero_division=0)
    rec = recall_score(valid_y, y_pred, zero_division=0)
    f1 = f1_score(valid_y, y_pred, zero_division=0)
    cm = confusion_matrix(valid_y, y_pred)

    tn = cm[0][0] if len(cm) > 0 and len(cm[0]) > 0 else 0
    fp = cm[0][1] if len(cm) > 0 and len(cm[0]) > 1 else 0
    fn = cm[1][0] if len(cm) > 1 and len(cm[1]) > 0 else 0
    tp = cm[1][1] if len(cm) > 1 and len(cm[1]) > 1 else 0

    print(f"\nEvaluated {len(valid_urls)} test samples:")
    print(f" • Accuracy:              {acc * 100:.2f}%")
    print(f" • Precision (Malicious): {prec * 100:.2f}% (How many flagged links were genuinely malicious)")
    print(f" • Recall (Malicious):    {rec * 100:.2f}% (How many malicious links were caught)")
    print(f" • F1-Score:              {f1 * 100:.2f}% (Harmonic balance)")

    print("\nConfusion Matrix:")
    print(f"                Predicted Safe    Predicted Malicious")
    print(f"  Actual Safe:        {tn:<17} {fp:<19}")
    print(f"  Actual Malicious:   {fn:<17} {tp:<19}")

    # 6. Critical Security Audit: False Negatives
    false_negatives = []
    for u, true_label, pred_label, proba in zip(valid_urls, valid_y, y_pred, y_proba):
        if true_label == 1 and pred_label == 0:
            false_negatives.append((u, proba))

    if false_negatives:
        print(f"\n⚠ SECURITY ALERT: {len(false_negatives)} Malicious URLs were MISSED (False Negatives):")
        for u, proba in false_negatives:
            print(f"  - URL: {u}")
            print(f"    Model Probabilities: Safe={proba[0]:.2f}, Malicious={proba[1]:.2f}")
    else:
        print("\n✓ Perfect Recall on this test set: 0 False Negatives (No malicious URLs were missed).")

    print("\nDetailed Classification Report:\n")
    print(classification_report(valid_y, y_pred, target_names=["LEGITIMATE", "MALICIOUS"], zero_division=0))

if __name__ == "__main__":
    target_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TEST_PATH
    evaluate(target_path)
