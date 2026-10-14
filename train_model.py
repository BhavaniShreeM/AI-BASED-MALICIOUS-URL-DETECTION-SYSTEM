"""
AI-Based Malicious URL Detection System
Machine Learning Training Pipeline using Scikit-Learn

ALGORITHM:
Random Forest Classifier (Ensemble of Decision Trees)

PIPELINE STAGES:
1. Loads cleaned & deduplicated dataset (Train and Test splits).
2. Extracts identical 16-feature vectors using feature_extractor.py.
3. Configures class weighting to handle class imbalance.
4. Trains the RandomForestClassifier with fixed random_state for 100% reproducibility.
5. Evaluates model performance on the un-seen test split (Accuracy, Precision, Recall, F1, Confusion Matrix).
6. Highlights Malicious Recall (minimizing False Negatives).
7. Serializes model to 'models/url_classifier.joblib' along with feature configuration & metadata.
8. Writes genuine evaluation metrics to 'models/evaluation_results.json'.
"""

import os
import sys
import csv
import json
import time
from typing import List, Tuple, Dict, Any

# Ensure current directory is on sys.path to import feature_extractor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import extract_url_vector, FEATURE_NAMES

# ==============================================================================
# 1. HYPERPARAMETERS & CONFIGURATION
# ==============================================================================

RANDOM_SEED = 42
TRAIN_DATA_PATH = "data/processed/train.csv"
TEST_DATA_PATH = "data/processed/test.csv"
CLEAN_DATA_PATH = "data/processed/clean_dataset.csv"
MODEL_OUTPUT_DIR = "models"

MODEL_HYPERPARAMS = {
    "n_estimators": 100,         # 100 ensemble trees
    "max_depth": 12,             # Constrain depth to prevent overfitting
    "min_samples_split": 4,      # Minimum samples required to split internal node
    "min_samples_leaf": 2,       # Minimum samples in leaf node
    "class_weight": "balanced",  # Automatically adjusts weights inversely proportional to class frequencies
    "random_state": RANDOM_SEED, # Guarantees exact reproducibility
    "n_jobs": -1                 # Use all available CPU cores
}

LABEL_ENCODING = {
    "LEGITIMATE": 0,
    "MALICIOUS": 1
}
REVERSE_LABEL_ENCODING = {v: k for k, v in LABEL_ENCODING.items()}


# ==============================================================================
# 2. DATA LOADING & FEATURE EXTRACTION
# ==============================================================================

def load_data_from_csv(csv_path: str) -> Tuple[List[str], List[int]]:
    """
    Reads a CSV file containing 'url' and 'label' columns,
    validates rows, and encodes labels to integers (0 or 1).
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset CSV not found at: {csv_path}")

    urls = []
    labels = []

    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row_idx, row in enumerate(reader, start=1):
            url = (row.get("url") or "").strip()
            raw_label = (row.get("label") or "").strip().upper()

            if not url:
                continue

            if raw_label not in LABEL_ENCODING:
                # Skip unmapped labels safely
                continue

            urls.append(url)
            labels.append(LABEL_ENCODING[raw_label])

    return urls, labels


def extract_dataset_features(urls: List[str], labels: List[int]) -> Tuple[List[List[float]], List[int], List[str]]:
    """
    Extracts 16 numerical features for each URL using feature_extractor.py.
    Returns: (X, y, valid_urls)
    """
    X = []
    y = []
    valid_urls = []

    for url, label in zip(urls, labels):
        try:
            vec = extract_url_vector(url)
            X.append(vec)
            y.append(label)
            valid_urls.append(url)
        except Exception as e:
            # Skip malformed URLs that fail validation
            continue

    return X, y, valid_urls


# ==============================================================================
# 3. TRAINING & EVALUATION PIPELINE
# ==============================================================================

def run_training_pipeline():
    """
    Executes end-to-end model training, evaluation, and artifact serialization.
    """
    print("\n" + "=" * 70)
    print("AI-BASED MALICIOUS URL DETECTION SYSTEM")
    print("Machine Learning Model Training Pipeline (Random Forest)")
    print("=" * 70)

    # Step 1: Ensure dataset files exist
    if not os.path.exists(TRAIN_DATA_PATH) or not os.path.exists(TEST_DATA_PATH):
        print(f"⚠ Processed train/test splits not found in '{TRAIN_DATA_PATH}'.")
        print("Running data preparation pipeline first...")
        raw_source = 'data/raw/dataset.csv' if os.path.exists('data/raw/dataset.csv') else 'data/raw/hackathon_training_corpus.csv'
        prep = UrlDatasetPipeline(
            raw_csv_path=raw_source,
            output_dir='data/processed'
        )
        prep.run()

    # Step 2: Load training and testing sets
    print("\nLoading dataset splits...")
    train_urls, train_labels = load_data_from_csv(TRAIN_DATA_PATH)
    test_urls, test_labels = load_data_from_csv(TEST_DATA_PATH)

    print(f"Loaded {len(train_urls)} training samples from -> {TRAIN_DATA_PATH}")
    print(f"Loaded {len(test_urls)} testing samples from  -> {TEST_DATA_PATH}")

    # Step 3: Extract features using feature_extractor module
    print("\nExtracting 16 lexical and structural features using feature_extractor.py...")
    start_feat_time = time.time()
    X_train, y_train, clean_train_urls = extract_dataset_features(train_urls, train_labels)
    X_test, y_test, clean_test_urls = extract_dataset_features(test_urls, test_labels)
    feat_extraction_duration = round(time.time() - start_feat_time, 3)

    print(f"✓ Feature extraction complete in {feat_extraction_duration}s.")
    print(f"  Training feature matrix shape: ({len(X_train)}, {len(FEATURE_NAMES)})")
    print(f"  Testing feature matrix shape:  ({len(X_test)}, {len(FEATURE_NAMES)})")

    # Verify zero data leakage between train and test
    train_set_set = set(clean_train_urls)
    test_set_set = set(clean_test_urls)
    overlap = train_set_set.intersection(test_set_set)
    if overlap:
        raise AssertionError(f"CRITICAL ERROR: Data leakage detected! {len(overlap)} URLs appear in both train and test sets.")
    print("✓ Data leakage check passed: Zero URL overlap between train and test splits.")

    # Class distribution in training set
    train_legit_count = sum(1 for y in y_train if y == 0)
    train_mal_count = sum(1 for y in y_train if y == 1)
    print(f"  Training class distribution: Legitimate={train_legit_count}, Malicious={train_mal_count}")

    # Step 4: Import Scikit-learn and train model
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import (
            accuracy_score,
            precision_score,
            recall_score,
            f1_score,
            confusion_matrix,
            classification_report
        )
        import joblib
    except ImportError as e:
        print(f"\n❌ Required package missing: {e}")
        print("Please install scikit-learn and joblib: pip install scikit-learn joblib")
        return

    print("\n" + "=" * 70)
    print("STAGE 2: TRAINING RANDOM FOREST CLASSIFIER")
    print("=" * 70)
    print(f"Initializing RandomForestClassifier with hyperparameters:")
    for k, v in MODEL_HYPERPARAMS.items():
        print(f" - {k}: {v}")

    rf_model = RandomForestClassifier(**MODEL_HYPERPARAMS)

    start_train_time = time.time()
    rf_model.fit(X_train, y_train)
    train_duration = round(time.time() - start_train_time, 3)
    print(f"✓ Random Forest model successfully trained in {train_duration}s.")

    # Step 5: Evaluate on held-out test data
    print("\n" + "=" * 70)
    print("STAGE 3: EVALUATION ON UNSEEN TEST DATA")
    print("=" * 70)

    y_pred = rf_model.predict(X_test)
    y_pred_proba = rf_model.predict_proba(X_test)

    # Compute genuine metrics
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))

    # Confusion matrix: [[True Negatives, False Positives], [False Negatives, True Positives]]
    cm = confusion_matrix(y_test, y_pred).tolist()
    tn = cm[0][0] if len(cm) > 0 and len(cm[0]) > 0 else 0
    fp = cm[0][1] if len(cm) > 0 and len(cm[0]) > 1 else 0
    fn = cm[1][0] if len(cm) > 1 and len(cm[1]) > 0 else 0
    tp = cm[1][1] if len(cm) > 1 and len(cm[1]) > 1 else 0

    class_names = ["LEGITIMATE", "MALICIOUS"]
    report_dict = classification_report(y_test, y_pred, target_names=class_names, output_dict=True, zero_division=0)
    report_text = classification_report(y_test, y_pred, target_names=class_names, zero_division=0)

    print("\nActual Test Evaluation Metrics (Generated from Real Test Data):")
    print(f" • Accuracy:           {acc * 100:.2f}%")
    print(f" • Precision (Malicious): {prec * 100:.2f}%")
    print(f" • Recall (Malicious):    {rec * 100:.2f}%  <-- Critical for threat detection")
    print(f" • F1-Score:           {f1 * 100:.2f}%")

    print("\nConfusion Matrix Breakdown:")
    print(f" • True Negatives  (Legitimate correctly marked safe):     {tn}")
    print(f" • False Positives (Legitimate falsely flagged malicious): {fp}")
    print(f" • False Negatives (Malicious MISSED as safe - dangerous): {fn}")
    print(f" • True Positives  (Malicious correctly flagged threat):   {tp}")

    print("\nDetailed Per-Class Classification Report:\n")
    print(report_text)

    # Step 6: Feature Importance Analysis
    importances = rf_model.feature_importances_
    sorted_idx = importances.argsort()[::-1]
    ranked_features = []
    print("Random Forest Gini Feature Importance Ranking:")
    for rank, idx in enumerate(sorted_idx, start=1):
        name = FEATURE_NAMES[idx]
        imp = float(importances[idx])
        ranked_features.append({"rank": rank, "feature": name, "importance": round(imp, 4)})
        bar = "█" * int(imp * 40)
        print(f" {rank:>2}. {name:<25} : {imp * 100:>5.2f}% | {bar}")

    # Step 7: Serialize Model & Save Artifacts
    print("\n" + "=" * 70)
    print("STAGE 4: SAVING MODEL & METADATA ARTIFACTS")
    print("=" * 70)

    os.makedirs(MODEL_OUTPUT_DIR, exist_ok=True)

    # 1. Save Trained Scikit-Learn Model
    model_path = os.path.join(MODEL_OUTPUT_DIR, "url_classifier.joblib")
    joblib.dump(rf_model, model_path)
    print(f"✓ Saved trained model -> {model_path}")

    # 2. Save Feature Configuration
    feature_config = {
        "feature_names": list(FEATURE_NAMES),
        "feature_count": len(FEATURE_NAMES),
        "label_encoding": LABEL_ENCODING,
        "reverse_label_encoding": REVERSE_LABEL_ENCODING,
        "extractor_module": "feature_extractor.py",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    config_path = os.path.join(MODEL_OUTPUT_DIR, "feature_config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(feature_config, f, indent=2)
    print(f"✓ Saved feature config -> {config_path}")

    # 3. Save Evaluation Results
    evaluation_results = {
        "evaluation_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "test_sample_count": len(X_test),
        "test_accuracy": round(acc, 4),
        "precision_malicious": round(prec, 4),
        "recall_malicious": round(rec, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
            "raw_matrix": cm
        },
        "classification_report": report_dict,
        "feature_importance_ranking": ranked_features
    }
    eval_path = os.path.join(MODEL_OUTPUT_DIR, "evaluation_results.json")
    with open(eval_path, "w", encoding="utf-8") as f:
        json.dump(evaluation_results, f, indent=2)
    print(f"✓ Saved evaluation results -> {eval_path}")

    # 4. Save Training Metadata (reproducibility audit)
    training_metadata = {
        "algorithm": "RandomForestClassifier",
        "library": "scikit-learn",
        "random_seed": RANDOM_SEED,
        "hyperparameters": MODEL_HYPERPARAMS,
        "dataset_splits": {
            "train_path": TRAIN_DATA_PATH,
            "train_samples": len(X_train),
            "test_path": TEST_DATA_PATH,
            "test_samples": len(X_test),
            "split_strategy": "Stratified 70/15/15 prior split"
        },
        "training_duration_seconds": train_duration,
        "feature_extraction_duration_seconds": feat_extraction_duration,
        "limitations": [
            "Trained on URL lexical/structural features without fetching web page DOM or network payloads.",
            "Cannot detect zero-day phishing hosted on compromised high-reputation domains with standard path morphology.",
            "HTTPS status reflects transport encryption, not server trustworthiness."
        ]
    }
    meta_path = os.path.join(MODEL_OUTPUT_DIR, "training_metadata.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(training_metadata, f, indent=2)
    print(f"✓ Saved training metadata -> {meta_path}")

    print("\n🎉 Training pipeline finished successfully!")
    print(f"Your model is saved and ready for Flask backend integration.")


if __name__ == "__main__":
    run_training_pipeline()
