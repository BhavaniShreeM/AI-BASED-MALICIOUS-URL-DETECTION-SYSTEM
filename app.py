"""
AI-Based Malicious URL Detection System
Flask Backend API Service
Author: Hackathon Engineering Pipeline

OBJECTIVE:
Provides real-time machine learning prediction endpoints for detecting malicious URLs.
Uses a trained Scikit-learn RandomForestClassifier model with a validated 3-level
risk classification policy (SAFE, SUSPICIOUS, MALICIOUS).

ENDPOINTS:
- GET  /                     : Serves the standalone HTML/CSS/JS frontend
- GET  /api/health           : Health check and model status
- POST /api/scan             : Primary scan endpoint returning 3-level classification
- POST /api/predict          : Standard ML prediction endpoint
- POST /api/analyze          : Comprehensive frontend threat analysis endpoint
- POST /scan                 : Alias for /api/scan
- POST /predict              : Alias for /api/predict
"""

import os
import sys
import json
import logging
from typing import Dict, Any, List, Optional, Tuple

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import joblib

# Ensure current directory is accessible for local imports
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from feature_extractor import (
    extract_url_features,
    extract_url_vector,
    validate_url,
    FEATURE_NAMES
)

# Configure logging cleanly to stdout
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout
)
logger = logging.getLogger("malicious_url_api")

# Silence Werkzeug request access logs so they don't flood stderr
werkzeug_logger = logging.getLogger("werkzeug")
werkzeug_logger.setLevel(logging.ERROR)

# Initialize Flask application
STATIC_FRONTEND_DIR = os.path.join(BASE_DIR, "standalone_frontend")
app = Flask(__name__, static_folder=STATIC_FRONTEND_DIR)
CORS(app)  # Enable Cross-Origin Resource Sharing for all origins

# Model & Configuration Paths
MODEL_PATH = os.path.join(BASE_DIR, "models", "url_classifier.joblib")
FEATURE_CONFIG_PATH = os.path.join(BASE_DIR, "models", "feature_config.json")

# Global model cache
model = None
feature_config = {}

# ==============================================================================
# THREE-LEVEL RISK CLASSIFICATION POLICY
# ==============================================================================
# The underlying Random Forest model outputs probability of being malicious [0.0 - 1.0].
# Validation dataset empirical findings:
#   - Confirmed Legitimate URLs: prob_malicious <= 0.19
#   - Confirmed Malicious URLs:  prob_malicious >= 0.80
#
# Policy Thresholds:
#   - prob_malicious < 0.35: Low statistical probability.
#     -> Categorized as SAFE, UNLESS high-risk structural evasion indicators are present.
#   - 0.35 <= prob_malicious < 0.70: Borderline / uncertain probability.
#     -> Categorized as SUSPICIOUS. Forest trees are divided or patterns are mixed.
#   - prob_malicious >= 0.70: High probability.
#     -> Categorized as MALICIOUS. Strong consensus across forest estimators.
#
# Critical Safety Policy Rule:
#   "Do not label a URL SAFE simply because it uses HTTPS. Treat uncertain results cautiously."
#   If a URL has prob_malicious < 0.35 but contains critical structural red flags
#   (raw IPv4 host, '@' credential confusion, multiple phishing keywords, or excessive subdomains),
#   the classification is cautiously upgraded to SUSPICIOUS with an explicit override note.
# ==============================================================================
THRESHOLD_SAFE = 0.35
THRESHOLD_SUSPICIOUS = 0.70


def load_model() -> bool:
    """Loads the trained Random Forest model and feature configuration into memory."""
    global model, feature_config
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            logger.info("✓ Trained RandomForest model loaded successfully from %s", MODEL_PATH)
        except Exception as e:
            logger.error("Failed to load model from %s: %s", MODEL_PATH, e)
            model = None
    else:
        logger.warning("Model file not found at %s. Please run train_model.py first.", MODEL_PATH)
        model = None

    if os.path.exists(FEATURE_CONFIG_PATH):
        try:
            with open(FEATURE_CONFIG_PATH, "r", encoding="utf-8") as f:
                feature_config = json.load(f)
            logger.info("✓ Feature configuration loaded successfully.")
        except Exception as e:
            logger.error("Failed to load feature configuration: %s", e)

    return model is not None


# Load model on startup
load_model()


def evaluate_three_class_policy(
    prob_malicious: float,
    prob_legitimate: float,
    features: Dict[str, float]
) -> Tuple[str, float, str, Dict[str, Any]]:
    """
    Evaluates model probabilities and structural features against the 3-level policy.

    Returns:
        (category, confidence_percentage, explanation, policy_metadata)
    """
    override_reasons = []

    # Check for high-risk structural evasion red flags
    if features.get("is_ipv4", 0.0) == 1.0 or features.get("has_ip_in_url", 0.0) == 1.0:
        override_reasons.append("Direct IPv4 address used as host instead of a legitimate domain.")
    if features.get("num_at_symbols", 0.0) > 0:
        override_reasons.append("Credential confusion '@' symbol present in URL.")
    if features.get("num_suspicious_keywords", 0.0) >= 2:
        keywords_count = int(features.get("num_suspicious_keywords", 0.0))
        override_reasons.append(f"Multiple sensitive phishing keywords detected ({keywords_count}).")
    if features.get("num_subdomains", 0.0) >= 4:
        subdomains = int(features.get("num_subdomains", 0.0))
        override_reasons.append(f"Deep subdomain nesting ({subdomains} levels) characteristic of evasion.")

    # 1. Base probability categorization
    if prob_malicious >= THRESHOLD_SUSPICIOUS:
        category = "MALICIOUS"
        confidence = round(prob_malicious * 100, 1)
        explanation = (
            f"The Random Forest model identified strong malicious characteristics with "
            f"{confidence}% confidence (malicious probability: {prob_malicious:.4f}). "
            f"Multiple threat features align with known phishing, scam, or malware distribution links. "
            f"Note: This assessment is based on URL lexical and structural patterns."
        )
        policy_rule = "model_probability_malicious (>= 0.70)"

    elif prob_malicious >= THRESHOLD_SAFE:
        category = "SUSPICIOUS"
        confidence = round(max(prob_malicious, prob_legitimate) * 100, 1)
        explanation = (
            f"The URL falls in the uncertain / borderline probability range "
            f"(malicious probability: {prob_malicious:.4f}). Decision trees in the forest "
            f"are divided or the link exhibits mixed legitimate and suspicious lexical traits. "
            f"Exercise caution before interacting with this destination."
        )
        policy_rule = "model_probability_borderline (0.35 - 0.70)"

    else:
        # Base probability is under 0.35. Check for structural override.
        if override_reasons:
            category = "SUSPICIOUS"
            confidence = round(max(prob_malicious, 0.65) * 100, 1)
            reasons_summary = "; ".join(override_reasons)
            explanation = (
                f"Statistical feature probability was low ({prob_malicious:.4f}), but cautious policy override "
                f"classified this URL as SUSPICIOUS due to high-risk structural indicator(s): {reasons_summary}. "
                f"HTTPS transport encryption alone does not guarantee a website is safe."
            )
            policy_rule = "cautious_structural_override_to_suspicious"
        else:
            category = "SAFE"
            confidence = round(prob_legitimate * 100, 1)
            explanation = (
                f"The URL exhibits standard domain hierarchy and lexical patterns with "
                f"{confidence}% confidence (malicious probability: {prob_malicious:.4f}). "
                f"No anomalous phishing signatures or structural evasions were detected. "
                f"Note: This system analyses URL features only and cannot guarantee server trustworthiness."
            )
            policy_rule = "model_probability_safe (< 0.35)"

    policy_metadata = {
        "applied_rule": policy_rule,
        "structural_overrides_triggered": len(override_reasons) > 0,
        "override_details": override_reasons,
        "thresholds": {
            "safe_max": THRESHOLD_SAFE,
            "suspicious_min": THRESHOLD_SAFE,
            "suspicious_max": THRESHOLD_SUSPICIOUS,
            "malicious_min": THRESHOLD_SUSPICIOUS
        }
    }

    return category, confidence, explanation, policy_metadata


def generate_risk_factors(features: Dict[str, float]) -> List[str]:
    """
    Translates raw numerical features into clear, human-readable risk indicators.
    """
    factors = []

    # 1. IP Address usage
    if features.get("is_ipv4", 0.0) == 1.0 or features.get("has_ip_in_url", 0.0) == 1.0:
        factors.append("Direct IPv4 address used instead of a legitimate registered domain name.")

    # 2. '@' Symbol trick
    if features.get("num_at_symbols", 0.0) > 0:
        factors.append("Contains '@' symbol: Often used in phishing to confuse the browser and hide true destination.")

    # 3. Excessive URL length
    length = features.get("url_length", 0.0)
    if length > 75:
        factors.append(f"Unusually long URL ({int(length)} characters): Commonly used to hide payloads or tracking strings.")

    # 4. HTTPS protocol missing
    if features.get("uses_https", 1.0) == 0.0:
        factors.append("Missing HTTPS encryption: Link uses unencrypted HTTP communication.")

    # 5. Suspicious security / phishing keywords
    keywords_count = features.get("num_suspicious_keywords", 0.0)
    if keywords_count > 0:
        factors.append(f"Contains {int(keywords_count)} sensitive keyword(s) frequently targeted in phishing attacks.")

    # 6. High subdomain depth
    subdomains = features.get("num_subdomains", 0.0)
    if subdomains >= 3:
        factors.append(f"Deep subdomain nesting ({int(subdomains)} levels): Characteristic of disposable phishing subdomains.")

    # 7. Excessive hyphens
    hyphens = features.get("num_hyphens", 0.0)
    if hyphens >= 3:
        factors.append(f"Excessive hyphens ({int(hyphens)}): Often seen in brand typosquatting attempts.")

    # 8. High digit count
    digits = features.get("num_digits", 0.0)
    if digits >= 8:
        factors.append(f"High numeric digit density ({int(digits)} digits) in hostname or path.")

    # 9. Percent-encoded characters
    percent = features.get("num_percent_encoded", 0.0)
    if percent >= 2:
        factors.append(f"Contains {int(percent)} percent-encoded (%XX) sequences to obscure target destination.")

    # 10. Long hostname
    host_len = features.get("hostname_length", 0.0)
    if host_len > 30:
        factors.append(f"Very long hostname ({int(host_len)} characters) mimicking known corporate brands.")

    if not factors:
        factors.append("No typical malicious lexical patterns or anomalous structural features detected.")

    return factors


def generate_recommendations(category: str) -> List[str]:
    """Generates context-aware cybersecurity safety advice for the user."""
    if category == "MALICIOUS":
        return [
            "DO NOT click, open, or share this URL under any circumstances.",
            "Do not input passwords, financial credentials, or personal information on this destination.",
            "Report this link to your security team or public antiphishing registries (PhishTank, Google Safe Browsing).",
            "If already visited, immediately change affected credentials and run an anti-malware scan."
        ]
    elif category == "SUSPICIOUS":
        return [
            "Exercise extreme caution before opening this link.",
            "Carefully inspect the root domain name in your browser address bar to verify authentic branding.",
            "Do not download attachments, run executables, or enter sensitive information.",
            "Verify the request through an independent secondary communication channel (e.g., official phone number or app)."
        ]
    else:  # SAFE
        return [
            "URL appears legitimate according to the Random Forest lexical feature classifier.",
            "Always inspect the address bar for valid SSL/TLS certificates before submitting personal data.",
            "Remember that even legitimate websites can occasionally be compromised by attackers."
        ]


def process_url_prediction(raw_url: str) -> Dict[str, Any]:
    """
    Core prediction engine:
    1. Validates URL format
    2. Extracts 16 features consistently with training pipeline
    3. Calculates model probabilities from the trained Random Forest
    4. Categorizes into SAFE, SUSPICIOUS, or MALICIOUS using validated policy
    5. Returns transparent indicators, explanation, and advice
    """
    if raw_url is None:
        raise ValueError("URL cannot be None. Please provide a valid URL string.")

    if not isinstance(raw_url, str):
        raise ValueError(f"Expected string input, received {type(raw_url).__name__}.")

    cleaned_url = raw_url.strip()
    if not cleaned_url:
        raise ValueError("URL cannot be empty. Please provide a website URL to scan.")

    # Step 1: Input Format Validation
    is_valid, reason = validate_url(cleaned_url)
    if not is_valid:
        raise ValueError(f"Invalid URL format: {reason}")

    # Step 2: Feature Extraction (identical to training pipeline)
    features_dict = extract_url_features(cleaned_url)
    features_vector = extract_url_vector(cleaned_url)

    # Step 3: Model Inference
    global model
    if model is None:
        loaded = load_model()
        if not loaded or model is None:
            raise RuntimeError("Machine Learning model is not available. Please run 'python train_model.py' first.")

    # Model and feature consistency check
    expected_features = len(FEATURE_NAMES)
    if hasattr(model, "n_features_in_") and model.n_features_in_ != expected_features:
        raise RuntimeError(
            f"Model feature mismatch: model expects {model.n_features_in_} features, "
            f"but feature extractor produced {expected_features} features."
        )

    # Calculate probabilities if supported, or handle discrete models without inventing fake probabilities
    has_predict_proba = hasattr(model, "predict_proba")
    if has_predict_proba:
        probabilities = model.predict_proba([features_vector])[0]
        prob_legitimate = float(probabilities[0])
        prob_malicious = float(probabilities[1])
    else:
        discrete_pred = int(model.predict([features_vector])[0])
        prob_malicious = 1.0 if discrete_pred == 1 else 0.0
        prob_legitimate = 1.0 - prob_malicious

    # Step 4: Map probabilities and features into 3 discrete categories using documented policy
    category, confidence, explanation, policy_metadata = evaluate_three_class_policy(
        prob_malicious=prob_malicious,
        prob_legitimate=prob_legitimate,
        features=features_dict
    )

    # Step 5: Risk factors and recommendations
    risk_factors = generate_risk_factors(features_dict)
    recommendations = generate_recommendations(category)

    # Count voting trees in ensemble
    trees_voting = {"legitimate": 0, "malicious": 0}
    if hasattr(model, "estimators_"):
        for tree in model.estimators_:
            tree_pred = tree.predict([features_vector])[0]
            if tree_pred == 1:
                trees_voting["malicious"] += 1
            else:
                trees_voting["legitimate"] += 1

    return {
        "success": True,
        "url": cleaned_url,
        "category": category,
        "verdict": category,  # Backward compatibility
        "confidence_percentage": confidence,
        "malicious_probability": round(prob_malicious, 4),
        "legitimate_probability": round(prob_legitimate, 4),
        "explanation": explanation,
        "decision_thresholds": {
            "safe": f"< {THRESHOLD_SAFE}",
            "suspicious": f"{THRESHOLD_SAFE} - {THRESHOLD_SUSPICIOUS} (or high-risk structural red flags)",
            "malicious": f">= {THRESHOLD_SUSPICIOUS}"
        },
        "policy_metadata": policy_metadata,
        "features": features_dict,
        "feature_names": FEATURE_NAMES,
        "risk_factors": risk_factors,
        "recommendations": recommendations,
        "ensemble_consensus": {
            "total_trees": len(getattr(model, "estimators_", [])),
            "trees_voting_malicious": trees_voting["malicious"],
            "trees_voting_legitimate": trees_voting["legitimate"]
        },
        "model_metadata": {
            "algorithm": "RandomForestClassifier",
            "feature_count": len(FEATURE_NAMES),
            "model_path": MODEL_PATH,
            "trained": True,
            "predict_proba_supported": has_predict_proba
        }
    }


# ==============================================================================
# ROUTE DEFINITIONS
# ==============================================================================

@app.route("/", methods=["GET"])
def index():
    """Serves the standalone HTML frontend index.html."""
    if os.path.exists(os.path.join(STATIC_FRONTEND_DIR, "index.html")):
        return send_from_directory(STATIC_FRONTEND_DIR, "index.html")
    return jsonify({
        "service": "AI-Based Malicious URL Detection System",
        "status": "online",
        "endpoints": ["/api/scan", "/api/predict", "/api/analyze", "/api/health"]
    })


@app.route("/<path:filename>", methods=["GET"])
def static_files(filename):
    """Serves static assets (css, js) for the standalone frontend."""
    if os.path.exists(os.path.join(STATIC_FRONTEND_DIR, filename)):
        return send_from_directory(STATIC_FRONTEND_DIR, filename)
    return jsonify({"error": "File not found"}), 404


@app.route("/api/health", methods=["GET"])
@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint reporting API and ML model availability."""
    global model
    return jsonify({
        "status": "healthy",
        "service": "AI-Based Malicious URL Detection API",
        "model_loaded": model is not None,
        "categories": ["SAFE", "SUSPICIOUS", "MALICIOUS"],
        "features_supported": len(FEATURE_NAMES),
        "thresholds": {
            "safe_max": THRESHOLD_SAFE,
            "suspicious_max": THRESHOLD_SUSPICIOUS,
            "malicious_min": THRESHOLD_SUSPICIOUS
        }
    }), 200


@app.route("/api/scan", methods=["POST"])
@app.route("/scan", methods=["POST"])
@app.route("/api/predict", methods=["POST"])
@app.route("/predict", methods=["POST"])
@app.route("/api/analyze", methods=["POST"])
def scan_endpoint():
    """
    Main scan/prediction endpoint.
    Accepts JSON payload: {"url": "https://example.com"}
    or Form Data: url=https://example.com
    """
    try:
        data = request.get_json(silent=True) or {}
        raw_url = data.get("url") or request.form.get("url")

        if not raw_url:
            return jsonify({
                "success": False,
                "error": "Missing 'url' parameter. Please provide a URL in the request body.",
                "example": {"url": "https://example.com"}
            }), 400

        result = process_url_prediction(raw_url)
        return jsonify(result), 200

    except ValueError as val_err:
        logger.info("Validation rejected for URL '%s': %s", raw_url if 'raw_url' in locals() else None, val_err)
        return jsonify({
            "success": False,
            "error": str(val_err),
            "status": "invalid_input"
        }), 400

    except RuntimeError as r_err:
        logger.error("Model unavailable error: %s", r_err)
        return jsonify({
            "success": False,
            "error": str(r_err),
            "status": "model_missing"
        }), 503

    except Exception as err:
        logger.error("Internal prediction error: %s", err, exc_info=True)
        return jsonify({
            "success": False,
            "error": f"Prediction failed: {str(err)}",
            "status": "server_error"
        }), 500


if __name__ == "__main__":
    port = int(os.environ.get("FLASK_PORT", 5000))
    print("=" * 70)
    print("AI-BASED MALICIOUS URL DETECTION SYSTEM")
    print(f"Starting Flask API Server on port {port}...")
    print(f"Primary scan endpoint: http://127.0.0.1:{port}/api/scan")
    print(f"Prediction endpoints:  http://127.0.0.1:{port}/api/predict")
    print(f"                       http://127.0.0.1:{port}/api/analyze")
    print(f"Health check:          http://127.0.0.1:{port}/api/health")
    print("=" * 70)
    app.run(host="0.0.0.0", port=port, debug=False)
