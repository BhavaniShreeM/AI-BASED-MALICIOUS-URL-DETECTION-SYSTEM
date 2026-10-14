"""
AI-Based Malicious URL Detection System
Flask Backend API Service
Author: Hackathon Engineering Pipeline

OBJECTIVE:
Provides real-time machine learning prediction endpoints for detecting malicious URLs.
Integrates with the trained Scikit-learn RandomForestClassifier model.

ENDPOINTS:
- GET  /                     : Serves the standalone HTML/CSS/JS frontend
- GET  /api/health           : Health check and model status
- POST /api/predict          : Predicts URL risk category (SAFE, SUSPICIOUS, MALICIOUS)
- POST /api/analyze          : Frontend analysis endpoint with full threat diagnostics
- POST /predict              : Alternative REST prediction endpoint
"""

import os
import sys
import json
import logging
from typing import Dict, Any, List

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

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("malicious_url_api")

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

# Transparent Decision Thresholds
THRESHOLD_SAFE = 0.35       # Probabilities below 35% are classified as SAFE
THRESHOLD_SUSPICIOUS = 0.70 # Probabilities between 35% and 70% are classified as SUSPICIOUS
                            # Probabilities at or above 70% are classified as MALICIOUS


def load_model():
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

    if os.path.exists(FEATURE_CONFIG_PATH):
        try:
            with open(FEATURE_CONFIG_PATH, "r", encoding="utf-8") as f:
                feature_config = json.load(f)
            logger.info("✓ Feature configuration loaded successfully.")
        except Exception as e:
            logger.error("Failed to load feature configuration: %s", e)


# Load model immediately on module import
load_model()


def generate_risk_factors(features: Dict[str, float]) -> List[str]:
    """
    Translates raw numerical features into clear, human-readable risk indicators
    for beginners and hackathon judges.
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


def generate_recommendations(verdict: str) -> List[str]:
    """Generates context-aware cybersecurity recommendations for the user."""
    if verdict == "MALICIOUS":
        return [
            "DO NOT click, open, or share this URL under any circumstances.",
            "Do not input passwords, bank accounts, or personal information on this destination.",
            "Report this link to your security administrator or public phishing databases (PhishTank, Google Safe Browsing).",
            "If already visited, immediately change affected credentials and scan your system with anti-malware."
        ]
    elif verdict == "SUSPICIOUS":
        return [
            "Exercise extreme caution before opening this link.",
            "Carefully check the root domain name in your browser address bar to verify authentic branding.",
            "Do not download attachments, run executables, or enter sensitive information.",
            "Verify the request through an independent secondary communication channel (e.g., phone call or official app)."
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
    3. Calculates model probabilities
    4. Categorizes into SAFE, SUSPICIOUS, or MALICIOUS
    5. Returns transparent indicators and advice
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("URL cannot be empty. Please provide a valid URL string.")

    cleaned_url = raw_url.strip()

    # Step 1: Input Format Validation
    is_valid, reason = validate_url(cleaned_url)
    if not is_valid:
        raise ValueError(f"Invalid URL format: {reason}")

    # Step 2: Feature Extraction (identical to training)
    features_dict = extract_url_features(cleaned_url)
    features_vector = extract_url_vector(cleaned_url)

    # Step 3: Model Inference
    global model
    if model is None:
        load_model()

    if model is None:
        raise RuntimeError("Machine Learning model is not available. Please run 'python train_model.py' first.")

    # Calculate probabilities: [prob_legitimate, prob_malicious]
    probabilities = model.predict_proba([features_vector])[0]
    prob_legitimate = float(probabilities[0])
    prob_malicious = float(probabilities[1])

    # Step 4: Map probabilities into 3 discrete categories using transparent thresholds
    if prob_malicious < THRESHOLD_SAFE:
        verdict = "SAFE"
        confidence = round(prob_legitimate * 100, 1)
    elif prob_malicious < THRESHOLD_SUSPICIOUS:
        verdict = "SUSPICIOUS"
        confidence = round(max(prob_malicious, prob_legitimate) * 100, 1)
    else:
        verdict = "MALICIOUS"
        confidence = round(prob_malicious * 100, 1)

    # Step 5: Explainable risk factors and recommendations
    risk_factors = generate_risk_factors(features_dict)
    recommendations = generate_recommendations(verdict)

    # Count voting trees in ensemble if available
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
        "verdict": verdict,
        "category": verdict,
        "confidence_percentage": confidence,
        "malicious_probability": round(prob_malicious, 4),
        "legitimate_probability": round(prob_legitimate, 4),
        "decision_thresholds": {
            "safe": f"< {THRESHOLD_SAFE}",
            "suspicious": f"{THRESHOLD_SAFE} - {THRESHOLD_SUSPICIOUS}",
            "malicious": f">= {THRESHOLD_SUSPICIOUS}"
        },
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
            "model_path": MODEL_PATH
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
        "endpoints": ["/api/predict", "/api/analyze", "/api/health"]
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
        "features_supported": len(FEATURE_NAMES),
        "thresholds": {
            "safe_max": THRESHOLD_SAFE,
            "suspicious_max": THRESHOLD_SUSPICIOUS,
            "malicious_min": THRESHOLD_SUSPICIOUS
        }
    }), 200


@app.route("/api/predict", methods=["POST"])
@app.route("/predict", methods=["POST"])
@app.route("/api/analyze", methods=["POST"])
def predict():
    """
    Main prediction endpoint.
    Accepts JSON payload: {"url": "https://example.com"}
    or Form Data: url=https://example.com
    """
    try:
        # Extract URL from JSON body or Form
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
        logger.warning("Validation error on URL '%s': %s", raw_url if 'raw_url' in locals() else None, val_err)
        return jsonify({
            "success": False,
            "error": str(val_err),
            "status": "invalid_input"
        }), 400

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
    print(f"Prediction endpoints: http://127.0.0.1:{port}/api/predict")
    print(f"                      http://127.0.0.1:{port}/api/analyze")
    print(f"                      http://127.0.0.1:{port}/predict")
    print(f"Health check:         http://127.0.0.1:{port}/api/health")
    print("=" * 70)
    app.run(host="0.0.0.0", port=port, debug=False)
