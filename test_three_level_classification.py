"""
Unit and Integration Tests for AI-Based Malicious URL Detection System
Covers the Three-Level Risk Classification Policy (SAFE, SUSPICIOUS, MALICIOUS)
and verifies all requirements a through n:
  a. Valid HTTP URL
  b. Valid HTTPS URL
  c. Missing URL
  d. Empty URL
  e. Invalid URL
  f. Unsupported URL scheme
  g. Missing model
  h. Incompatible model features
  i. SAFE classification
  j. SUSPICIOUS classification
  k. MALICIOUS classification
  l. Structural-risk override
  m. Every supported API route
  n. Frontend API error handling
"""

import unittest
import json
import os
import joblib

import app
from app import app as flask_app, process_url_prediction, evaluate_three_class_policy
from feature_extractor import extract_url_features, extract_url_vector, validate_url, FEATURE_NAMES


class TestThreeLevelRiskClassification(unittest.TestCase):
    """
    Complete test suite for the AI-Based Malicious URL Detection System.
    Validates model integrity, feature extraction, policy thresholds, and all endpoints.
    """

    @classmethod
    def setUpClass(cls):
        cls.client = flask_app.test_client()
        cls.model_path = os.path.join(os.path.dirname(__file__), "models", "url_classifier.joblib")
        assert os.path.exists(cls.model_path), "Trained model file url_classifier.joblib must exist!"
        cls.loaded_model = joblib.load(cls.model_path)

    # --------------------------------------------------------------------------
    # a. Valid HTTP URL
    # --------------------------------------------------------------------------
    def test_a_valid_http_url(self):
        """Valid HTTP URLs must be supported and extracted correctly (uses_https == 0.0)."""
        url = "http://example.com/portal/index.html"
        is_valid, reason = validate_url(url)
        self.assertTrue(is_valid, f"Expected HTTP URL to be valid, got: {reason}")

        result = process_url_prediction(url)
        self.assertTrue(result["success"])
        self.assertEqual(result["features"]["uses_https"], 0.0)
        self.assertIn(result["category"], ["SAFE", "SUSPICIOUS", "MALICIOUS"])

    # --------------------------------------------------------------------------
    # b. Valid HTTPS URL
    # --------------------------------------------------------------------------
    def test_b_valid_https_url(self):
        """Valid HTTPS URLs must be supported and extracted correctly (uses_https == 1.0)."""
        url = "https://www.google.com/search?q=cybersecurity"
        is_valid, reason = validate_url(url)
        self.assertTrue(is_valid, f"Expected HTTPS URL to be valid, got: {reason}")

        result = process_url_prediction(url)
        self.assertTrue(result["success"])
        self.assertEqual(result["features"]["uses_https"], 1.0)
        self.assertIn(result["category"], ["SAFE", "SUSPICIOUS", "MALICIOUS"])

    # --------------------------------------------------------------------------
    # c. Missing URL
    # --------------------------------------------------------------------------
    def test_c_missing_url(self):
        """Requests with missing 'url' key or None must return HTTP 400 Bad Request."""
        # API test with empty JSON payload
        resp = self.client.post("/api/scan", json={})
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertIn("Missing 'url' parameter", data["error"])

        # Core function test with None
        with self.assertRaises(ValueError):
            process_url_prediction(None)

    # --------------------------------------------------------------------------
    # d. Empty URL
    # --------------------------------------------------------------------------
    def test_d_empty_url(self):
        """Empty or whitespace-only URLs must return HTTP 400 Bad Request."""
        empty_cases = ["", "   ", "\t\n  "]
        for case in empty_cases:
            resp = self.client.post("/api/scan", json={"url": case})
            self.assertEqual(resp.status_code, 400)
            data = resp.get_json()
            self.assertFalse(data["success"])

            with self.assertRaises(ValueError):
                process_url_prediction(case)

    # --------------------------------------------------------------------------
    # e. Invalid URL
    # --------------------------------------------------------------------------
    def test_e_invalid_url(self):
        """Malformed URLs (illegal whitespace, missing hostname structure, too short) must return HTTP 400."""
        invalid_cases = [
            "invalid_domain_without_dot",
            "http://invalid whitespace in url.com",
            "ab",
            "http://",
        ]
        for bad_url in invalid_cases:
            with self.subTest(bad_url=bad_url):
                resp = self.client.post("/api/scan", json={"url": bad_url})
                self.assertEqual(resp.status_code, 400)
                data = resp.get_json()
                self.assertFalse(data["success"])
                self.assertEqual(data["status"], "invalid_input")

                with self.assertRaises(ValueError):
                    process_url_prediction(bad_url)

    # --------------------------------------------------------------------------
    # f. Unsupported URL scheme
    # --------------------------------------------------------------------------
    def test_f_unsupported_url_scheme(self):
        """Unsupported URL schemes (ftp://, javascript:, file://, mailto:) must return HTTP 400."""
        unsupported_schemes = [
            "ftp://files.example.com/download.zip",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "mailto:admin@example.com",
            "ssh://root@192.168.1.1",
        ]
        for scheme_url in unsupported_schemes:
            with self.subTest(scheme_url=scheme_url):
                resp = self.client.post("/api/scan", json={"url": scheme_url})
                self.assertEqual(resp.status_code, 400)
                data = resp.get_json()
                self.assertFalse(data["success"])
                self.assertIn("Unsupported URL scheme", data["error"])

    # --------------------------------------------------------------------------
    # g. Missing model
    # --------------------------------------------------------------------------
    def test_g_missing_model(self):
        """When ML model is unavailable, API must return HTTP 503 with clear diagnostic error."""
        original_model = app.model
        orig_load = app.load_model
        try:
            app.load_model = lambda: False
            app.model = None
            resp = self.client.post("/api/scan", json={"url": "https://example.com"})
            self.assertEqual(resp.status_code, 503)
            data = resp.get_json()
            self.assertFalse(data["success"])
            self.assertEqual(data["status"], "model_missing")
            self.assertIn("Machine Learning model is not available", data["error"])
        finally:
            app.load_model = orig_load
            app.model = original_model

    # --------------------------------------------------------------------------
    # h. Incompatible model features
    # --------------------------------------------------------------------------
    def test_h_incompatible_model_features(self):
        """When model has mismatched feature expectations, API must raise diagnostic error."""
        class MockIncompatibleModel:
            n_features_in_ = 10  # Mismatched from 16
            def predict_proba(self, X):
                return [[0.5, 0.5]]

        original_model = app.model
        try:
            app.model = MockIncompatibleModel()
            resp = self.client.post("/api/scan", json={"url": "https://example.com"})
            self.assertIn(resp.status_code, [500, 503])
            data = resp.get_json()
            self.assertFalse(data["success"])
            self.assertIn("feature mismatch", data["error"].lower())
        finally:
            app.model = original_model

    # --------------------------------------------------------------------------
    # i. SAFE classification
    # --------------------------------------------------------------------------
    def test_i_safe_classification(self):
        """Legitimate URL with probability < 0.35 and no structural overrides yields SAFE category."""
        url = "https://en.wikipedia.org/wiki/Computer_security"
        result = process_url_prediction(url)
        self.assertEqual(result["category"], "SAFE")
        self.assertLess(result["malicious_probability"], app.THRESHOLD_SAFE)
        self.assertIn("explanation", result)
        # Verify explanation clearly states lexical analysis does not guarantee site trustworthiness
        self.assertTrue(
            "URL features only" in result["explanation"] or
            "cannot guarantee" in result["explanation"]
        )

    # --------------------------------------------------------------------------
    # j. SUSPICIOUS classification
    # --------------------------------------------------------------------------
    def test_j_suspicious_classification(self):
        """Probability from 0.35 to < 0.70 correctly categorizes as SUSPICIOUS."""
        # Test directly via policy evaluator
        category, conf, exp, meta = evaluate_three_class_policy(
            prob_malicious=0.52,
            prob_legitimate=0.48,
            features={"uses_https": 1.0}
        )
        self.assertEqual(category, "SUSPICIOUS")
        self.assertEqual(meta["applied_rule"], "model_probability_borderline (0.35 - 0.70)")
        self.assertIn("borderline", exp.lower())

    # --------------------------------------------------------------------------
    # k. MALICIOUS classification
    # --------------------------------------------------------------------------
    def test_k_malicious_classification(self):
        """Probability at or above 0.70 yields MALICIOUS category with threat indicators."""
        url = "http://192.168.1.104/paypal.com/login.php"
        result = process_url_prediction(url)
        self.assertEqual(result["category"], "MALICIOUS")
        self.assertGreaterEqual(result["malicious_probability"], app.THRESHOLD_SUSPICIOUS)
        self.assertIn("risk_factors", result)
        self.assertTrue(len(result["risk_factors"]) > 0)
        self.assertIn("recommendations", result)
        self.assertTrue(any("DO NOT" in rec for rec in result["recommendations"]))

    # --------------------------------------------------------------------------
    # l. Structural-risk override
    # --------------------------------------------------------------------------
    def test_l_structural_risk_override(self):
        """
        Structural-risk override: Even if base malicious probability is < 0.35,
        high-risk evasion signatures (raw IPv4 host or '@' credential confusion)
        must override classification to SUSPICIOUS.
        """
        # Case 1: Credential confusion with @ symbol
        res_at = process_url_prediction("https://paypal.com@verify-account-portal.xyz/login")
        self.assertIn(res_at["category"], ["SUSPICIOUS", "MALICIOUS"])
        self.assertTrue(res_at["policy_metadata"]["structural_overrides_triggered"])

        # Case 2: Direct IPv4 with HTTPS
        category, conf, exp, meta = evaluate_three_class_policy(
            prob_malicious=0.15,  # Statistically low
            prob_legitimate=0.85,
            features={"is_ipv4": 1.0, "uses_https": 1.0}
        )
        self.assertEqual(category, "SUSPICIOUS")
        self.assertTrue(meta["structural_overrides_triggered"])
        self.assertEqual(meta["applied_rule"], "cautious_structural_override_to_suspicious")

    # --------------------------------------------------------------------------
    # m. Every supported API route
    # --------------------------------------------------------------------------
    def test_m_every_supported_api_route(self):
        """All supported API scan routes (/api/scan, /scan, /api/predict, /predict, /api/analyze) return consistent schema."""
        supported_routes = [
            "/api/scan",
            "/scan",
            "/api/predict",
            "/predict",
            "/api/analyze",
        ]
        test_payload = {"url": "https://www.google.com"}

        for route in supported_routes:
            with self.subTest(route=route):
                resp = self.client.post(route, json=test_payload)
                self.assertEqual(resp.status_code, 200, f"Route {route} failed with {resp.status_code}")
                data = resp.get_json()
                self.assertTrue(data["success"])
                self.assertIn("category", data)
                self.assertIn(data["category"], ["SAFE", "SUSPICIOUS", "MALICIOUS"])
                self.assertIn("confidence_percentage", data)
                self.assertIn("explanation", data)
                self.assertIn("decision_thresholds", data)
                self.assertIn("ensemble_consensus", data)

    # --------------------------------------------------------------------------
    # n. Frontend API error handling
    # --------------------------------------------------------------------------
    def test_n_frontend_api_error_handling(self):
        """
        Frontend integration verification:
        Ensures error responses contain structured fields ('success': False, 'error', 'status')
        so that src/App.tsx and standalone_frontend/script.js handle them cleanly without crashing.
        """
        # Validation error (400)
        res400 = self.client.post("/api/scan", json={"url": "bad url with spaces"})
        self.assertEqual(res400.status_code, 400)
        d400 = res400.get_json()
        self.assertFalse(d400["success"])
        self.assertIn("error", d400)
        self.assertEqual(d400["status"], "invalid_input")

        # Unsupported scheme error (400)
        res_scheme = self.client.post("/api/scan", json={"url": "ftp://myfiles.org"})
        self.assertEqual(res_scheme.status_code, 400)
        d_scheme = res_scheme.get_json()
        self.assertFalse(d_scheme["success"])
        self.assertIn("Unsupported URL scheme", d_scheme["error"])

        # Health endpoint error-free check
        res_health = self.client.get("/api/health")
        self.assertEqual(res_health.status_code, 200)
        d_health = res_health.get_json()
        self.assertTrue(d_health["model_loaded"])
        self.assertEqual(d_health["categories"], ["SAFE", "SUSPICIOUS", "MALICIOUS"])


if __name__ == "__main__":
    unittest.main()
