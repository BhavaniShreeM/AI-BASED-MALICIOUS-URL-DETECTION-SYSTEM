"""
Unit Tests for URL Feature Extractor Module
Author: Hackathon Engineering Pipeline

Executes comprehensive tests across:
1. Standard legitimate URLs
2. Malicious and phishing patterns (IP addresses, '@' credential tokens, keyword stacking)
3. Subdomain depth and path morphology
4. Percent-encoding detection
5. HTTPS / HTTP protocol signaling
6. Bare and unusual URL formats
7. Malformed, empty, and invalid inputs
8. Strict feature vector dimension and ordering integrity
"""

import unittest
from feature_extractor import (
    UrlFeatureExtractor,
    extract_url_features,
    extract_url_vector,
    get_feature_names,
    validate_url,
    FEATURE_NAMES
)

class TestUrlFeatureExtractor(unittest.TestCase):

    def test_feature_names_integrity(self):
        """Verifies that FEATURE_NAMES has exactly 16 defined features in consistent order."""
        names = get_feature_names()
        self.assertEqual(len(names), 16)
        self.assertEqual(names[0], "url_length")
        self.assertEqual(names[1], "hostname_length")
        self.assertEqual(names[8], "is_ipv4")
        self.assertEqual(names[9], "uses_https")
        self.assertEqual(names[14], "num_at_symbols")
        self.assertEqual(names[15], "num_percent_encoded")

    def test_legitimate_url_features(self):
        """Tests standard legitimate URL features."""
        url = "https://www.google.com/search?q=machine+learning"
        feats = extract_url_features(url)
        vec = extract_url_vector(url)

        # Check vector length and alignment
        self.assertEqual(len(vec), 16)
        self.assertEqual(feats["url_length"], len(url))
        self.assertEqual(feats["hostname_length"], len("www.google.com"))
        self.assertEqual(feats["uses_https"], 1.0)
        self.assertEqual(feats["is_ipv4"], 0.0)
        self.assertEqual(feats["has_ip_in_url"], 0.0)
        self.assertEqual(feats["num_at_symbols"], 0.0)
        self.assertEqual(feats["num_subdomains"], 1.0)  # 'www'
        self.assertEqual(feats["num_path_segments"], 1.0)  # ['search']
        self.assertEqual(feats["query_length"], len("q=machine+learning"))

    def test_raw_ipv4_host_detection(self):
        """Tests detection of direct IPv4 address as host."""
        url = "http://192.168.1.104/paypal.com/webscr"
        feats = extract_url_features(url)

        self.assertEqual(feats["is_ipv4"], 1.0)
        self.assertEqual(feats["has_ip_in_url"], 1.0)
        self.assertEqual(feats["hostname_length"], len("192.168.1.104"))
        self.assertEqual(feats["uses_https"], 0.0)
        self.assertEqual(feats["num_subdomains"], 0.0)  # IP addresses do not have subdomains
        self.assertEqual(feats["num_dots"], 4.0)  # 3 dots in IP + 1 dot in 'paypal.com' path
        self.assertEqual(feats["num_path_segments"], 2.0)  # ['paypal.com', 'webscr']
        self.assertGreaterEqual(feats["num_suspicious_keywords"], 1.0)  # 'paypal'

    def test_embedded_at_symbol_spoofing(self):
        """Tests credential confusion technique with '@' symbol."""
        url = "https://paypal.com@secure-verify-update.ml/login.php"
        feats = extract_url_features(url)

        self.assertEqual(feats["num_at_symbols"], 1.0)
        self.assertEqual(feats["hostname_length"], len("secure-verify-update.ml"))
        self.assertEqual(feats["uses_https"], 1.0)
        self.assertGreaterEqual(feats["num_suspicious_keywords"], 3.0)  # paypal, secure, verify, update, login

    def test_percent_encoded_sequences(self):
        """Tests counting of percent-encoded sequences (%XX)."""
        url = "http://example.com/path?param=%20%2F%3D%3F%2A"
        feats = extract_url_features(url)

        self.assertEqual(feats["num_percent_encoded"], 5.0)  # %20, %2F, %3D, %3F, %2A

    def test_subdomain_depth_calculation(self):
        """Tests calculation of nested subdomains."""
        # 4 subdomains: ['a', 'b', 'c', 'd'] before 'example.com'
        url = "http://a.b.c.d.example.com/index.html"
        feats = extract_url_features(url)

        self.assertEqual(feats["num_subdomains"], 4.0)
        self.assertEqual(feats["num_dots"], 6.0)  # 5 in hostname + 1 in 'index.html'

    def test_bare_url_without_scheme(self):
        """Tests handling of URLs provided without http:// or https://."""
        url = "sub.domain.org/login/authenticate"
        feats = extract_url_features(url)

        self.assertEqual(feats["hostname_length"], len("sub.domain.org"))
        self.assertEqual(feats["num_subdomains"], 1.0)
        self.assertEqual(feats["num_path_segments"], 2.0)
        self.assertGreaterEqual(feats["num_suspicious_keywords"], 2.0)  # login, authenticate

    def test_special_characters_and_hyphens(self):
        """Tests accurate counting of special characters and hyphens."""
        url = "http://my-secure-wallet-portal.xyz/account_id?user=test&token=abc_123"
        feats = extract_url_features(url)

        self.assertGreaterEqual(feats["num_hyphens"], 3.0)
        self.assertGreaterEqual(feats["num_underscores"], 2.0)
        self.assertGreaterEqual(feats["num_special_chars"], 5.0)

    def test_validation_rejects_invalid_inputs(self):
        """Verifies that invalid or empty inputs raise ValueError."""
        invalid_cases = [
            "",
            "    ",
            None,
            12345,
            "justwordsnoperiod",
            "http://invalid whitespace.com",
            "ab"
        ]

        for case in invalid_cases:
            is_valid, _ = validate_url(case)
            self.assertFalse(is_valid, f"Should be invalid: {case}")
            with self.assertRaises(ValueError):
                extract_url_features(case)

    def test_consistency_between_dict_and_vector(self):
        """Verifies that feature vector matches the dictionary values exactly in order."""
        url = "https://bank-login-secure.xyz:8080/portal/verify?code=987"
        feat_dict = extract_url_features(url)
        feat_vec = extract_url_vector(url)

        self.assertEqual(len(feat_vec), len(FEATURE_NAMES))
        for i, name in enumerate(FEATURE_NAMES):
            self.assertEqual(feat_vec[i], feat_dict[name], f"Mismatch at index {i} for feature {name}")


if __name__ == '__main__':
    unittest.main()
