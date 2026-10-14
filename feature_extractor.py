"""
AI-Based Malicious URL Detection System
Reusable URL Feature Extraction Module

Extracts a consistent, reproducible vector of 16 lexical and structural features
from raw URL strings for training and inference in Machine Learning models.

CRITICAL DESIGN PRINCIPLES:
1. Purely Passive: Does not visit, ping, or download anything from the target URL.
2. Feature Parity: Exactly the same feature logic and ordering must be used in
   both training (dataset preparation) and inference (Flask/FastAPI/CLI).
3. Defensive Parsing: Safely handles malformed, bare, or unusual URLs without crashing.
4. No Single-Feature Bias: No single feature is treated as definitive proof of malicious intent.
"""

import re
import urllib.parse
from typing import Dict, List, Tuple, Any, Optional

# ==============================================================================
# 1. CONSTANTS & CONFIGURATION
# ==============================================================================

# Exact, immutable feature names in order of the feature vector
FEATURE_NAMES: Tuple[str, ...] = (
    "url_length",
    "hostname_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_digits",
    "num_special_chars",
    "num_subdomains",
    "is_ipv4",
    "uses_https",
    "has_ip_in_url",
    "num_suspicious_keywords",
    "num_path_segments",
    "query_length",
    "num_at_symbols",
    "num_percent_encoded"
)

# Curated list of keywords frequently exploited in phishing, fraud, and social engineering
SUSPICIOUS_KEYWORDS: Tuple[str, ...] = (
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "security",
    "secure",
    "account",
    "banking",
    "update",
    "paypal",
    "appleid",
    "wallet",
    "recover",
    "recovery",
    "billing",
    "authenticate",
    "confirm",
    "passcode",
    "password",
    "claim",
    "bonus",
    "unlock",
    "suspended"
)

# Standard special characters to audit in URL strings
SPECIAL_CHARS_PATTERN = re.compile(r'[-_.~!*\'();:@&=+$,/?%#[\]]')

# IPv4 regex: strictly matches valid 0-255 octets
IPV4_OCTET = r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
IPV4_STRICT_PATTERN = re.compile(rf'^{IPV4_OCTET}\.{IPV4_OCTET}\.{IPV4_OCTET}\.{IPV4_OCTET}$')

# General IPv4 pattern appearing anywhere within the URL
IPV4_ANYWHERE_PATTERN = re.compile(rf'{IPV4_OCTET}\.{IPV4_OCTET}\.{IPV4_OCTET}\.{IPV4_OCTET}')

# Percent-encoding sequence pattern: % followed by 2 hex digits (e.g. %20, %2F)
PERCENT_ENCODED_PATTERN = re.compile(r'%[0-9a-fA-F]{2}')


# ==============================================================================
# 2. VALIDATION & SANITIZATION HELPERS
# ==============================================================================

def validate_url(url: Any) -> Tuple[bool, str]:
    """
    Validates whether an input represents a plausible URL string.
    
    Returns:
        (is_valid: bool, error_message: str)
    """
    if url is None:
        return False, "Input URL cannot be None."
    
    if not isinstance(url, str):
        return False, f"Expected string input, received {type(url).__name__}."
    
    cleaned = url.strip()
    if not cleaned:
        return False, "URL string is empty or contains only whitespace."
    
    if len(cleaned) < 3:
        return False, "URL string is too short to be evaluated."
    
    # Ensure URL does not contain unescaped whitespace
    if re.search(r'\s', cleaned):
        return False, "URL contains illegal whitespace characters."

    # Validate scheme if explicitly provided
    scheme_match = re.match(r'^([a-zA-Z][a-zA-Z0-9+.-]*):', cleaned)
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        if scheme not in ("http", "https"):
            return False, f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS schemes are supported."

    # Safely parse URL structure to verify non-empty host
    parsed = safe_parse_url(cleaned)
    if not parsed.netloc:
        return False, "Missing host or domain name in URL."

    # Verify that the host contains a period, port colon, or localhost
    if "." not in parsed.netloc and ":" not in parsed.netloc and "localhost" not in parsed.netloc.lower():
        return False, "Missing top-level domain, port, or hostname structure."

    return True, "Valid"


def safe_parse_url(raw_url: str) -> urllib.parse.ParseResult:
    """
    Safely parses a URL string using urllib.parse.urlparse.
    If the protocol scheme is omitted (e.g. 'example.com/path'),
    normalizes it with '//' prefix so urlparse correctly separates
    the netloc (hostname) from the path.
    """
    cleaned = raw_url.strip()
    
    # If scheme is missing (e.g., 'www.example.com/test' or '192.168.1.1/login')
    # Prepending '//' informs urllib that the leading segment is a netloc/hostname
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', cleaned):
        if not cleaned.startswith('//'):
            cleaned = '//' + cleaned
            
    try:
        parsed = urllib.parse.urlparse(cleaned)
        return parsed
    except Exception:
        # Fallback to an empty ParseResult if parsing fundamentally fails
        return urllib.parse.ParseResult(
            scheme='', netloc='', path=cleaned, params='', query='', fragment=''
        )


# ==============================================================================
# 3. FEATURE EXTRACTION ENGINE
# ==============================================================================

class UrlFeatureExtractor:
    """
    Reusable feature extraction class for URL threat analysis.
    """

    @staticmethod
    def extract_features(raw_url: str) -> Dict[str, Any]:
        """
        Extracts all 16 features and returns a dictionary mapping feature names to values.
        
        Raises:
            ValueError: If the URL fails basic format validation.
        """
        is_valid, msg = validate_url(raw_url)
        if not is_valid:
            raise ValueError(f"Invalid URL: {msg}")
        
        url = raw_url.strip()
        parsed = safe_parse_url(url)
        
        # Extract hostname, stripping any credentials (user:pass@) or port
        hostname = (parsed.hostname or '').lower()
        path = parsed.path or ''
        query = parsed.query or ''
        url_lower = url.lower()
        
        # 1. Total URL length
        url_length = len(url)
        
        # 2. Hostname length
        hostname_length = len(hostname)
        
        # 3. Number of dots (.) in full URL
        num_dots = url.count('.')
        
        # 4. Number of hyphens (-) in full URL
        num_hyphens = url.count('-')
        
        # 5. Number of underscores (_) in full URL
        num_underscores = url.count('_')
        
        # 6. Number of digits (0-9) in full URL
        num_digits = sum(1 for ch in url if ch.isdigit())
        
        # 7. Number of special characters in full URL
        num_special_chars = len(SPECIAL_CHARS_PATTERN.findall(url))
        
        # 8. Number of subdomains
        # In 'sub.domain.example.com', parts are ['sub', 'domain', 'example', 'com'] (4 parts)
        # Standard domain + TLD takes 2 parts, so subdomain count is max(0, len - 2)
        if hostname:
            host_parts = hostname.split('.')
            # If hostname is a raw IPv4, it doesn't have subdomains
            if IPV4_STRICT_PATTERN.match(hostname):
                num_subdomains = 0
            else:
                num_subdomains = max(0, len(host_parts) - 2)
        else:
            num_subdomains = 0
            
        # 9. Whether the hostname is an IPv4 address (1 or 0)
        is_ipv4 = 1 if bool(IPV4_STRICT_PATTERN.match(hostname)) else 0
        
        # 10. Whether the URL uses HTTPS (1 or 0)
        uses_https = 1 if parsed.scheme.lower() == 'https' else 0
        
        # 11. Whether the URL contains an IP address anywhere in its string (1 or 0)
        has_ip_in_url = 1 if bool(IPV4_ANYWHERE_PATTERN.search(url)) else 0
        
        # 12. Whether selected suspicious keywords appear in the URL
        # We count the number of distinct keywords matched from the blacklist
        num_suspicious_keywords = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
        
        # 13. Number of URL path segments (e.g. /path/to/page has 3 segments)
        path_segments = [p for p in path.split('/') if p]
        num_path_segments = len(path_segments)
        
        # 14. Length of the query string (characters after '?')
        query_length = len(query)
        
        # 15. Number of '@' symbols in URL
        # Attackers use userinfo 'http://google.com@phish.com' to deceive users
        num_at_symbols = url.count('@')
        
        # 16. Number of percent-encoded sequences (%XX)
        num_percent_encoded = len(PERCENT_ENCODED_PATTERN.findall(url))
        
        return {
            "url_length": float(url_length),
            "hostname_length": float(hostname_length),
            "num_dots": float(num_dots),
            "num_hyphens": float(num_hyphens),
            "num_underscores": float(num_underscores),
            "num_digits": float(num_digits),
            "num_special_chars": float(num_special_chars),
            "num_subdomains": float(num_subdomains),
            "is_ipv4": float(is_ipv4),
            "uses_https": float(uses_https),
            "has_ip_in_url": float(has_ip_in_url),
            "num_suspicious_keywords": float(num_suspicious_keywords),
            "num_path_segments": float(num_path_segments),
            "query_length": float(query_length),
            "num_at_symbols": float(num_at_symbols),
            "num_percent_encoded": float(num_percent_encoded)
        }

    @classmethod
    def extract_vector(cls, raw_url: str) -> List[float]:
        """
        Extracts features and returns them as a 1D numerical list in strict FEATURE_NAMES order.
        Suitable for direct consumption by Scikit-Learn models: model.predict([vector])
        """
        feat_dict = cls.extract_features(raw_url)
        return [feat_dict[name] for name in FEATURE_NAMES]


# ==============================================================================
# 4. CONVENIENCE FUNCTION EXPORTS
# ==============================================================================

def extract_url_features(url: str) -> Dict[str, Any]:
    """Convenience helper: returns feature dictionary."""
    return UrlFeatureExtractor.extract_features(url)


def extract_url_vector(url: str) -> List[float]:
    """Convenience helper: returns feature vector list matching FEATURE_NAMES order."""
    return UrlFeatureExtractor.extract_vector(url)


def get_feature_names() -> List[str]:
    """Returns the immutable list of feature names."""
    return list(FEATURE_NAMES)
