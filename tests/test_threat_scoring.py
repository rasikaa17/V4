"""
Basic unit tests for the heuristic scoring engine.
Run with: pytest tests/
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.feature_engineering import detect_indicator_type, extract_features
from ml.preprocessing import clean_indicator_string, validate_indicator
from utils.threat_scoring import score_indicator


def test_detect_indicator_type_ip():
    assert detect_indicator_type("8.8.8.8") == "IP Address"


def test_detect_indicator_type_hash():
    sha256 = "a" * 64
    assert detect_indicator_type(sha256) == "File Hash"


def test_detect_indicator_type_domain():
    assert detect_indicator_type("example.com") == "URL/Domain"


def test_clean_indicator_strips_protocol():
    assert clean_indicator_string("https://example.com/") == "example.com"


def test_validate_indicator_rejects_empty():
    ok, _ = validate_indicator("   ")
    assert ok is False


def test_suspicious_domain_scores_higher_than_trusted():
    suspicious = extract_features("login-secure-verify.xyz", "URL/Domain")
    trusted = extract_features("harvard.edu", "URL/Domain")

    suspicious_score = score_indicator("login-secure-verify.xyz", "URL/Domain", suspicious)
    trusted_score = score_indicator("harvard.edu", "URL/Domain", trusted)

    assert suspicious_score["risk_score"] > trusted_score["risk_score"]


def test_score_within_bounds():
    result = score_indicator("1.2.3.4", "IP Address")
    assert 0 <= result["risk_score"] <= 100
    assert result["priority"] in {"Critical", "High", "Medium", "Low"}
