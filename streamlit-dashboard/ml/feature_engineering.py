"""
feature_engineering.py
------------------------
Extracts explainable heuristic features from a raw indicator
(IP address, URL/domain, or file hash). These features feed the
rule-based risk-scoring engine in utils/threat_scoring.py.

No external network calls are made (no live WHOIS / geo-IP / VT
lookups) — all signals are derived deterministically from the
indicator string itself and small internal reference lists. This
keeps the project fully offline-runnable and reproducible, which is
ideal for a student cybersecurity project and for grading/demo
purposes.
"""

import math
import re

SUSPICIOUS_TLDS = {"xyz", "top", "click", "tk", "gq", "ml", "cf", "work", "loan", "zip", "review"}
TRUSTED_TLDS = {"gov", "edu", "mil"}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account", "invoice",
    "wallet", "bank", "confirm", "signin", "reset", "support",
]

PRIVATE_IP_PATTERNS = [
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[0-1])\."),
]

KNOWN_RISKY_FIRST_OCTETS = {45, 91, 103, 185, 194, 5, 89}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def _is_ip(value: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value.strip()))


def _is_hash(value: str) -> bool:
    v = value.strip()
    return bool(re.match(r"^[a-fA-F0-9]{32}$", v) or re.match(r"^[a-fA-F0-9]{40}$", v) or re.match(r"^[a-fA-F0-9]{64}$", v))


def detect_indicator_type(value: str) -> str:
    """Infer indicator type directly from the raw string (used by the
    Threat Analysis page when the user doesn't explicitly pick a type)."""
    value = value.strip()
    if _is_ip(value):
        return "IP Address"
    if _is_hash(value):
        return "File Hash"
    return "URL/Domain"


def extract_features(indicator: str, indicator_type: str) -> dict:
    """Extract a dict of heuristic, explainable features for scoring."""
    indicator = indicator.strip()
    features = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "entropy": round(_shannon_entropy(indicator), 3),
        "length": len(indicator),
        "is_private_ip": False,
        "risky_octet": False,
        "suspicious_tld": False,
        "trusted_tld": False,
        "suspicious_keyword": False,
        "hyphen_count": indicator.count("-"),
        "digit_ratio": round(sum(c.isdigit() for c in indicator) / max(len(indicator), 1), 3),
        "hash_length_valid": False,
    }

    if indicator_type == "IP Address":
        features["is_private_ip"] = any(p.match(indicator) for p in PRIVATE_IP_PATTERNS)
        try:
            first_octet = int(indicator.split(".")[0])
            features["risky_octet"] = first_octet in KNOWN_RISKY_FIRST_OCTETS
        except (ValueError, IndexError):
            features["risky_octet"] = False

    elif indicator_type == "URL/Domain":
        domain = indicator.lower().split("/")[0]
        tld = domain.split(".")[-1] if "." in domain else ""
        features["suspicious_tld"] = tld in SUSPICIOUS_TLDS
        features["trusted_tld"] = tld in TRUSTED_TLDS
        features["suspicious_keyword"] = any(k in domain for k in SUSPICIOUS_KEYWORDS)

    elif indicator_type == "File Hash":
        features["hash_length_valid"] = _is_hash(indicator)

    return features
