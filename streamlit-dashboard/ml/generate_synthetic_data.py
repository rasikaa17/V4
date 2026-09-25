"""
generate_synthetic_data.py
---------------------------
Generates a realistic synthetic threat-intelligence dataset for the
AI Threat Intelligence Platform student project.

This does NOT call any external threat-feed APIs. It procedurally
creates indicators (IPs, domains/URLs, file hashes) with plausible
attributes, then scores them with the same heuristic engine used by
the live app (utils.threat_scoring) so labels are internally consistent.

Run:
    python ml/generate_synthetic_data.py
Output:
    data/threat_data.csv
"""

import csv
import hashlib
import os
import random
import sys
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.feature_engineering import extract_features
from utils.threat_scoring import score_indicator

random.seed(42)

N_RECORDS = 1200

THREAT_TYPES = [
    "Malware", "Phishing", "Botnet C2", "Ransomware", "Spyware",
    "DDoS", "Brute Force", "Data Exfiltration", "Cryptomining", "Benign",
]

SOURCES = [
    "AlienVault OTX", "AbuseIPDB", "VirusTotal", "Internal Honeypot",
    "MISP Feed", "PhishTank", "Spamhaus", "Manual Analyst Report",
]

STATUSES = ["Active", "Investigating", "Mitigated", "Resolved", "False Positive"]

SUSPICIOUS_TLDS = ["xyz", "top", "click", "tk", "gq", "ml", "cf", "work", "loan"]
NORMAL_TLDS = ["com", "net", "org", "io", "co", "gov", "edu"]

MALWARE_KEYWORDS = ["update", "secure", "login", "verify", "account", "invoice", "wallet"]


def random_ip(malicious_bias=False):
    if malicious_bias and random.random() < 0.4:
        # bias toward known "risky" ranges used purely for synthetic realism
        first = random.choice([45, 91, 103, 185, 194, 5, 89])
    else:
        first = random.randint(1, 223)
    return f"{first}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def random_domain(malicious_bias=False):
    length = random.randint(5, 14)
    letters = "abcdefghijklmnopqrstuvwxyz0123456789-"
    name = "".join(random.choice(letters) for _ in range(length))
    if malicious_bias and random.random() < 0.55:
        name = random.choice(MALWARE_KEYWORDS) + "-" + name
        tld = random.choice(SUSPICIOUS_TLDS)
    else:
        tld = random.choice(NORMAL_TLDS)
    return f"{name}.{tld}"


def random_hash():
    raw = f"{random.random()}{datetime.now()}".encode()
    return hashlib.sha256(raw).hexdigest()


def random_timestamp():
    days_back = random.randint(0, 180)
    seconds_back = random.randint(0, 86400)
    ts = datetime.now() - timedelta(days=days_back, seconds=seconds_back)
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def build_record():
    indicator_type = random.choices(
        ["IP Address", "URL/Domain", "File Hash"], weights=[0.4, 0.4, 0.2]
    )[0]
    malicious_bias = random.random() < 0.55  # ~55% of dataset skews toward real threats

    if indicator_type == "IP Address":
        indicator = random_ip(malicious_bias)
    elif indicator_type == "URL/Domain":
        indicator = random_domain(malicious_bias)
    else:
        indicator = random_hash()

    features = extract_features(indicator, indicator_type)
    result = score_indicator(indicator, indicator_type, features)

    if not malicious_bias and result["risk_score"] > 40:
        # keep a realistic mix of benign-looking traffic with low scores
        result["risk_score"] = max(2, result["risk_score"] - random.randint(30, 50))

    threat_type = result["threat_type"] if result["risk_score"] >= 20 else "Benign"

    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "threat_type": threat_type,
        "risk_score": result["risk_score"],
        "priority": result["priority"],
        "confidence": result["confidence"],
        "source": random.choice(SOURCES),
        "timestamp": random_timestamp(),
        "status": random.choice(STATUSES),
    }


def main():
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "threat_data.csv")

    fieldnames = [
        "indicator", "indicator_type", "threat_type", "risk_score",
        "priority", "confidence", "source", "timestamp", "status",
    ]

    rows = [build_record() for _ in range(N_RECORDS)]
    rows.sort(key=lambda r: r["timestamp"], reverse=True)

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generated {len(rows)} synthetic threat records -> {out_path}")


if __name__ == "__main__":
    main()
