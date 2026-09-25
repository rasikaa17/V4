"""
generate_dataset.py
---------------------
PHASE 2 — Threat Intelligence Dataset

Generates a realistic SYNTHETIC dataset for this academic project.

IMPORTANT: This data is entirely artificial. It is NOT pulled from any
real threat-intelligence feed (no AlienVault OTX, AbuseIPDB, VirusTotal,
etc. API calls are made). Source names like "AlienVault OTX" appear only
as plausible category labels to make the dataset structurally realistic
for demonstration purposes. This is clearly documented so no one mistakes
it for real-world threat data — see data/DATASET_INFO.md.

The dataset intentionally includes a ground-truth label column
(priority_label) computed from a weighted formula plus random noise, so
that Phase 5 (Machine Learning) has something meaningful to learn to
predict from the other columns. Without noise, the ML problem would be
trivial (the model could just re-derive the formula); the noise makes it
a genuine, if simplified, classification problem.

Run:
    python data/generate_dataset.py
Output:
    data/threat_data.csv
"""

import csv
import os
import random
from datetime import datetime, timedelta

random.seed(42)

N_RECORDS = 1500

INDICATOR_TYPES = ["IP Address", "URL/Domain", "File Hash", "CVE/Vulnerability"]

THREAT_TYPES = [
    "Malware", "Phishing", "Botnet C2", "Ransomware", "Spyware",
    "DDoS", "Brute Force", "Data Exfiltration", "Cryptomining",
    "Vulnerability Exploit", "Benign",
]

MALWARE_FAMILIES = {
    "Malware": ["Emotet", "TrickBot", "QakBot", "AgentTesla", "FormBook"],
    "Ransomware": ["LockBit", "Conti", "REvil", "WannaCry"],
    "Spyware": ["njRAT", "DarkComet", "Pegasus-like-sim"],
    "Botnet C2": ["Mirai", "Qbot", "Gafgyt"],
    "Cryptomining": ["XMRig", "CoinMiner"],
}

SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]
SOURCES = [
    "AlienVault OTX", "AbuseIPDB", "VirusTotal", "Internal Honeypot",
    "MISP Feed", "PhishTank", "Spamhaus", "Manual Analyst Report",
]
STATUSES = ["Active", "Investigating", "Mitigated", "Resolved", "False Positive"]

SUSPICIOUS_TLDS = ["xyz", "top", "click", "tk", "gq", "ml", "cf", "work", "loan"]
NORMAL_TLDS = ["com", "net", "org", "io", "co", "gov", "edu"]
SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "update", "account", "invoice", "wallet"]

SEVERITY_WEIGHT = {"Low": 10, "Medium": 35, "High": 65, "Critical": 90}


def random_ip(malicious_bias=False):
    first = random.choice([45, 91, 103, 185, 194, 5, 89]) if (malicious_bias and random.random() < 0.4) \
        else random.randint(1, 223)
    return f"{first}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def random_domain(malicious_bias=False):
    letters = "abcdefghijklmnopqrstuvwxyz0123456789-"
    name = "".join(random.choice(letters) for _ in range(random.randint(5, 14)))
    if malicious_bias and random.random() < 0.55:
        name = random.choice(SUSPICIOUS_KEYWORDS) + "-" + name
        tld = random.choice(SUSPICIOUS_TLDS)
    else:
        tld = random.choice(NORMAL_TLDS)
    return f"{name}.{tld}"


def random_hash():
    import hashlib
    raw = f"{random.random()}{datetime.now()}".encode()
    return hashlib.sha256(raw).hexdigest()


def random_cve():
    return f"CVE-{random.randint(2019, 2026)}-{random.randint(1000, 49999)}"


def random_timestamp():
    days_back = random.randint(0, 180)
    seconds_back = random.randint(0, 86400)
    return (datetime.now() - timedelta(days=days_back, seconds=seconds_back)).strftime("%Y-%m-%d %H:%M:%S")


def compute_priority_label(severity, confidence, attack_frequency, affected_systems, days_ago):
    """
    Ground-truth label generator for supervised learning (Phase 5).

    Combines several weighted factors + random noise into a 0-100 score,
    then bands it into Critical/High/Medium/Low. This is a SIMPLIFIED,
    synthetic formula for academic purposes — real-world risk scoring
    would involve far more context (asset criticality, business impact,
    exploit availability, etc.), which is explicitly noted as a
    limitation in the project documentation.
    """
    score = 0.0
    score += SEVERITY_WEIGHT[severity] * 0.40
    score += confidence * 0.25
    score += min(attack_frequency, 50) * 0.6  # cap contribution
    score += min(affected_systems, 30) * 0.5
    recency_bonus = max(0, 20 - days_ago) * 0.5  # more recent = more urgent
    score += recency_bonus
    score += random.gauss(0, 8)  # noise so the label isn't perfectly derivable
    score = max(0, min(100, score))

    if score >= 75:
        return "Critical", round(score, 1)
    if score >= 50:
        return "High", round(score, 1)
    if score >= 25:
        return "Medium", round(score, 1)
    return "Low", round(score, 1)


def build_record():
    indicator_type = random.choices(INDICATOR_TYPES, weights=[0.35, 0.35, 0.2, 0.1])[0]
    malicious_bias = random.random() < 0.55

    if indicator_type == "IP Address":
        indicator = random_ip(malicious_bias)
    elif indicator_type == "URL/Domain":
        indicator = random_domain(malicious_bias)
    elif indicator_type == "File Hash":
        indicator = random_hash()
    else:
        indicator = random_cve()

    if not malicious_bias and random.random() < 0.5:
        threat_type = "Benign"
    else:
        threat_type = random.choice([t for t in THREAT_TYPES if t != "Benign"])

    malware_family = "Unknown"
    if threat_type in MALWARE_FAMILIES:
        malware_family = random.choice(MALWARE_FAMILIES[threat_type])

    severity = random.choices(SEVERITY_LEVELS, weights=[0.35, 0.3, 0.22, 0.13])[0] \
        if threat_type != "Benign" else random.choices(SEVERITY_LEVELS, weights=[0.7, 0.2, 0.08, 0.02])[0]

    confidence = round(random.uniform(40, 99), 1) if threat_type != "Benign" else round(random.uniform(20, 70), 1)
    attack_frequency = random.randint(0, 60) if threat_type != "Benign" else random.randint(0, 5)
    affected_systems = random.randint(0, 25) if threat_type != "Benign" else random.randint(0, 2)

    timestamp = random_timestamp()
    days_ago = (datetime.now() - datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")).days

    priority_label, risk_reference_score = compute_priority_label(
        severity, confidence, attack_frequency, affected_systems, days_ago
    )

    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "threat_type": threat_type,
        "malware_family": malware_family,
        "severity": severity,
        "confidence": confidence,
        "source": random.choice(SOURCES),
        "timestamp": timestamp,
        "attack_frequency": attack_frequency,
        "affected_systems": affected_systems,
        "status": random.choice(STATUSES),
        "priority_label": priority_label,          # ground-truth target for Phase 5 ML
        "risk_reference_score": risk_reference_score,  # numeric ground truth (0-100), for regression experiments
    }


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(base_dir, "threat_data.csv")

    fieldnames = [
        "indicator", "indicator_type", "threat_type", "malware_family",
        "severity", "confidence", "source", "timestamp", "attack_frequency",
        "affected_systems", "status", "priority_label", "risk_reference_score",
    ]

    rows = [build_record() for _ in range(N_RECORDS)]
    rows.sort(key=lambda r: r["timestamp"], reverse=True)

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generated {len(rows)} SYNTHETIC threat records -> {out_path}")

    # quick sanity summary
    from collections import Counter
    label_counts = Counter(r["priority_label"] for r in rows)
    print(f"Priority label distribution: {dict(label_counts)}")


if __name__ == "__main__":
    main()
