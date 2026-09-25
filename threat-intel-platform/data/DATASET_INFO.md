# Dataset Information

## ⚠️ This dataset is SYNTHETIC

`threat_data.csv` is **entirely artificially generated** by `generate_dataset.py`
for academic/demo purposes. It is **not** sourced from any real threat-intelligence
feed. Source names such as "AlienVault OTX", "AbuseIPDB", "VirusTotal", etc. appear
only as plausible category labels to make the dataset structurally realistic — no
API calls to these services were made, and no real indicators of compromise are
included.

This is disclosed here, in the README, and in the final project documentation so
no reader mistakes it for real-world threat intelligence.

## How it was generated

Run `python data/generate_dataset.py` to regenerate it (seeded with `random.seed(42)`
for reproducibility). It procedurally creates 1,500 records with a plausible mix of
benign and malicious indicators, then computes a synthetic ground-truth priority
label from a weighted formula (severity + confidence + attack frequency + affected
systems + recency) plus random noise — this noise is intentional, so the Phase 5 ML
model has a genuine (if simplified) prediction problem rather than one that
perfectly reproduces a known formula.

## Column Dictionary

| Column | Type | Description |
|---|---|---|
| `indicator` | string | The raw IOC value: IP address, domain/URL, file hash, or CVE ID |
| `indicator_type` | categorical | `IP Address`, `URL/Domain`, `File Hash`, or `CVE/Vulnerability` |
| `threat_type` | categorical | Threat category (Malware, Phishing, Botnet C2, Ransomware, Spyware, DDoS, Brute Force, Data Exfiltration, Cryptomining, Vulnerability Exploit, or Benign) |
| `malware_family` | categorical | Named malware family if applicable, else `Unknown` (deliberately not `N/A`, since pandas silently treats the literal string `"N/A"` as a missing value) |
| `severity` | categorical | Reported severity from the (simulated) source: Low / Medium / High / Critical |
| `confidence` | numeric (0-100) | Source's confidence in this indicator's classification |
| `source` | categorical | Simulated feed/analyst source name |
| `timestamp` | datetime | When the indicator was observed |
| `attack_frequency` | numeric | Number of times this indicator was observed in related attack activity |
| `affected_systems` | numeric | Number of internal systems reportedly affected/contacted |
| `status` | categorical | Active / Investigating / Mitigated / Resolved / False Positive |
| `priority_label` | categorical | **Ground-truth target for ML (Phase 5)**: Critical / High / Medium / Low |
| `risk_reference_score` | numeric (0-100) | Numeric ground-truth score behind `priority_label`, useful if a regression approach is tried instead of classification |

## Known limitations of this dataset (for the Limitations section of your report)

- Synthetic, not real-world data — patterns are simplified compared to actual
  threat intelligence.
- The ground-truth formula is a reasonable but simplified approximation of
  real-world risk scoring; it does not account for asset criticality, business
  context, or exploit availability.
- Class balance was deliberately kept reasonably even for ML training purposes,
  which is not necessarily representative of real SOC alert volumes (which tend
  to be heavily skewed toward Low/Medium).
