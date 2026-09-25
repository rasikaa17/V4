# 🛡️ AI Threat Intelligence Platform

A Streamlit-based Security Operations Center (SOC) dashboard that scores IP addresses,
URLs/domains, and file hashes for risk using an explainable, rule-based scoring engine —
built as a student cybersecurity project.

---

## 📌 Project Description

The AI Threat Intelligence Platform ingests threat indicator data, scores each indicator's
risk using a transparent heuristic engine, and presents the results through an interactive
SOC-style dashboard. Analysts can also submit new indicators for real-time analysis.

## ❓ Problem Statement

Security teams are flooded with raw indicators of compromise (IOCs) from multiple feeds,
with little context on which ones actually matter. Manually triaging every IP, domain, or
file hash does not scale. This project demonstrates an automated, explainable pipeline for
triaging indicators by risk, so analysts can focus on the highest-priority threats first.

## 🎯 Objectives

- Build an explainable risk-scoring pipeline for IPs, domains/URLs, and file hashes.
- Present threat intelligence through a clear, professional SOC dashboard.
- Allow analysts to submit new indicators and get an instant risk assessment.
- Maintain a searchable, filterable historical record of all analyzed threats.
- Demonstrate a full, version-controlled software development workflow on GitHub.

## ✨ Features

- **Overview metrics** — total, critical, high, medium, low threat counts, and average risk score.
- **Threat distribution charts** — by priority, threat type, indicator type, and risk-score histogram.
- **Threat intelligence table** — sortable, filterable table of all records.
- **High-priority threat panel** — top Critical/High threats with reason and recommended action.
- **Threat analysis tool** — submit an IP, domain, or hash for live scoring.
- **Filters** — priority, threat type, indicator type, source, and date range.
- **Persistent SQLite database** — historical + analyst-submitted records.
- **CSV export** — download filtered results from the Threat Database page.

## 🔄 System Workflow

```
Raw Indicator (IP / URL / Hash)
        │
        ▼
 Preprocessing & Type Detection  (ml/preprocessing.py, ml/feature_engineering.py)
        │
        ▼
 Heuristic Feature Extraction    (ml/feature_engineering.py)
        │
        ▼
 Rule-Based Risk Scoring         (utils/threat_scoring.py, calibrated by ml/train_model.py)
        │
        ▼
 SQLite Storage                  (database/database.py)
        │
        ▼
 Streamlit SOC Dashboard         (app.py, pages/*.py)
```

## 🛠️ Technologies Used

- **Python 3.10+**
- **Streamlit** — dashboard framework
- **Pandas / NumPy** — data processing
- **Plotly** — interactive charts
- **SQLite** — lightweight persistence
- **Git/GitHub** — version control

## 📁 Project Structure

```
ai-threat-intelligence-platform/
│
├── README.md
├── requirements.txt
├── app.py
├── .gitignore
│
├── data/
│   └── threat_data.csv
│
├── models/
│   └── threat_model.pkl
│
├── ml/
│   ├── preprocessing.py
│   ├── feature_engineering.py
│   ├── train_model.py
│   ├── predict.py
│   └── generate_synthetic_data.py
│
├── database/
│   └── database.py
│
├── utils/
│   ├── threat_scoring.py
│   ├── ui.py
│   └── dashboard_view.py
│
├── pages/
│   ├── dashboard.py
│   ├── threat_analysis.py
│   └── threat_database.py
│
├── assets/
│   └── images/
│
└── tests/
    └── test_threat_scoring.py
```

## ⚙️ Installation Steps

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/ai-threat-intelligence-platform.git
cd ai-threat-intelligence-platform

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Generate the synthetic dataset (first-time setup)
python ml/generate_synthetic_data.py

# 5. Train / calibrate the model artifact
python ml/train_model.py
```

## ▶️ How to Run the Dashboard

```bash
streamlit run app.py
```

The app opens at `http://localhost:8501`. Use the sidebar to navigate between
**Dashboard**, **Threat Analysis**, and **Threat Database**.

## 🖼️ Screenshots

_Add screenshots of the Overview dashboard, Threat Analysis page, and Threat Database
here once the app is running locally (e.g. `assets/images/dashboard.png`)._

## 🤖 ML Methodology

This project uses a **transparent, rule-based scoring engine** rather than a black-box
classifier, prioritizing explainability — every risk score can be traced back to specific,
human-readable reasons (e.g. "suspicious TLD", "high domain entropy", "known risky IP range").

- **Feature extraction** (`ml/feature_engineering.py`): derives features like Shannon
  entropy, suspicious TLDs/keywords, hyphenation patterns, and hash-format validity —
  all computed offline, with no external API dependency.
- **Scoring** (`utils/threat_scoring.py`): each feature contributes a weighted point value
  to a 0–100 risk score, with clear reasons attached to every contributing rule.
- **"Training"** (`ml/train_model.py`): calibrates priority-band thresholds (Critical/High/
  Medium/Low) against the actual percentile distribution of the dataset's risk scores,
  and stores dataset statistics used by the dashboard — packaged into `models/threat_model.pkl`.

This design was chosen deliberately over a black-box ML classifier so that every score
shown on the dashboard is explainable to a human analyst, which matters more for SOC
tooling than marginal accuracy gains from an opaque model.

## 📊 Dataset Description

`data/threat_data.csv` is a **synthetically generated** dataset of 1,200 threat records,
built to have realistic structure and a plausible mix of benign and malicious indicators:

| Column | Description |
|---|---|
| `indicator` | The IP, domain/URL, or file hash |
| `indicator_type` | IP Address / URL-Domain / File Hash |
| `threat_type` | Predicted threat category (or Benign) |
| `risk_score` | 0–100 heuristic risk score |
| `priority` | Critical / High / Medium / Low |
| `confidence` | Model confidence (%) |
| `source` | Simulated feed/source name |
| `timestamp` | When the indicator was observed |
| `status` | Active / Investigating / Mitigated / Resolved / False Positive |

Regenerate it anytime with `python ml/generate_synthetic_data.py`.

## 📈 Results

- The scoring engine consistently assigns higher risk scores to indicators with known
  malicious patterns (suspicious TLDs, phishing keywords, high entropy, flagged IP ranges)
  than to benign-looking indicators — verified in `tests/test_threat_scoring.py`.
- Calibrated priority thresholds place roughly the top 10% of scored indicators in the
  Critical band, consistent with typical SOC triage expectations.

## ⚠️ Limitations

- The dataset is synthetic, not sourced from a live threat-intelligence feed.
- Scoring rules are heuristic; they do not replace real threat-intel enrichment
  (WHOIS, live geo-IP, VirusTotal, sandboxing, etc.).
- No authentication/RBAC — intended for local/demo/educational use, not production SOC use.

## 🚀 Future Scope

- Integrate real threat-intel feeds (AbuseIPDB, VirusTotal, AlienVault OTX APIs).
- Replace/augment the heuristic engine with a trained supervised classifier once labeled
  real-world data is available.
- Add user authentication and role-based access control.
- Add alerting (email/Slack) for newly detected Critical-priority threats.

## 👥 Contributors

- _Add your name(s) here._

---

## ☁️ Deployment (Streamlit Community Cloud)

Once the local app is fully tested:

1. Push the repository to GitHub (see workflow below).
2. Go to [share.streamlit.io](https://share.streamlit.io) and sign in with GitHub.
3. Click **New app**, select this repository, branch `main`, and set the main file to `app.py`.
4. Deploy. Streamlit Cloud will install `requirements.txt` automatically.
5. On first run, the app auto-generates the SQLite database from `data/threat_data.csv`
   if it doesn't already exist — no manual setup step needed post-deploy.

```
GitHub Repository → Streamlit Application → Live Threat Intelligence Dashboard
```
