"""
train_model.py
----------------
"Trains" the threat model by calibrating the heuristic scoring engine
against the historical dataset and packaging everything (rule weights,
calibrated priority thresholds, dataset statistics, metadata) into a
single artifact: models/threat_model.pkl.

This is a transparent, rule-based model rather than a black-box
classifier — appropriate for a student cybersecurity project where
explainability matters. "Training" here means:
  1. Validating the rule engine reproduces sensible score
     distributions on real (synthetic) data.
  2. Calibrating priority-band thresholds to the actual score
     distribution (e.g. top 10% -> Critical) instead of hardcoded
     cutoffs, so thresholds adapt if the dataset changes.
  3. Recording per-threat-type and per-indicator-type statistics used
     by the dashboard's "confidence" narrative.

Run:
    python ml/train_model.py
"""

import os
import pickle
import sys
from datetime import datetime

import numpy as np
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.preprocessing import load_dataset
from utils.threat_scoring import RULES, BASE_SCORE

MODEL_VERSION = "1.0.0"


def calibrate_thresholds(scores: pd.Series) -> dict:
    """Derive percentile-based priority thresholds from the dataset's
    actual score distribution."""
    return {
        "critical": float(np.percentile(scores, 90)),
        "high": float(np.percentile(scores, 70)),
        "medium": float(np.percentile(scores, 40)),
    }


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_path = os.path.join(base_dir, "data", "threat_data.csv")
    model_path = os.path.join(base_dir, "models", "threat_model.pkl")

    if not os.path.exists(data_path):
        raise FileNotFoundError(
            f"Dataset not found at {data_path}. Run ml/generate_synthetic_data.py first."
        )

    df = load_dataset(data_path)

    thresholds = calibrate_thresholds(df["risk_score"])
    threat_type_dist = df["threat_type"].value_counts(normalize=True).to_dict()
    indicator_type_dist = df["indicator_type"].value_counts(normalize=True).to_dict()
    avg_confidence_by_priority = df.groupby("priority")["confidence"].mean().to_dict()

    artifact = {
        "model_version": MODEL_VERSION,
        "trained_at": datetime.now().isoformat(),
        "trained_on_records": int(len(df)),
        "rule_weights": RULES,
        "base_scores": BASE_SCORE,
        "calibrated_thresholds": thresholds,
        "threat_type_distribution": threat_type_dist,
        "indicator_type_distribution": indicator_type_dist,
        "avg_confidence_by_priority": avg_confidence_by_priority,
    }

    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    with open(model_path, "wb") as f:
        pickle.dump(artifact, f)

    print(f"Model artifact saved -> {model_path}")
    print(f"Trained on {len(df)} records | version {MODEL_VERSION}")
    print(f"Calibrated thresholds: {thresholds}")


if __name__ == "__main__":
    main()
