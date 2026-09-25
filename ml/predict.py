"""
predict.py
-----------
Loads the trained model artifact (models/threat_model.pkl) and
provides a single entry point, analyze_indicator(), used by the
Streamlit "Threat Analysis" page to score a new, user-submitted
indicator.
"""

import os
import pickle

from ml.feature_engineering import extract_features
from ml.preprocessing import clean_indicator_string, infer_type_if_needed
from utils.threat_scoring import score_indicator

_MODEL_CACHE = None


def _model_path() -> str:
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, "models", "threat_model.pkl")


def load_model() -> dict:
    global _MODEL_CACHE
    if _MODEL_CACHE is not None:
        return _MODEL_CACHE
    path = _model_path()
    if not os.path.exists(path):
        # Graceful fallback so the app still works before training is run
        _MODEL_CACHE = {"model_version": "untrained", "calibrated_thresholds": None}
        return _MODEL_CACHE
    with open(path, "rb") as f:
        _MODEL_CACHE = pickle.load(f)
    return _MODEL_CACHE


def _apply_calibrated_priority(score: int, thresholds: dict | None) -> str:
    if not thresholds:
        return None  # fall back to the engine's own default banding
    if score >= thresholds["critical"]:
        return "Critical"
    if score >= thresholds["high"]:
        return "High"
    if score >= thresholds["medium"]:
        return "Medium"
    return "Low"


def analyze_indicator(raw_indicator: str, selected_type: str = "Auto-detect") -> dict:
    """Full pipeline: clean -> detect type -> extract features -> score
    -> (optionally) re-band priority using calibrated thresholds."""
    model = load_model()

    cleaned = clean_indicator_string(raw_indicator)
    indicator_type = infer_type_if_needed(cleaned, selected_type)
    features = extract_features(cleaned, indicator_type)
    result = score_indicator(cleaned, indicator_type, features)

    calibrated_priority = _apply_calibrated_priority(
        result["risk_score"], model.get("calibrated_thresholds")
    )
    if calibrated_priority:
        result["priority"] = calibrated_priority

    result["model_version"] = model.get("model_version", "untrained")
    return result
