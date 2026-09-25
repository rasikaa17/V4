"""
preprocessing.py
------------------
Cleaning and validation utilities used both when loading the
historical dataset (data/threat_data.csv) and when a user submits a
new indicator through the Threat Analysis page.
"""

import re

import pandas as pd

from ml.feature_engineering import detect_indicator_type

REQUIRED_COLUMNS = [
    "indicator", "indicator_type", "threat_type", "risk_score",
    "priority", "confidence", "source", "timestamp", "status",
]


def clean_indicator_string(raw: str) -> str:
    """Trim whitespace and strip protocol prefixes so 'https://foo.com/x'
    and 'foo.com' are treated consistently."""
    value = raw.strip()
    value = re.sub(r"^https?://", "", value, flags=re.IGNORECASE)
    value = value.rstrip("/")
    return value


def validate_indicator(raw: str) -> tuple[bool, str]:
    """Return (is_valid, message). Rejects empty input; everything else
    is treated as a potential URL/domain if it doesn't match IP/hash
    patterns, since domains have very few hard format constraints."""
    if not raw or not raw.strip():
        return False, "Indicator cannot be empty."
    if len(raw.strip()) > 512:
        return False, "Indicator is too long to be a valid IP, domain, or hash."
    return True, ""


def load_dataset(csv_path: str) -> pd.DataFrame:
    """Load and clean the historical threat dataset for the dashboard."""
    df = pd.read_csv(csv_path)

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing required columns: {missing}")

    df = df.drop_duplicates(subset=["indicator", "timestamp"])
    df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce").fillna(0).clip(0, 100)
    df["confidence"] = pd.to_numeric(df["confidence"], errors="coerce").fillna(50).clip(0, 100)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])

    for col in ["priority", "threat_type", "indicator_type", "source", "status"]:
        df[col] = df[col].fillna("Unknown").astype(str)

    return df.reset_index(drop=True)


def infer_type_if_needed(raw: str, selected_type: str | None) -> str:
    """If the user didn't pick an indicator type explicitly, infer it."""
    if selected_type and selected_type != "Auto-detect":
        return selected_type
    return detect_indicator_type(raw)
