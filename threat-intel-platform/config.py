"""
config.py
----------
Central configuration for the AI-Powered Threat Intelligence Platform.
Keeping all paths and settings here means every other file (app.py,
database/database.py, ml/*.py) can import from one place instead of
hardcoding paths, which avoids inconsistencies between phases.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
    DEBUG = True

    # Paths
    DATA_DIR = os.path.join(BASE_DIR, "data")
    RAW_DATA_DIR = os.path.join(DATA_DIR, "raw")
    PROCESSED_DATA_DIR = os.path.join(DATA_DIR, "processed")
    DATASET_PATH = os.path.join(DATA_DIR, "threat_data.csv")

    MODELS_DIR = os.path.join(BASE_DIR, "models")
    MODEL_PATH = os.path.join(MODELS_DIR, "threat_model.pkl")

    DATABASE_PATH = os.path.join(BASE_DIR, "database", "threat_intel.db")

    # Threat prioritization thresholds (Phase 6 will use these)
    PRIORITY_THRESHOLDS = {
        "critical": 75,
        "high": 50,
        "medium": 25,
    }
