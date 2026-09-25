"""
database.py
-------------
Lightweight SQLite persistence layer for the Threat Intelligence
Platform. Handles:
  - Initial load of data/threat_data.csv into a local SQLite DB
  - Insertion of new indicators analyzed via the Threat Analysis page
  - Filtered/sorted queries used by the dashboard and database pages

SQLite is used (over a heavier DB) because it's zero-config and file
based, appropriate for a student project and for Streamlit Community
Cloud deployment.
"""

import os
import sqlite3

import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "threat_intel.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    risk_score REAL NOT NULL,
    priority TEXT NOT NULL,
    confidence REAL NOT NULL,
    source TEXT,
    timestamp TEXT NOT NULL,
    status TEXT,
    explanation TEXT,
    recommended_action TEXT
);
"""


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute(SCHEMA)
    return conn


def is_empty() -> bool:
    if not os.path.exists(DB_PATH):
        return True
    conn = get_connection()
    count = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    conn.close()
    return count == 0


def seed_from_csv(csv_path: str) -> int:
    """Populate the database from the historical CSV dataset. Only runs
    if the table is currently empty (idempotent on repeated app runs)."""
    if not is_empty():
        return 0

    df = pd.read_csv(csv_path)
    df["explanation"] = "Historical record imported from dataset."
    df["recommended_action"] = "See Threat Analysis for a fresh assessment if needed."

    conn = get_connection()
    df[
        [
            "indicator", "indicator_type", "threat_type", "risk_score",
            "priority", "confidence", "source", "timestamp", "status",
            "explanation", "recommended_action",
        ]
    ].to_sql("threats", conn, if_exists="append", index=False)
    conn.close()
    return len(df)


def insert_threat(record: dict) -> None:
    conn = get_connection()
    conn.execute(
        """INSERT INTO threats
           (indicator, indicator_type, threat_type, risk_score, priority,
            confidence, source, timestamp, status, explanation, recommended_action)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            record["indicator"],
            record["indicator_type"],
            record["threat_type"],
            record["risk_score"],
            record["priority"],
            record["confidence"],
            record.get("source", "Manual Analysis"),
            record.get("timestamp"),
            record.get("status", "Active"),
            record.get("explanation", ""),
            record.get("recommended_action", ""),
        ),
    )
    conn.commit()
    conn.close()


def fetch_all() -> pd.DataFrame:
    conn = get_connection()
    df = pd.read_sql_query("SELECT * FROM threats", conn)
    conn.close()
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


def fetch_filtered(
    priority=None, threat_type=None, indicator_type=None,
    source=None, start_date=None, end_date=None,
) -> pd.DataFrame:
    df = fetch_all()
    if df.empty:
        return df

    if priority and "All" not in priority:
        df = df[df["priority"].isin(priority)]
    if threat_type and "All" not in threat_type:
        df = df[df["threat_type"].isin(threat_type)]
    if indicator_type and "All" not in indicator_type:
        df = df[df["indicator_type"].isin(indicator_type)]
    if source and "All" not in source:
        df = df[df["source"].isin(source)]
    if start_date is not None:
        df = df[df["timestamp"] >= pd.Timestamp(start_date)]
    if end_date is not None:
        df = df[df["timestamp"] <= pd.Timestamp(end_date)]

    return df.reset_index(drop=True)
