import sqlite3
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent
DB_DIR = BASE_DIR / "database"
DB_DIR.mkdir(exist_ok=True)

DB_PATH = DB_DIR / "scan_history.db"


def initialize_database():
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_text TEXT,
            scan_type TEXT,
            risk_score REAL,
            classification TEXT,
            scan_date TEXT
        )
    """)

    connection.commit()
    connection.close()


def save_scan(text, scan_type, risk_score, classification):
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO scans
        (scanned_text, scan_type, risk_score, classification, scan_date)
        VALUES (?, ?, ?, ?, ?)
    """, (
        text,
        scan_type,
        risk_score,
        classification,
        datetime.now().isoformat()
    ))

    connection.commit()
    connection.close()


def get_scan_history():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY id DESC")

    results = [dict(row) for row in cursor.fetchall()]

    connection.close()
    return results


def delete_scan(scan_id: int) -> bool:
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    connection.commit()
    deleted = cursor.rowcount > 0
    connection.close()
    return deleted


def clear_scan_history():
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    cursor.execute("DELETE FROM scans")
    connection.commit()
    connection.close()
