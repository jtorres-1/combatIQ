# db_init.py — CombatIQ Database Initialization
import sqlite3
import os

# Always use absolute path to prevent duplicate DBs in different directories
db_path = os.path.join(os.path.dirname(__file__), "combatiq.db")

conn = sqlite3.connect(db_path)
c = conn.cursor()

# === USERS TABLE ===
c.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    plan TEXT DEFAULT 'free',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

# === PREDICTIONS TABLE ===
c.execute("""
CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    mode TEXT,
    fighter1 TEXT,
    fighter2 TEXT,
    result TEXT,
    confidence REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
)
""")

conn.commit()
conn.close()

print(f"✅ Database initialized successfully at: {db_path}")
