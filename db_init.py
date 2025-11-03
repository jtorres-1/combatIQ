# db_init.py — CombatIQ Database Initialization
import sqlite3
import os

# === Absolute path to DB (avoids duplicate DBs across directories) ===
db_path = os.path.join(os.path.dirname(__file__), "combatiq.db")

conn = sqlite3.connect(db_path)
c = conn.cursor()

# =====================================================
# USERS TABLE
# =====================================================
c.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    name TEXT,
    picture TEXT,
    plan TEXT DEFAULT 'free',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

# =====================================================
# PREDICTIONS TABLE
# =====================================================
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

# =====================================================
# FUTURE EXTENSIONS (OPTIONAL)
# =====================================================
# You can add more tables later here, such as:
# - user_sessions (track login activity)
# - subscription_payments (for premium tiers)
# - recent_activity (log user behavior in app)

conn.commit()
conn.close()

print(f"✅ Database initialized successfully at: {db_path}")
