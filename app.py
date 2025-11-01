# app.py — CombatIQ Fight Predictor + Betting Mode (UFCStats + Tapology Enhanced + SQLite Integration)
from flask import Flask, render_template, request, jsonify
from openai import OpenAI
import os, re, json, random, sys, logging, sqlite3
from datetime import datetime
from dotenv import load_dotenv
from fighter_scraper import scrape_fighter_stats
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ---------------------------
# Confidence scoring heuristic
# ---------------------------
def estimate_confidence(report_text):
    """Quick heuristic to give users a confidence score (70–95%)"""
    keywords = ["dominant", "clear advantage", "superior", "unanimous", "KO", "submission"]
    base = 70
    bonus = sum(5 for word in keywords if word in report_text.lower())
    noise = random.randint(-3, 3)
    return max(65, min(base + bonus + noise, 95))

# ---------------------------
# Stat parsing helpers
# ---------------------------
def parse_numeric(value):
    """Extract numeric inches/cm from mixed strings like 5'11" (180cm)."""
    if not value or value == "N/A":
        return None
    value = value.strip()
    match_cm = re.search(r"(\d+)\s*cm", value)
    if match_cm:
        return int(match_cm.group(1))
    match_ft_in = re.search(r"(\d+)'(\d+)", value)
    if match_ft_in:
        ft, inch = int(match_ft_in.group(1)), int(match_ft_in.group(2))
        return round(ft * 30.48 + inch * 2.54)
    match_in = re.search(r"(\d+)\s*in", value)
    if match_in:
        return round(int(match_in.group(1)) * 2.54)
    match_num = re.search(r"(\d+)", value)
    return int(match_num.group(1)) if match_num else None

def safe_stat_value(stat, fallback=175):
    """Fallback for invalid or missing numeric stats."""
    num = parse_numeric(stat)
    if not num or num < 100 or num > 250:  # sanity check for heights/reach
        return fallback
    return num

# ---------------------------
# Load environment
# ---------------------------
load_dotenv()
app = Flask(__name__)

# ---------------------------
# Init Limiter + Logging
# ---------------------------
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])
logging.basicConfig(filename='usage.log', level=logging.INFO, format='%(asctime)s %(message)s')

# ---------------------------
# Init OpenAI Client
# ---------------------------
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
GPT_MODEL = "gpt-4o-mini"

CACHE_DIR = "matchups_cache"
os.makedirs(CACHE_DIR, exist_ok=True)

# ---------------------------
# Database connection
# ---------------------------
def get_db():
    conn = sqlite3.connect("combatiq.db")
    conn.row_factory = sqlite3.Row
    return conn

# =====================================================
# HOME — Fight Prediction Mode
# =====================================================
@app.route("/", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def index():
    result = None
    fighter1 = fighter2 = ""
    stats1 = stats2 = {}
    confidence = None
    height1_pct = height2_pct = reach1_pct = reach2_pct = 50

    if request.method == "POST":
        matchup = request.form.get("matchup", "").strip()
        force_refresh = "force_refresh" in request.form

        # Fixed flexible splitting for "vs" detection
        fighters = [p.strip() for p in re.split(r"\s*vs\s*|\s*VS\s*|\s*Vs\s*", matchup) if p.strip()]
        if len(fighters) < 2:
            return render_template("index.html", result="<p>Please enter matchup as 'Fighter A vs Fighter B'</p>")

        fighter1, fighter2 = fighters[0], fighters[1]
        print(f"[DEBUG] Parsed fighters: {fighter1} vs {fighter2}")
        matchup_key = f"{fighter1.lower().replace(' ', '_')}_vs_{fighter2.lower().replace(' ', '_')}.json"
        cache_path = os.path.join(CACHE_DIR, matchup_key)

        logging.info(f"Request from {request.remote_addr} for matchup: {matchup}")

        # --- Cache Load ---
        if not force_refresh and os.path.exists(cache_path):
            with open(cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return render_template("index.html", **data)

        # --- Fresh Scrape ---
        print(f"[SCRAPE] Fetching stats for {fighter1} and {fighter2}")
        stats1 = scrape_fighter_stats(fighter1, force_refresh=force_refresh)
        stats2 = scrape_fighter_stats(fighter2, force_refresh=force_refresh)

        h1 = safe_stat_value(stats1.get("height"))
        h2 = safe_stat_value(stats2.get("height"))
        r1 = safe_stat_value(stats1.get("reach"))
        r2 = safe_stat_value(stats2.get("reach"))

        def normalize_bar(stat1, stat2):
            max_val = max(stat1, stat2, 1)
            return (stat1 / max_val) * 100, (stat2 / max_val) * 100

        height1_pct, height2_pct = normalize_bar(h1, h2)
        reach1_pct, reach2_pct = normalize_bar(r1, r2)

        # --- GPT Fight Report ---
        summary = f"Fighter 1 - {fighter1}: {stats1}\n\nFighter 2 - {fighter2}: {stats2}\n\n"
        prompt = (
            f"Analyze the fight between {fighter1} and {fighter2}. "
            "Predict the most likely winner and explain using striking, grappling, fight IQ, and current form. "
            "Base it only on reliable fight data — no fantasy scenarios. "
            "Return a clean HTML response using <h3>, <h4>, <p>, and <strong> tags."
        )

        try:
            response = client.chat.completions.create(
                model=GPT_MODEL,
                messages=[
                    {"role": "system", "content": "You are an elite MMA analyst."},
                    {"role": "user", "content": prompt + "\n\n" + summary},
                ],
            )
            raw_result = response.choices[0].message.content
            result = raw_result.replace("```html", "").replace("```", "").strip()
            confidence = estimate_confidence(result)
        except Exception as e:
            print(f"[ERROR] GPT request failed: {e}")
            result = "<p>Unable to generate analysis. Using stat-based fallback.</p>"
            confidence = 70

        # --- Save Matchup Cache ---
        cache_data = {
            "fighter1": fighter1,
            "fighter2": fighter2,
            "stats1": stats1,
            "stats2": stats2,
            "result": result,
            "confidence": confidence,
            "height1_pct": height1_pct,
            "height2_pct": height2_pct,
            "reach1_pct": reach1_pct,
            "reach2_pct": reach2_pct,
        }
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, indent=2, ensure_ascii=False)

        # --- Save to Database ---
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute(
                "INSERT INTO predictions (mode, fighter1, fighter2, result, confidence) VALUES (?, ?, ?, ?, ?)",
                ("fight", fighter1, fighter2, result, confidence)
            )
            conn.commit()
            conn.close()
            print(f"[DB] Logged fight: {fighter1} vs {fighter2} ({confidence}%)")
        except Exception as e:
            print(f"[DB ERROR] Failed to log prediction: {e}")

    return render_template(
        "index.html",
        result=result,
        fighter1=fighter1,
        fighter2=fighter2,
        stats1=stats1,
        stats2=stats2,
        confidence=confidence,
        height1_pct=height1_pct,
        height2_pct=height2_pct,
        reach1_pct=reach1_pct,
        reach2_pct=reach2_pct,
    )

# =====================================================
# Fighter Stats Page
# =====================================================
@app.route("/fighter/<name>")
@limiter.limit("10 per minute")
def fighter_profile(name):
    stats = scrape_fighter_stats(name, force_refresh=False)
    return render_template("fighter_profile.html", fighter=name, stats=stats)

# =====================================================
# Fighter Stats API (JSON)
# =====================================================
@app.route("/api/fighter/<name>")
@limiter.limit("10 per minute")
def api_fighter(name):
    stats = scrape_fighter_stats(name, force_refresh=False)
    return jsonify(stats)

# =====================================================
# Betting Mode
# =====================================================
@app.route("/betting", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def betting():
    prediction = None
    fighter = stat = ""
    line = 0.0
    confidence = None
    RECENT_PATH = "recent_predictions.json"

    STAT_MAP = {
        "sig strikes": ["avg_sig_strikes", "sig_strikes_per_min"],
        "takedowns": ["avg_takedowns", "takedown_avg"],
        "striking accuracy": ["striking_accuracy"],
        "takedown accuracy": ["takedown_accuracy"],
        "submissions": ["avg_submissions", "submissions_avg"],
    }

    def save_recent(entry):
        try:
            recent = []
            if os.path.exists(RECENT_PATH):
                with open(RECENT_PATH, "r", encoding="utf-8") as f:
                    recent = json.load(f)
            recent.insert(0, entry)
            with open(RECENT_PATH, "w", encoding="utf-8") as f:
                json.dump(recent[:5], f, indent=2)
        except Exception as e:
            print("[WARN] Failed to save recent prediction:", e)

    if request.method == "POST":
        fighter = request.form.get("fighter", "").strip()
        stat = request.form.get("stat", "").lower().strip()
        try:
            line = float(request.form.get("line", "0"))
        except ValueError:
            line = 0.0

        if not fighter or not stat:
            prediction = "Please enter both a fighter and a stat type."
        else:
            fighter_file = os.path.join("fighters_cache", f"{fighter.lower().replace(' ', '_')}.json")
            if os.path.exists(fighter_file):
                with open(fighter_file, "r", encoding="utf-8") as f:
                    fighter_data = json.load(f)
            else:
                fighter_data = scrape_fighter_stats(fighter)

            avg_value = None
            for possible_key in STAT_MAP.get(stat, []):
                if possible_key in fighter_data:
                    try:
                        avg_value = float(fighter_data[possible_key])
                        break
                    except ValueError:
                        continue

            if avg_value is None:
                prediction = f"No data available for {stat} on {fighter}."
                confidence = 0
            else:
                diff = avg_value - line
                pick = "Over" if diff >= 0 else "Under"
                confidence = round(max(40, 95 - abs(diff) * 8 + random.uniform(-3, 3)), 2)

                try:
                    prompt = f"""
                    Fighter: {fighter}
                    Stat: {stat}
                    Average from dataset: {avg_value}
                    Line to beat: {line}
                    Write a concise MMA betting pick summary explaining Over/Under choice.
                    """
                    response = client.chat.completions.create(
                        model=GPT_MODEL,
                        messages=[
                            {"role": "system", "content": "You are an MMA betting analyst writing concise predictions."},
                            {"role": "user", "content": prompt}
                        ],
                    )
                    breakdown = response.choices[0].message.content.strip()
                    breakdown = breakdown.replace("```html", "").replace("```", "").strip()
                except Exception:
                    breakdown = f"<p>{fighter} averages {avg_value} {stat} per fight. Suggestion: <strong>{pick}</strong>.</p>"

                prediction = f"""
                <p><strong>{fighter}</strong> averages <strong>{avg_value:.2f} {stat}</strong> per fight.</p>
                <p>Line: <strong>{line}</strong></p>
                <p>Projected Pick: <strong style='color:gold;'>{pick}</strong></p>
                {breakdown}
                """

                save_recent({
                    "fighter": fighter,
                    "stat": stat,
                    "line": line,
                    "prediction": pick,
                    "confidence": confidence,
                    "timestamp": str(datetime.now())
                })

    recent_predictions = []
    if os.path.exists(RECENT_PATH):
        with open(RECENT_PATH, "r", encoding="utf-8") as f:
            recent_predictions = json.load(f)

    return render_template(
        "betting.html",
        prediction=prediction,
        fighter=fighter,
        stat=stat,
        line=line,
        confidence=confidence,
        recent_predictions=recent_predictions
    )

# =====================================================
# Run App
# =====================================================
if __name__ == "__main__":
    port = 5050
    if len(sys.argv) > 2 and sys.argv[1] == "--port":
        port = int(sys.argv[2])
    app.run(host="0.0.0.0", port=port, debug=False)
