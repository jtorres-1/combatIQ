# app.py — CombatIQ Fight Predictor + Betting Mode + User History + Free/Pro Paywall System + Stripe
from datetime import datetime, date, timedelta
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, abort
from openai import OpenAI
import os, re, json, random, sys, logging, sqlite3
from dotenv import load_dotenv
from fighter_scraper import scrape_fighter_stats
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
import google.auth.transport.requests
import stripe

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
    if not num or num < 100 or num > 250:
        return fallback
    return num

# ---------------------------
# Load environment
# ---------------------------
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")
app.config["PERMANENT_SESSION_LIFETIME"] = 2592000  # 30 days in seconds
app.permanent_session_lifetime = 2592000

if os.getenv("FLASK_ENV") == "production":
    app.config["SESSION_COOKIE_SAMESITE"] = "None"
    app.config["SESSION_COOKIE_SECURE"] = True
else:
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = False

GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "https://combatiq.app/auth/callback")

# ---------------------------
# Stripe Setup
# ---------------------------
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PUBLIC_KEY = os.getenv("STRIPE_PUBLIC_KEY")
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID")
DOMAIN = os.getenv("DOMAIN", "http://127.0.0.1:5050")

# ---------------------------
# Init Limiter + Logging
# ---------------------------
# limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])
logging.basicConfig(filename="usage.log", level=logging.INFO, format="%(asctime)s %(message)s")

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
# GOOGLE OAUTH LOGIN SYSTEM
# =====================================================

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_SECRET_PATH = os.getenv("GOOGLE_CLIENT_SECRET_PATH", "client_secret.json")

def build_flow():
    return Flow.from_client_secrets_file(
        GOOGLE_SECRET_PATH,
        scopes=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
        ],
        redirect_uri=GOOGLE_REDIRECT_URI,
    )

@app.route("/login")
def login():
    flow = build_flow()
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/auth/callback")
def callback():
    flow = build_flow()

    if "state" not in session or session["state"] != request.args.get("state"):
        return "Invalid state parameter", 400

    flow.fetch_token(authorization_response=request.url)

    request_session = google.auth.transport.requests.Request()
    credentials = flow.credentials

    id_info = id_token.verify_oauth2_token(
        credentials.id_token,
        request_session,
        GOOGLE_CLIENT_ID
    )

    session["user"] = id_info

    # Save user in DB if not exists
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "INSERT OR IGNORE INTO users (email, name, picture) VALUES (?, ?, ?)",
            (id_info.get("email"), id_info.get("name"), id_info.get("picture")),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB ERROR] Failed to insert user: {e}")

    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# =====================================================
# FIXED PAYWALL HELPER - NULL-SAFE + CLEANER LOGIC
# =====================================================
def can_user_predict(email, fighter1=None, fighter2=None):
    """
    Returns (allowed: bool, user_id: int|None, plan: str)
    - allowed=True means user can proceed with prediction
    - user_id is needed for DB logging after generation
    - plan indicates 'pro' or 'free'
    
    NEW: If fighter1 and fighter2 are provided, checks if THIS specific matchup
    was already generated today. Allows refreshes of the same matchup.
    """
    if not email:
        return False, None, "none"

    conn = None
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id, plan FROM users WHERE email=?", (email,))
        row = c.fetchone()

        if not row:
            return False, None, "none"

        user_id = row["id"]
        plan = row["plan"] if row["plan"] else "free"

        # Pro users always allowed
        if plan == "pro":
            return True, user_id, plan

        # Free users: check if THIS specific matchup exists today
        today_start = datetime.combine(date.today(), datetime.min.time())
        
        if fighter1 and fighter2:
            # Normalize fighter names for comparison
            f1_lower = fighter1.lower().strip()
            f2_lower = fighter2.lower().strip()
            
            # Check if this exact matchup (either direction) was generated today
            c.execute(
                """
                SELECT COUNT(*) FROM predictions 
                WHERE user_id=? 
                AND created_at >= ? 
                AND (
                    (LOWER(TRIM(fighter1))=? AND LOWER(TRIM(fighter2))=?) OR 
                    (LOWER(TRIM(fighter1))=? AND LOWER(TRIM(fighter2))=?)
                )
                """,
                (user_id, today_start, f1_lower, f2_lower, f2_lower, f1_lower)
            )
            result = c.fetchone()
            matchup_exists = (result[0] if result else 0) > 0
            
            if matchup_exists:
                # They already generated this matchup today - allow refresh
                print(f"[MATCHUP EXISTS] Allowing refresh for {fighter1} vs {fighter2}")
                return True, user_id, plan
        
        # Count UNIQUE matchups today (case-insensitive)
        c.execute(
            """
            SELECT COUNT(DISTINCT LOWER(TRIM(fighter1)) || ' vs ' || LOWER(TRIM(fighter2))) 
            FROM predictions 
            WHERE user_id=? AND created_at >= ?
            """,
            (user_id, today_start)
        )
        result = c.fetchone()
        unique_matchups = result[0] if result else 0

        # Free tier: 1 unique matchup per day
        allowed = unique_matchups < 1
        
        if not allowed:
            print(f"[LIMIT] User has {unique_matchups} unique matchup(s) today")
        
        return allowed, user_id, plan

    except Exception as e:
        print(f"[ERROR] can_user_predict failed: {e}")
        return False, None, "error"
    finally:
        if conn:
            conn.close()

# =====================================================
# FIXED PREDICTION LOGGING - SINGLE CALL, NO DUPLICATES
# =====================================================
def log_prediction(user_id, mode, fighter1, fighter2, result, confidence):
    """
    Logs a prediction to the database.
    Only called ONCE per new prediction generation.
    """
    if not user_id:
        return

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute(
            """
            INSERT INTO predictions (user_id, mode, fighter1, fighter2, result, confidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, mode, fighter1, fighter2, result, confidence, datetime.now()),
        )
        conn.commit()
        conn.close()
        print(f"[DB LOG] Prediction logged for user_id={user_id}, mode={mode}")
    except Exception as e:
        print(f"[DB ERROR] Failed to log prediction: {e}")

# =====================================================
# HOME — Fight Prediction Mode
# =====================================================
@app.route("/", methods=["GET", "POST"])
def index():
    user = session.get("user")

    result = None
    fighter1 = fighter2 = ""
    stats1 = stats2 = {}
    confidence = None
    height1_pct = height2_pct = reach1_pct = reach2_pct = 50

    # =====================================================
    # Handle GET /?matchup=...
    # =====================================================
    if request.method == "GET" and request.args.get("matchup"):
        matchup = request.args.get("matchup", "").strip()
        fighters = [p.strip() for p in re.split(r"\s*vs\s*|\s*VS\s*|\s*Vs\s*", matchup) if p.strip()]
        if len(fighters) != 2:  # Changed from < 2 to != 2
            return render_template(
                "index.html",
                result="<p>Please enter matchup as 'Fighter A vs Fighter B'</p>",
                user=user
            )
        
        fighter1, fighter2 = fighters
        return run_prediction_flow(fighter1, fighter2, user, force_refresh=False)

    # =====================================================
    # Handle POST submission
    # =====================================================
    if request.method == "POST":
        matchup = request.form.get("matchup", "").strip()
        force_refresh = "force_refresh" in request.form

        fighters = [p.strip() for p in re.split(r"\s*vs\s*|\s*VS\s*|\s*Vs\s*", matchup) if p.strip()]
        if len(fighters) != 2:  # Changed from < 2 to != 2
            return render_template(
                "index.html",
                result="<p>Please enter matchup as 'Fighter A vs Fighter B'</p>",
                user=user
            )
        
        fighter1, fighter2 = fighters
        return run_prediction_flow(fighter1, fighter2, user, force_refresh)

    # =====================================================
    # Default render
    # =====================================================
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
        user=user,
    )

def clean_name(name):
    return re.sub(r"[^a-z0-9_]+", "", name.lower().replace(" ", "_"))

# =====================================================
# FIXED PREDICTION FLOW - CACHE FIRST, THEN LIMIT CHECK
# =====================================================
def run_prediction_flow(fighter1, fighter2, user, force_refresh=False):
    """
    CORRECT FLOW:
    1. Check cache FIRST (if not force_refresh)
    2. If cache hit → serve immediately, NO DB insert, NO usage increment
    3. If cache miss → check limit
    4. If limit exceeded → redirect to upgrade
    5. If allowed → generate prediction, cache it, log ONCE
    """
    matchup_key = f"{clean_name(fighter1)}_vs_{clean_name(fighter2)}.json"
    cache_path = os.path.join(CACHE_DIR, matchup_key)

    # =====================================================
    # ANONYMOUS USER HANDLING
    # =====================================================
    if not user:
        # Check if they've used their free anonymous prediction
        if session.get("anonymous_used"):
            # Already used - show signup gate
            return render_template(
                "signup_gate.html",
                fighter1=fighter1,
                fighter2=fighter2
            )
        else:
            # First visit - allow one prediction and mark as used
            session["anonymous_used"] = True
            print("[ANONYMOUS] First prediction allowed")
    
    # Continue with existing cache check...
    # =====================================================
    # STEP 1: CHECK CACHE FIRST (if not forcing refresh)
    # =====================================================
    if not force_refresh and os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Validate cache has required keys
            required_keys = ["fighter1", "fighter2", "stats1", "stats2", "result", "confidence"]
            if not all(k in data for k in required_keys):
                print(f"[CACHE INVALID] Missing keys in cache, regenerating")
                os.remove(cache_path)
            else:
                print(f"[CACHE HIT] Serving cached prediction for {fighter1} vs {fighter2}")
                # CRITICAL: Cached predictions do NOT increment usage
                # Just serve the data directly
                return render_template("index.html", **data, user=user)
        
        except (json.JSONDecodeError, IOError, KeyError) as e:
            print(f"[CACHE ERROR] Corrupted cache file, deleting: {e}")
            try:
                os.remove(cache_path)
            except:
                pass
        except Exception as e:
            print(f"[CACHE ERROR] Unexpected error loading cache: {e}")
            # Fall through to generation

    # =====================================================
    # STEP 2: CACHE MISS - CHECK IF USER CAN GENERATE NEW PREDICTION
    # =====================================================
    email = user.get("email") if user else None
    allowed, user_id, plan = can_user_predict(email, fighter1, fighter2)

    if not allowed:
        print(f"[LIMIT REACHED] User {email} hit free tier limit")
        return redirect(url_for("upgrade"))

    # =====================================================
    # STEP 3: GENERATE NEW PREDICTION
    # =====================================================
    print(f"[GENERATING] New prediction for {fighter1} vs {fighter2}")
    print(f"[DEBUG] About to scrape. fighter1={fighter1}, fighter2={fighter2}, user_email={user.get('email') if user else 'None'}")

    # Scrape stats with comprehensive fallback
    stats1 = {}
    stats2 = {}
    
    try:
        result = scrape_fighter_stats(fighter1, force_refresh=force_refresh)
        if result and isinstance(result, dict):
            stats1 = result
        else:
            print(f"[SCRAPER WARN] {fighter1} returned invalid data: {type(result)}")
    except Exception as e:
        print(f"[SCRAPER ERROR] Failed to scrape {fighter1}: {e}")

    try:
        result = scrape_fighter_stats(fighter2, force_refresh=force_refresh)
        if result and isinstance(result, dict):
            stats2 = result
        else:
            print(f"[SCRAPER WARN] {fighter2} returned invalid data: {type(result)}")
    except Exception as e:
        print(f"[SCRAPER ERROR] Failed to scrape {fighter2}: {e}")

    # Safe extraction with None guards
    h1 = safe_stat_value(stats1.get("height") if stats1 else None)
    h2 = safe_stat_value(stats2.get("height") if stats2 else None)
    r1 = safe_stat_value(stats1.get("reach") if stats1 else None)
    r2 = safe_stat_value(stats2.get("reach") if stats2 else None)

    def normalize_bar(a, b):
        max_val = max(a, b, 1)
        return (a / max_val) * 100, (b / max_val) * 100

    height1_pct, height2_pct = normalize_bar(h1, h2)
    reach1_pct, reach2_pct = normalize_bar(r1, r2)

    prompt = f"""
Analyze the fight between {fighter1} and {fighter2}.

Return BEAUTIFULLY FORMATTED HTML that displays cleanly inside a narrow content box.  
Use clear structure, spacing, and readable formatting.

Formatting rules:
- Use <h3> section headers using this style: <h3 class='section-title'>Title</h3>
- Use <p> for paragraphs, but keep paragraphs short (2 to 3 sentences).
- Add spacing between sections using: <div class='spacer'></div>
- Use bullet points (<ul><li>) where helpful.
- NO code blocks, no markdown.

Required sections:
1. <h3 class='section-title'>Striking</h3>
2. <h3 class='section-title'>Grappling</h3>
3. <h3 class='section-title'>Fight IQ</h3>
4. <h3 class='section-title'>Recent Form</h3>
5. <h3 class='section-title'>Prediction</h3>

Write clean, concise analysis with natural spacing.
"""

    try:
        response = client.chat.completions.create(
            model=GPT_MODEL,
            messages=[
                {"role": "system", "content": "You are an elite MMA analyst writing clear structured breakdowns."},
                {"role": "user", "content": prompt},
            ],
        )
        raw = response.choices[0].message.content
        result = raw.replace("```html", "").replace("```", "").strip()
        confidence = estimate_confidence(result)

    except Exception as e:
        print(f"[API ERROR] OpenAI call failed: {e}")
        result = "<p>Analysis unavailable. Showing stat based summary instead.</p>"
        confidence = 70

    # =====================================================
    # STEP 4: CACHE THE RESULT
    # =====================================================
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

    try:
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, indent=2, ensure_ascii=False)
        print(f"[CACHE SAVED] {cache_path}")
    except Exception as e:
        print(f"[CACHE ERROR] Failed to save cache: {e}")
        # Non-fatal, continue

    # =====================================================
    # STEP 5: LOG PREDICTION (ONLY ONCE, ONLY FOR NEW GENERATIONS)
    # =====================================================
    try:
        log_prediction(user_id, "fight", fighter1, fighter2, result, confidence)
    except Exception as e:
        print(f"[DB ERROR] Failed to log prediction (non-fatal): {e}")
        # Non-fatal, user already has their result

    return render_template("index.html", **cache_data, user=user)


# =====================================================
# BETTING MODE - FIXED WITH SAME PATTERN
# =====================================================
@app.route("/betting", methods=["GET", "POST"])
def betting():
    prediction = None
    fighter = stat = ""
    line = 0.0
    confidence = None
    user = session.get("user")
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
        # Require login
        if not user:
            return redirect(url_for("login"))

        # Check limit BEFORE processing
        email = user.get("email")
        # For betting mode, we don't have fighter names, so pass None
        allowed, user_id, plan = can_user_predict(email, None, None)

        if not allowed:
            return redirect(url_for("upgrade"))

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
                            {"role": "user", "content": prompt},
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
                    "timestamp": str(datetime.now()),
                })

                # Log to DB (only once per new generation)
                log_prediction(user_id, "betting", fighter, stat, pick, confidence)

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
        recent_predictions=recent_predictions,
        user=user,
    )

# =====================================================
# USER HISTORY PAGE
# =====================================================
@app.route("/history")
def history():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))

    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email=?", (user.get("email"),))
        row = c.fetchone()
        if not row:
            return render_template("history.html", predictions=[], user=user)
        user_id = row["id"]

        c.execute(
            "SELECT * FROM predictions WHERE user_id=? ORDER BY created_at DESC LIMIT 20",
            (user_id,),
        )
        predictions = c.fetchall()
        conn.close()
    except Exception as e:
        print(f"[DB ERROR] History fetch failed: {e}")
        predictions = []

    return render_template("history.html", predictions=predictions, user=user)

# =====================================================
# STRIPE CHECKOUT + UPGRADE FLOW
# =====================================================
@app.route("/upgrade")
def upgrade():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))

    # Fetch plan for display
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT plan FROM users WHERE email=?", (user.get("email"),))
        row = c.fetchone()
        plan = row["plan"] if row and row["plan"] else "free"
        conn.close()
    except Exception as e:
        print(f"[DB ERROR] Failed to fetch plan: {e}")
        plan = "free"

    return render_template(
        "upgrade.html",
        user=user,
        plan=plan,
        stripe_public_key=STRIPE_PUBLIC_KEY
    )

@app.route("/create-checkout-session", methods=["POST"])
def create_checkout_session():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))

    if not STRIPE_PRICE_ID or not stripe.api_key:
        return "Stripe is not configured correctly.", 500

    try:
        checkout_session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
            success_url=f"{DOMAIN}/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{DOMAIN}/cancel",
            customer_email=user.get("email"),
        )
        return redirect(checkout_session.url)
    except Exception as e:
        print(f"[STRIPE ERROR] Failed to create checkout session: {e}")
        return "Unable to start checkout session.", 500

@app.route("/success")
def success():
    user = session.get("user")
    session_id = request.args.get("session_id")

    if session_id and stripe.api_key:
        try:
            checkout_session = stripe.checkout.Session.retrieve(session_id)
            email = None
            if checkout_session and checkout_session.get("customer_details"):
                email = checkout_session["customer_details"].get("email")
            if not email and user:
                email = user.get("email")

            if email:
                conn = get_db()
                c = conn.cursor()
                c.execute("UPDATE users SET plan='pro' WHERE email=?", (email,))
                conn.commit()
                conn.close()
        except Exception as e:
            print(f"[STRIPE ERROR] Failed to mark user as pro: {e}")

    return render_template("success.html", user=user)

@app.route("/cancel")
def cancel():
    user = session.get("user")
    return render_template("cancel.html", user=user)

# =====================================================
# STRIPE WEBHOOK ENDPOINT
# =====================================================
@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")
    webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except ValueError:
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError:
        return "Invalid signature", 400

    if event["type"] == "checkout.session.completed":
        session_data = event["data"]["object"]

        email = (
            session_data.get("customer_email")
            or (session_data.get("customer_details") or {}).get("email")
        )

        if email:
            try:
                conn = get_db()
                c = conn.cursor()
                c.execute("UPDATE users SET plan='pro' WHERE email=?", (email,))
                conn.commit()
                conn.close()
                print(f"[WEBHOOK] User {email} upgraded to Pro.")
            except Exception as e:
                print(f"[DB ERROR] Failed to upgrade user: {e}")

    return "Success", 200

# =====================================================
# RUN APP
# =====================================================
if __name__ == "__main__":
    port = 5050
    if len(sys.argv) > 2 and sys.argv[1] == "--port":
        port = int(sys.argv[2])
    app.run(host="0.0.0.0", port=port, debug=True)
