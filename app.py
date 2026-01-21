# app.py — CombatIQ Fight Predictor + Betting Mode + User History + Free/Pro Paywall System + Stripe
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, abort
from openai import OpenAI
import os, re, json, random, sys, logging, sqlite3
from datetime import datetime, date
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

app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True


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
DB_PATH = os.path.join(os.path.dirname(__file__), "combatiq.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
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
# PAYWALL HELPER FUNCTION 1 prediction free dail
# =====================================================
def check_user_limit(email):
    """Check if a free user has exceeded 3 predictions today."""
    if not email:
        return False, "login_required"

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, plan FROM users WHERE email=?", (email,))
    row = c.fetchone()
    if not row:
        conn.close()
        return False, "no_user"

    user_id = row["id"]
    plan = row["plan"]

    # Pro users always pass
    if plan == "pro":
        conn.close()
        return True, "pro"

    # Count today's predictions
    today_start = date.today().isoformat()

    c.execute(
        "SELECT COUNT(*) FROM predictions WHERE user_id=? AND DATE(created_at)=?",
        (user_id, today_start),
    )

    count = c.fetchone()[0]
    conn.close()

    if count >= 1:
        return False, "limit_reached"
    return True, "ok"

# =====================================================
# HOME — Fight Prediction Mode
# =====================================================
@app.route("/", methods=["GET", "POST"])
# @limiter.limit("2 per minute", methods=["POST"])

def index():
    user = session.get("user")

    result = None
    fighter1 = fighter2 = ""
    stats1 = stats2 = {}
    confidence = None
    height1_pct = height2_pct = reach1_pct = reach2_pct = 50

    # =====================================================
    # 1. Handle GET /?matchup=...
    # =====================================================
    if request.method == "GET" and request.args.get("matchup"):
        matchup = request.args.get("matchup", "").strip()

        

        if not matchup:
            return render_template(
                "index.html",
                result="<p>Please enter a matchup.</p>",
                fighter1="",
                fighter2="",
                stats1={},
                stats2={},
                confidence=None,
                height1_pct=50,
                height2_pct=50,
                reach1_pct=50,
                reach2_pct=50,
                user=user,
            )



        fighters = [p.strip() for p in re.split(r"\s*vs\s*|\s*VS\s*|\s*Vs\s*", matchup) if p.strip()]
        if len(fighters) < 2:
            return render_template(
                "index.html",
                result="<p>Please enter matchup as 'Fighter A vs Fighter B'</p>",
                fighter1="",
                fighter2="",
                user=user
            )

        fighter1, fighter2 = fighters

        # Directly run prediction flow# GET should only prefill the form, NOT run prediction
    return render_template(
        "index.html",
        fighter1=fighter1,
        fighter2=fighter2,
        user=user
    )



    # =====================================================
    # 2. Handle POST submission
    # =====================================================
    if request.method == "POST":
        try:
            # Require login
            if not user:
                return redirect(url_for("login"))
    
            allowed, reason = check_user_limit(user["email"])
            if not allowed and reason == "limit_reached":
                return render_template(
                    "index.html",
                    result="LIMIT HIT",
                    fighter1="",
                    fighter2="",
                    stats1={},
                    stats2={},
                    confidence=None,
                    height1_pct=50,
                    height2_pct=50,
                    reach1_pct=50,
                    reach2_pct=50,
                    user=user,
                )
    
            matchup = request.form.get("matchup", "")
            matchup = matchup.strip()
    
            if not matchup:
                return render_template(
                    "index.html",
                    result="EMPTY MATCHUP",
                    fighter1="",
                    fighter2="",
                    stats1={},
                    stats2={},
                    confidence=None,
                    height1_pct=50,
                    height2_pct=50,
                    reach1_pct=50,
                    reach2_pct=50,
                    user=user,
                )
    
            fighters = [p.strip() for p in re.split(r"\s*vs\s*", matchup) if p.strip()]
            if len(fighters) < 2:
                return render_template(
                    "index.html",
                    result="BAD FORMAT",
                    fighter1="",
                    fighter2="",
                    stats1={},
                    stats2={},
                    confidence=None,
                    height1_pct=50,
                    height2_pct=50,
                    reach1_pct=50,
                    reach2_pct=50,
                    user=user,
                )
    
            fighter1, fighter2 = fighters
            return run_prediction_flow(fighter1, fighter2, user)
    
        except Exception as e:
            import traceback
            print("POST ROUTE CRASH")
            print(traceback.format_exc())
            return "POST CRASH", 500


        fighters = [p.strip() for p in re.split(r"\s*vs\s*|\s*VS\s*|\s*Vs\s*", matchup) if p.strip()]
        if len(fighters) < 2:
            return render_template(
                "index.html",
                result="<p>Please enter matchup as 'Fighter A vs Fighter B'</p>",
                fighter1="",
                fighter2="",
                user=user
            )

        fighter1, fighter2 = fighters

        # Use same prediction flow
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

def run_prediction_flow(fighter1, fighter2, user, force_refresh=False):
    matchup_key = f"{clean_name(fighter1)}_vs_{clean_name(fighter2)}.json"

    cache_path = os.path.join(CACHE_DIR, matchup_key)

    # Use cache if available
    if not force_refresh and os.path.exists(cache_path):
        with open(cache_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    
        # log prediction
        try:
            conn = get_db()
            c = conn.cursor()
    
            user_id = None
            if user:
                c.execute("SELECT id FROM users WHERE email=?", (user["email"],))
                row = c.fetchone()
                if row:
                    user_id = row["id"]
    
            c.execute(
                """
                INSERT INTO predictions
                (user_id, mode, fighter1, fighter2, result, confidence, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    "fight",
                    fighter1,
                    fighter2,
                    data.get("result"),
                    data.get("confidence"),
                    datetime.now(),
                )
            )
    
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[DB ERROR] Failed to log fight prediction: {e}")
    
        return render_template(
            "index.html",
            fighter1=data.get("fighter1", ""),
            fighter2=data.get("fighter2", ""),
            stats1=data.get("stats1", {}),
            stats2=data.get("stats2", {}),
            result=data.get("result"),
            confidence=data.get("confidence"),
            height1_pct=data.get("height1_pct", 50),
            height2_pct=data.get("height2_pct", 50),
            reach1_pct=data.get("reach1_pct", 50),
            reach2_pct=data.get("reach2_pct", 50),
            user=user,
        )
    
    

    # Scrape stats
    stats1 = scrape_fighter_stats(fighter1, force_refresh=force_refresh)
    stats2 = scrape_fighter_stats(fighter2, force_refresh=force_refresh)

    stats1 = stats1 if isinstance(stats1, dict) else {}
    stats2 = stats2 if isinstance(stats2, dict) else {}


    h1 = safe_stat_value(stats1.get("height"))
    h2 = safe_stat_value(stats2.get("height"))
    r1 = safe_stat_value(stats1.get("reach"))
    r2 = safe_stat_value(stats2.get("reach"))

    def normalize_bar(a, b):
        max_val = max(a, b, 1)
        return (a / max_val) * 100, (b / max_val) * 100

    height1_pct, height2_pct = normalize_bar(h1, h2)
    reach1_pct, reach2_pct = normalize_bar(r1, r2)

    # Better structured formatting prompt
    prompt = f"""
Analyze the fight between {fighter1} and {fighter2}.

Return BEAUTIFULLY FORMATTED HTML that displays cleanly inside a narrow content box.  
Use clear structure, spacing, and readable formatting.

Formatting rules:
• Use <h3> section headers using this style: <h3 class='section-title'>Title</h3>
• Use <p> for paragraphs, but keep paragraphs short (2 to 3 sentences).
• Add spacing between sections using: <div class='spacer'></div>
• Use bullet points (<ul><li>) where helpful.
• NO code blocks, no markdown.

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
        result = "<p>Analysis unavailable. Showing stat based summary instead.</p>"
        confidence = 70

    # Cache save
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

    return render_template("index.html", **cache_data, user=user)


# =====================================================
# BETTING MODE
# =====================================================
@app.route("/betting", methods=["GET", "POST"])
# @limiter.limit("5 per minute")
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
        # --- Paywall enforcement ---
        if user:
            allowed, reason = check_user_limit(user["email"])
            if not allowed and reason == "limit_reached":
                upgrade_message = """
                <div style='text-align:center; padding:16px;'>
                  <p style='color:#facc15; font-weight:700; font-size:18px;'>
                    You’ve used your free prediction for today
                  </p>
                  <p style='color:#d1d5db; margin-top:8px;'>
                    CombatIQ Pro unlocks <strong>unlimited fight predictions</strong> and
                    <strong>unlimited betting stat analysis</strong>.
                  </p>
                  <p style='color:#9ca3af; margin-top:6px; font-size:14px;'>
                    Built for bettors who don’t guess.
                  </p>
                  <a href='/upgrade'
                     style='display:inline-block; margin-top:14px; background:#facc15;
                            color:black; padding:10px 18px; border-radius:8px;
                            font-weight:700; text-decoration:none;'>
                     Unlock Pro for $9.99/month
                  </a>
                </div>
                """

                return render_template("betting.html", prediction=upgrade_message, user=user)
        else:
            return redirect(url_for("login"))

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

                # --- Save to Database ---
                try:
                    conn = get_db()
                    c = conn.cursor()
                    user_id = None
                    if user:
                        c.execute("SELECT id FROM users WHERE email=?", (user["email"],))
                        row = c.fetchone()
                        if row:
                            user_id = row["id"]

                    c.execute(
                        "INSERT INTO predictions (user_id, mode, fighter1, fighter2, result, confidence, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (user_id, "betting", fighter, stat, pick, confidence, datetime.now()),
                    )
                    conn.commit()
                    conn.close()
                except Exception as e:
                    print(f"[DB ERROR] Failed to log betting prediction: {e}")

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
        c.execute("SELECT id FROM users WHERE email=?", (user["email"],))
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
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT plan FROM users WHERE email=?", (user["email"],))
    row = c.fetchone()
    plan = row["plan"] if row else "free"
    conn.close()

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
# @limiter.exempt
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
    port = 8080
    if len(sys.argv) > 2 and sys.argv[1] == "--port":
        port = int(sys.argv[2])
    app.run(host="0.0.0.0", port=port, debug=True)
