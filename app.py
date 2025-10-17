# app.py — CombatIQ Fight Predictor (Launch-Ready MVP)
from flask import Flask, render_template, request
from openai import OpenAI
import os, re, json
from datetime import datetime
from dotenv import load_dotenv
from fighter_scraper import scrape_fighter_stats
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# --- Load environment ---
load_dotenv()

# --- Init Flask + Limiter ---
app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])  # rate limit by IP

# --- Init OpenAI ---
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# --- Cache directory for matchups ---
CACHE_DIR = "matchups_cache"
os.makedirs(CACHE_DIR, exist_ok=True)


@app.route("/", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def index():
    result = None
    fighter1 = fighter2 = ""
    stats1 = stats2 = {}

    if request.method == "POST":
        matchup = request.form.get("matchup", "").strip()
        force_refresh = "force_refresh" in request.form

        fighters = [p.strip() for p in re.split(r"vs|VS|Vs", matchup) if p.strip()]
        if len(fighters) < 2:
            return render_template("index.html", result="<p>Please enter matchup as 'Fighter A vs Fighter B'</p>")

        fighter1, fighter2 = fighters[0], fighters[1]

        # Create matchup cache key
        matchup_key = f"{fighter1.lower().replace(' ', '_')}_vs_{fighter2.lower().replace(' ', '_')}.json"
        cache_path = os.path.join(CACHE_DIR, matchup_key)

        # --- Log request ---
        with open("usage.log", "a") as log:
            log.write(f"{datetime.now()} | {request.remote_addr} | {matchup}\n")

        # --- Use cache if available ---
        if not force_refresh and os.path.exists(cache_path):
            print(f"[CACHE] Using existing GPT report for {matchup}")
            with open(cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return render_template(
                "index.html",
                result=data["result"],
                fighter1=data["fighter1"],
                fighter2=data["fighter2"],
                stats1=data["stats1"],
                stats2=data["stats2"],
            )

        # --- Scrape fighter stats ---
        print(f"[SCRAPE] Fetching stats for {fighter1} and {fighter2}")
        stats1 = scrape_fighter_stats(fighter1, force_refresh=force_refresh)
        stats2 = scrape_fighter_stats(fighter2, force_refresh=force_refresh)

        # --- Build summary for GPT ---
        data_summary = (
            f"Fighter 1 - {fighter1}: {stats1}\n\n"
            f"Fighter 2 - {fighter2}: {stats2}\n\n"
            "If any fields are 'N/A', infer missing data from known performance history."
        )

        prompt = (
            f"Analyze the fight between {fighter1} and {fighter2}. "
            "Predict the most likely winner and explain using striking, grappling, fight IQ, and current form. "
            "Base it only on reliable fight data — no fantasy scenarios. "
            "Return a clean HTML response using <h3>, <h4>, <p>, and <strong> tags. "
            "Do NOT include code fences like ```html or ```.\n\n"
            f"{data_summary}"
        )

        # --- GPT analysis ---
        try:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an elite MMA analyst for ESPN-level commentary. "
                            "Be objective, data-driven, and concise."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
            )
            raw_result = response.choices[0].message.content
            result = raw_result.replace("```html", "").replace("```", "").strip()

            # --- Save to matchup cache ---
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "fighter1": fighter1,
                        "fighter2": fighter2,
                        "stats1": stats1,
                        "stats2": stats2,
                        "result": result,
                    },
                    f,
                    indent=2,
                    ensure_ascii=False,
                )

        except Exception as e:
            result = f"<p>[ERROR] GPT request failed: {e}</p>"
            print(result)

    # --- Render ---
    return render_template(
        "index.html",
        result=result,
        fighter1=fighter1,
        fighter2=fighter2,
        stats1=stats1,
        stats2=stats2,
    )


if __name__ == "__main__":
    import sys

    # Default port
    port = 5050  # use 5050 locally (5000 blocked on macOS)
    # Allow override via CLI arg, e.g. python app.py --port 8080
    if len(sys.argv) > 2 and sys.argv[1] == "--port":
        port = int(sys.argv[2])

    app.run(host="0.0.0.0", port=port, debug=False)
