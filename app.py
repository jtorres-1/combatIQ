# app.py — CombatIQ Fight Predictor
from flask import Flask, render_template, request
from openai import OpenAI
import os, re
from dotenv import load_dotenv
from fighter_scraper import scrape_fighter_stats  # ← uses Tapology + GPT hybrid

# --- Load environment ---
load_dotenv()

# --- Init OpenAI ---
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    fighter1 = fighter2 = ""
    stats1 = stats2 = {}

    if request.method == "POST":
        matchup = request.form.get("matchup", "").strip()
        fighters = [p.strip() for p in re.split(r"vs|VS|Vs", matchup) if p.strip()]

        fighter1 = fighters[0] if len(fighters) > 0 else ""
        fighter2 = fighters[1] if len(fighters) > 1 else ""

        # --- scrape stats ---
        stats1 = scrape_fighter_stats(fighter1) if fighter1 else {}
        stats2 = scrape_fighter_stats(fighter2) if fighter2 else {}

        # --- build summary ---
        data_summary = (
            f"Fighter 1 - {fighter1}: {stats1}\n\n"
            f"Fighter 2 - {fighter2}: {stats2}\n\n"
            "If any fields are 'N/A', infer missing data from known performance history."
        )

        # --- GPT matchup analysis ---
        prompt = (
            f"Analyze the fight between {fighter1} and {fighter2}. "
            "Predict the most likely winner and explain using striking, grappling, fight IQ, and current form. "
            "Base it only on reliable fight data — no fantasy scenarios. "
            "Return a clean HTML response using <h3>, <h4>, <p>, and <strong> tags. "
            "Do NOT include code fences like ```html or ```.\n\n"
            f"{data_summary}"
        )

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

        # --- clean output ---
        raw_result = response.choices[0].message.content
        result = raw_result.replace("```html", "").replace("```", "").strip()

    # --- render ---
    return render_template(
        "index.html",
        result=result,
        fighter1=fighter1,
        fighter2=fighter2,
        stats1=stats1,
        stats2=stats2,
    )


if __name__ == "__main__":
    app.run(debug=True)
