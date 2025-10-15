CombatIQ is an AI-powered fight prediction web app that simulates matchups between real UFC fighters — combining live fight data, Tapology + ESPN scraping, and GPT-4-powered analysis to deliver expert-level predictions and stylistic breakdowns.
⚡ Overview
CombatIQ bridges data and fight IQ.
It pulls fighter stats from verified sources (Tapology, ESPN, and a custom MMA API) and uses a fine-tuned GPT-4o model to predict outcomes, styles, and paths to victory.
Think of it as the AI fight analyst that never sleeps.
🧠 Core Features
✅ Real-Time Fighter Stats
Scrapes the latest records, reach, stance, height, and teams directly from Tapology + ESPN.
✅ AI Fight Predictions
Generates expert commentary and a probability-based outcome using GPT-4o-mini.
✅ Clean HTML Output
Delivers analysis formatted in <h3>, <p>, and <strong> tags for instant front-end rendering.
✅ Cross-Platform Ready
Runs locally via Flask or can be deployed to Render, Railway, or Hugging Face Spaces.
✅ Expandable Data Layer
Built to integrate with machine learning pipelines or betting simulation models later.
🧩 Tech Stack
Backend: Python, Flask
AI Engine: OpenAI GPT-4o-mini
Scrapers: Tapology, ESPN, MMA API (RapidAPI)
Frontend: HTML, CSS (Jinja templates)
Environment: .env with secure API key loading
⚙️ Setup
git clone https://github.com/jtorres-1/combatIQ.git
cd combatIQ
pip install -r requirements.txt
Then create a .env file:
OPENAI_API_KEY=your_openai_key
RAPIDAPI_KEY=your_rapidapi_key
Run locally:
python app.py
Visit:
http://127.0.0.1:5000
📊 Example Output
Input:
Ilia Topuria vs Max Holloway
Output:
<h3>Prediction</h3> <p><strong>Winner:</strong> Ilia Topuria (via decision)</p> <p>Topuria’s reach, power, and defensive grappling give him a statistical edge...</p>
🚧 Roadmap
 Add visual stat comparison (Chart.js)
 Integrate ML-based fight outcome probabilities
 Mobile UI (React + Flask API)
 Historical fight backtesting
 Betting simulator for testing strategies
💬 Credits
Created by Jesse Torres — a developer passionate about automation, combat sports, and machine intelligence.
Follow for upcoming releases and real-fight testing insights.
