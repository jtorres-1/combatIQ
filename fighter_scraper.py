# fighter_scraper.py — Hybrid MMA Stats Fetcher (MMA API + ESPN + Tapology + Local Cache)

import requests
import json
import os
import re
import argparse
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

RAPIDAPI_KEY = os.getenv("RAPIDAPI_KEY")
SEARCH_URL = "https://mma-api1.p.rapidapi.com/search"

HEADERS = {
    "x-rapidapi-key": RAPIDAPI_KEY,
    "x-rapidapi-host": "mma-api1.p.rapidapi.com"
}

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/117.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.google.com"
}

CACHE_DIR = "fighters_cache"
os.makedirs(CACHE_DIR, exist_ok=True)


# ------------------------------------------------------------
# ESPN SCRAPER
# ------------------------------------------------------------
def scrape_espn_stats(url):
    """Scrape fighter stats from ESPN fighter page"""
    print(f"[SCRAPE] Fetching detailed stats from ESPN: {url}")
    stats = {}
    try:
        resp = requests.get(url, headers=BROWSER_HEADERS, timeout=15)
        if resp.status_code != 200:
            print(f"[ERROR] ESPN page fetch failed: {resp.status_code}")
            return stats

        soup = BeautifulSoup(resp.text, "html.parser")

        # Record pattern like "17-0-0"
        record_tag = soup.find(string=re.compile(r"\d+-\d+(-\d+)?"))
        if record_tag:
            stats["record"] = record_tag.strip()

        # Fighter bio info (height, reach, stance, etc.)
        bio_section = soup.find("ul", class_=re.compile("AthleteHeader__Bio_List"))
        if bio_section:
            for li in bio_section.find_all("li"):
                label = li.find("span", class_=re.compile("AthleteHeader__Bio_Label"))
                value = li.find("span", class_=re.compile("AthleteHeader__Bio_Value"))
                if not label or not value:
                    continue

                key = label.text.strip().lower()
                val = value.text.strip()

                if "height" in key:
                    stats["height"] = val
                elif "weight" in key:
                    stats["weight"] = val
                elif "reach" in key:
                    stats["reach"] = val
                elif "stance" in key:
                    stats["stance"] = val
                elif "hometown" in key:
                    stats["hometown"] = val

        return stats

    except Exception as e:
        print(f"[EXCEPTION - ESPN SCRAPE] {e}")
        return stats


# ------------------------------------------------------------
# TAPOLOGY SCRAPER
# ------------------------------------------------------------
def scrape_tapology_stats(name):
    """Scrape fighter stats from Tapology (handles nested div structures, Oct 2025)"""
    print(f"[SCRAPE] Searching Tapology for {name}...")
    stats = {}
    try:
        search_url = f"https://www.tapology.com/search?term={name.replace(' ', '+')}"
        search_resp = requests.get(search_url, headers=BROWSER_HEADERS, timeout=15)

        if search_resp.status_code != 200:
            print(f"[ERROR] Tapology search failed: {search_resp.status_code}")
            return stats

        soup = BeautifulSoup(search_resp.text, "html.parser")
        fighter_link_tag = soup.select_one("a[href*='/fighters/']")
        if not fighter_link_tag:
            print("[ERROR] No Tapology fighter found.")
            return stats

        fighter_url = "https://www.tapology.com" + fighter_link_tag.get("href")
        print(f"[SCRAPE] Fetching fighter profile: {fighter_url}")

        profile_resp = requests.get(fighter_url, headers=BROWSER_HEADERS, timeout=15)
        if profile_resp.status_code != 200:
            print(f"[ERROR] Tapology profile fetch failed: {profile_resp.status_code}")
            return stats

        profile_soup = BeautifulSoup(profile_resp.text, "html.parser")

        # Scan every <strong> with next <span>
        for strong_tag in profile_soup.find_all("strong"):
            label = strong_tag.get_text(strip=True).lower().replace(":", "")
            next_span = strong_tag.find_next("span")
            if not next_span:
                continue
            value = next_span.get_text(strip=True)

            if "height" in label:
                stats["height"] = value
            elif "reach" in label:
                stats["reach"] = value
            elif "weight class" in label:
                stats["weight_class"] = value
            elif "last weigh" in label:
                stats["last_weigh_in"] = value
            elif "stance" in label:
                stats["stance"] = value
            elif "affiliation" in label or "team" in label:
                stats["team"] = value

        if not stats:
            print("[WARN] No fighter stats parsed from Tapology page — verify structure.")

        return stats

    except Exception as e:
        print(f"[EXCEPTION - TAPA SCRAPE] {e}")
        return stats


# ------------------------------------------------------------
# MAIN FETCHER WITH CACHE + FORCE REFRESH
# ------------------------------------------------------------
def scrape_fighter_stats(name: str, force_refresh: bool = False):
    """Fetch fighter data using MMA API, ESPN, and Tapology, with optional cache bypass."""
    cache_path = os.path.join(CACHE_DIR, f"{name.lower().replace(' ', '_')}.json")

    # 1️⃣ Handle force refresh
    if force_refresh and os.path.exists(cache_path):
        print(f"[REFRESH] Cache bypass active — removing {cache_path}")
        try:
            os.remove(cache_path)
        except Exception as e:
            print(f"[REFRESH ERROR] Could not remove cache: {e}")

    # 2️⃣ Check cache
    if os.path.exists(cache_path):
        print(f"[CACHE] Found cached data for {name}. Loading from cache.")
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[CACHE ERROR] Failed to read cache: {e}")

    # 3️⃣ Fetch fresh data
    try:
        print(f"[FETCH] Searching for {name} via MMA API...")
        search_resp = requests.get(SEARCH_URL, headers=HEADERS, params={"query": name}, timeout=15)

        if search_resp.status_code != 200:
            print(f"[ERROR] API call failed: {search_resp.status_code} {search_resp.text}")
            return None

        data = search_resp.json()
        if not data or "players" not in data or not data["players"]:
            print("[ERROR] No fighters found in response.")
            return None

        fighter = data["players"][0]
        print(f"[SUCCESS] Fighter found: {fighter.get('displayName')}")

        result = {
            "name": fighter.get("displayName", "N/A"),
            "fighterId": fighter.get("fighterId", "N/A"),
            "link": fighter.get("link", "N/A"),
            "image": fighter.get("image", None),
            "sport": fighter.get("sport", "N/A"),
        }

        # Merge ESPN stats
        result.update(scrape_espn_stats(result["link"]))

        # Merge Tapology stats
        result.update(scrape_tapology_stats(name))

        # 4️⃣ Save to cache
        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"[CACHE] Saved new data for {name} to {cache_path}")
        except Exception as e:
            print(f"[CACHE ERROR] Failed to write cache: {e}")

        return result

    except Exception as e:
        print(f"[EXCEPTION] {e}")
        return None


# ------------------------------------------------------------
# CLI ENTRY
# ------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hybrid MMA Fighter Stats Scraper")
    parser.add_argument("--fighter", required=True, help="Name of the fighter to fetch")
    parser.add_argument("--force-refresh", action="store_true", help="Bypass cache and fetch fresh data")
    args = parser.parse_args()

    data = scrape_fighter_stats(args.fighter, force_refresh=args.force_refresh)
    if data:
        print(json.dumps(data, indent=2))
    else:
        print("No fighter data found.")
