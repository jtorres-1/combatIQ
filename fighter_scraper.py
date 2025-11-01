# fighter_scraper.py — CombatIQ MMA Data Engine (UFCStats + Tapology + ESPN + Normalized Averages)
import requests, json, os, re, argparse, time
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/117.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9"
}

CACHE_DIR = "fighters_cache"
os.makedirs(CACHE_DIR, exist_ok=True)

REQUEST_TIMEOUT = 12
RETRY_DELAY = 2


def safe_get(url):
    """Wrapper for requests.get with retry and error handling."""
    for _ in range(2):
        try:
            resp = requests.get(url, headers=BROWSER_HEADERS, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                return resp
        except requests.RequestException:
            time.sleep(RETRY_DELAY)
    return None


# ------------------------------------------------------------
# TAPOLOGY SCRAPER
# ------------------------------------------------------------
def scrape_tapology(name):
    """Get weight class, team, and fighter image from Tapology."""
    print(f"[TAPOLOGY] Searching for {name}...")
    data = {}
    try:
        s_url = f"https://www.tapology.com/search?term={name.replace(' ', '+')}"
        resp = safe_get(s_url)
        if not resp:
            return data

        soup = BeautifulSoup(resp.text, "html.parser")
        link = soup.select_one("a[href*='/fighters/']")
        if not link:
            return data

        f_url = "https://www.tapology.com" + link["href"]
        prof = safe_get(f_url)
        if not prof:
            return data

        psoup = BeautifulSoup(prof.text, "html.parser")

        img_tag = psoup.select_one("img[src*='letterbox_images']")
        if img_tag and img_tag.get("src"):
            img_url = img_tag["src"]
            if not img_url.startswith("http"):
                img_url = "https://www.tapology.com" + img_url
            data["image"] = img_url

        for strong in psoup.find_all("strong"):
            lbl = strong.get_text(strip=True).lower().replace(":", "")
            val = strong.find_next("span")
            if not val:
                continue
            val = val.get_text(strip=True)
            if "weight class" in lbl:
                data["weight_class"] = val
            elif "affiliation" in lbl or "team" in lbl:
                data["team"] = val

        return data
    except Exception as e:
        print(f"[TAPOLOGY ERROR] {e}")
        return data


# ------------------------------------------------------------
# ESPN SCRAPER
# ------------------------------------------------------------
def scrape_espn(name):
    """Fetch bio details like height, weight, reach if available."""
    print(f"[ESPN] Searching {name}")
    bio = {}
    try:
        url = f"https://www.espn.com/mma/fighter/_/search/{name.replace(' ', '-')}"
        resp = safe_get(url)
        if not resp:
            return bio
        soup = BeautifulSoup(resp.text, "html.parser")
        bio_ul = soup.find("ul", class_=re.compile("AthleteHeader__Bio_List"))
        if not bio_ul:
            return bio
        for li in bio_ul.find_all("li"):
            key = li.find("span", class_=re.compile("Label"))
            val = li.find("span", class_=re.compile("Value"))
            if not key or not val:
                continue
            k = key.text.strip().lower()
            v = val.text.strip()
            if "height" in k:
                bio["height"] = v
            elif "weight" in k:
                bio["weight"] = v
            elif "reach" in k:
                bio["reach"] = v
            elif "stance" in k:
                bio["stance"] = v
        return bio
    except Exception as e:
        print(f"[ESPN ERROR] {e}")
        return bio


# ------------------------------------------------------------
# NORMALIZATION FUNCTION
# ------------------------------------------------------------
def normalize_stats(stats):
    """Clamp and scale fighter averages into realistic MMA ranges."""
    def clamp(val, low, high):
        try:
            return max(low, min(high, float(val)))
        except:
            return val

    if "avg_sig_strikes" in stats:
        val = float(stats["avg_sig_strikes"])
        if val > 50:
            val /= 20
        if val > 20:
            val /= 2
        stats["avg_sig_strikes"] = round(clamp(val, 0.5, 15.0), 2)

    if "avg_takedowns" in stats:
        val = float(stats["avg_takedowns"])
        if val > 10:
            val /= 4
        stats["avg_takedowns"] = round(clamp(val, 0, 5.0), 2)

    if "avg_submissions" in stats:
        val = float(stats["avg_submissions"])
        if val > 5:
            val /= 3
        stats["avg_submissions"] = round(clamp(val, 0, 3.0), 2)

    for key in ["striking_accuracy", "takedown_accuracy", "striking_defense", "takedown_defense"]:
        if key in stats:
            stats[key] = clamp(stats[key], 0, 100)

    return stats


# ------------------------------------------------------------
# UFCSTATS SCRAPER
# ------------------------------------------------------------
def scrape_ufcstats(name):
    """Scrape fighter profile, career stats, and per-fight data from UFCStats."""
    print(f"[UFCSTATS] Searching for {name}...")
    stats = {}
    try:
        last = name.split()[-1].lower()
        search_url = f"http://ufcstats.com/statistics/fighters/search?query={last}"
        r = safe_get(search_url)
        if not r:
            return stats

        soup = BeautifulSoup(r.text, "html.parser")
        fighter_link = soup.select_one("a[href*='/fighter-details/']")
        if not fighter_link:
            print("[UFCSTATS] No fighter found.")
            return stats

        fighter_url = fighter_link["href"]
        print(f"[UFCSTATS] Fetching profile: {fighter_url}")
        prof = safe_get(fighter_url)
        if not prof:
            return stats

        psoup = BeautifulSoup(prof.text, "html.parser")

        # Basic info
        for li in psoup.select("li.b-list__box-list-item.b-list__box-list-item_type_block"):
            t = li.get_text(" ", strip=True)
            if "Height:" in t:
                stats["height"] = t.split("Height:")[-1].strip()
            elif "Weight:" in t:
                stats["weight"] = t.split("Weight:")[-1].strip()
            elif "Reach:" in t:
                stats["reach"] = t.split("Reach:")[-1].strip()
            elif "Stance:" in t:
                stats["stance"] = t.split("Stance:")[-1].strip()
            elif "DOB:" in t:
                stats["dob"] = t.split("DOB:")[-1].strip()

        # Career statistics
        career_items = psoup.select(".b-list__info-box-left li, .b-list__info-box-right li")
        for li in career_items:
            label_el = li.select_one(".b-list__box-item-title")
            if not label_el:
                continue
            label = label_el.get_text(strip=True).replace(":", "")
            value_text = li.get_text(strip=True).replace(label_el.get_text(strip=True), "").strip()
            if not value_text:
                continue
            clean_label = label.lower()
            clean_value = value_text.replace("%", "").strip()
            try:
                clean_value = float(clean_value)
            except ValueError:
                pass
            if "slpm" in clean_label:
                stats["sig_strikes_per_min"] = clean_value
            elif "str. acc" in clean_label:
                stats["striking_accuracy"] = clean_value
            elif "sapm" in clean_label:
                stats["sig_strikes_absorbed_per_min"] = clean_value
            elif "str. def" in clean_label:
                stats["striking_defense"] = clean_value
            elif "td avg" in clean_label:
                stats["takedown_avg"] = clean_value
            elif "td acc" in clean_label:
                stats["takedown_accuracy"] = clean_value
            elif "td def" in clean_label:
                stats["takedown_defense"] = clean_value
            elif "sub. avg" in clean_label:
                stats["submissions_avg"] = clean_value

        # Fight-by-fight stats
        fights = psoup.select(
            "tr.b-fight-details__table-row.b-fight-details__table-row__hover.js-fight-details-click"
        )

        total_strikes = total_tds = total_subs = total_fights = 0
        for row in fights:
            cols = [c.get_text(strip=True) for c in row.find_all("td")]
            if len(cols) < 7 or not re.search(r"win|loss", cols[0], re.I):
                continue
            try:
                strikes = int(re.sub(r"\D", "", cols[3])) if re.search(r"\d", cols[3]) else 0
                tds = int(re.sub(r"\D", "", cols[4])) if re.search(r"\d", cols[4]) else 0
                subs = int(re.sub(r"\D", "", cols[5])) if re.search(r"\d", cols[5]) else 0
                if strikes + tds + subs == 0:
                    continue
                total_fights += 1
                total_strikes += strikes
                total_tds += tds
                total_subs += subs
            except Exception:
                continue

        if total_fights > 0:
            stats["avg_sig_strikes"] = round(total_strikes / total_fights, 2)
            stats["avg_takedowns"] = round(total_tds / total_fights, 2)
            stats["avg_submissions"] = round(total_subs / total_fights, 2)
        else:
            stats["avg_sig_strikes"] = stats.get("sig_strikes_per_min", 0)
            stats["avg_takedowns"] = stats.get("takedown_avg", 0)
            stats["avg_submissions"] = stats.get("submissions_avg", 0)

        return normalize_stats(stats)
    except Exception as e:
        print(f"[UFCSTATS ERROR] {e}")
        return stats


# ------------------------------------------------------------
# MASTER SCRAPER
# ------------------------------------------------------------
def scrape_fighter_stats(name: str, force_refresh: bool = False):
    cache_path = os.path.join(CACHE_DIR, f"{name.lower().replace(' ', '_')}.json")
    if force_refresh and os.path.exists(cache_path):
        os.remove(cache_path)
    if os.path.exists(cache_path):
        with open(cache_path, "r", encoding="utf-8") as f:
            return json.load(f)

    result = {"name": name, "source": []}
    for scraper, tag in [(scrape_ufcstats, "ufcstats"), (scrape_tapology, "tapology"), (scrape_espn, "espn")]:
        data = scraper(name)
        if data:
            result.update(data)
            result["source"].append(tag)

    if not result["source"]:
        result["partial"] = True

    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"[CACHE] Saved {name}")
    return result


# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CombatIQ Fighter Scraper")
    parser.add_argument("--fighter", required=True)
    parser.add_argument("--force-refresh", action="store_true")
    args = parser.parse_args()
    data = scrape_fighter_stats(args.fighter, force_refresh=args.force_refresh)
    print(json.dumps(data, indent=2))
