import os
import csv
import logging
import requests
from io import StringIO

# CISA KEV API Endpoint
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

# Path and Files
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE_FILE = os.path.join(SCRIPT_DIR, "data", "kev_seen.csv")
WEBHOOK_CONFIG_FILE = os.path.join(SCRIPT_DIR, "config", "webhook.conf")
LOG_FILE = os.path.join(SCRIPT_DIR, "logs", "cisa_kev.log")
ASSETS_FILE = os.path.join(SCRIPT_DIR, "config", "assets_blacklist.txt")

# Loging Setup
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def load_webhooks():
    webhooks = {}
    if not os.path.exists(WEBHOOK_CONFIG_FILE):
        logging.warning(f"Missing webhook config: {WEBHOOK_CONFIG_FILE}")
        print(f"Missing config. Create: {WEBHOOK_CONFIG_FILE} (format: appname=webhook_url)")
        return webhooks

    with open(WEBHOOK_CONFIG_FILE, encoding="utf-8") as f:
        for line in f:
            if "=" in line and not line.startswith("#"):
                app, url = map(str.strip, line.strip().split("=", 1))
                if url.startswith("http"):
                    webhooks[app] = url
                else:
                    logging.warning(f"Invalid webhook URL: {line.strip()}")
    return webhooks

def fetch_kev_data():
    try:
        response = requests.get(CISA_KEV_URL, timeout=10)
        response.raise_for_status()
        return list(csv.DictReader(StringIO(response.text)))
    except Exception as e:
        logging.error(f"Failed to fetch KEV data: {e}")
        return []

def load_previous_kevs():
    if not os.path.exists(STORAGE_FILE):
        return []
    try:
        with open(STORAGE_FILE, encoding="utf-8") as f:
            return list(csv.DictReader(f))
    except Exception as e:
        logging.error(f"Error loading previous KEVs: {e}")
        return []

def save_kevs(kevs):
    if not kevs:
        return
    try:
        os.makedirs(os.path.dirname(STORAGE_FILE), exist_ok=True)
        with open(STORAGE_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=kevs[0].keys())
            writer.writeheader()
            writer.writerows(kevs)
    except Exception as e:
        logging.error(f"Error saving KEVs: {e}")

def send_notifications(new_kevs, webhooks):
    if not new_kevs or not webhooks:
        return
    
    message = "*🚨 New CISA KEVs Added! 🚨*\n\n" + "\n\n".join(
        f"*{kev['cveID']}*: {kev['vendorProject']} {kev['product']} - {kev['vulnerabilityName']}\n"
        f"*Description:* {kev['shortDescription']}\n"
        f"*Added:* {kev['dateAdded']}\n"
        f"*More Info:* {kev['notes']}"
        for kev in new_kevs
    )

    payload = {"text": message}
    for app, url in webhooks.items():
        try:
            r = requests.post(url, json=payload, timeout=10)
            if r.status_code == 200:
                logging.info(f"Notification sent: {app}")
            else:
                logging.warning(f"Notification failed for {app}: {r.status_code}")
        except Exception as e:
            logging.error(f"Error sending notification to {app}: {e}")

def main():
    latest_kevs = fetch_kev_data()
    previous_kevs = load_previous_kevs()
    if not previous_kevs:
        save_kevs(latest_kevs)
        logging.info("Saved CISA KEVs Catalog")
        return
    webhooks = load_webhooks()

    previous_ids = {kev["cveID"] for kev in previous_kevs}
    new_kevs = [kev for kev in latest_kevs if kev["cveID"] not in previous_ids]

    if new_kevs:
        logging.info(f"Found {len(new_kevs)} new KEVs")
        send_notifications(new_kevs, webhooks)
        save_kevs(latest_kevs)
    else:
        logging.info("No new KEVs found")

if __name__ == "__main__":
    main()
