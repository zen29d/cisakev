import requests
import csv
import os
from io import StringIO
from logger import init_logger

# CISA KEV API Endpoint
URL_CISA_KEV_CSV = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
URL_CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
STORAGE_LOCATION = "local"
FILENAME = "cisa_kev_seen.csv"
KEV_FILE = os.path.join(STORAGE_LOCATION,FILENAME)

# Initialize logging
LOG_DIR = "log"
LOG_FILE = "cisa_kev.log"
log = init_logger(LOG_DIR, LOG_FILE)
# log.basicConfig(filename=LOG_FILE, level=log.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def fetch_kev_data():
    try:
        response = requests.get(URL_CISA_KEV_CSV, timeout=10)
        if response.status_code == 200:
            csv_data = response.text
            return list(csv.DictReader(StringIO(csv_data)))
        else:
            log.warning(f"Unexpected response status: {response.status_code}")
    except requests.RequestException as E:
        log.error(f"Failed to fetch KEV data: {E}")
    except csv.Error as E:
        log.error(f"Error parsing CSV data: {E}")
    return []

def save_new_kevs(kevs):
    if not kevs:
        return

    try:
        with open(KEV_FILE, "w", newline="", encoding="utf-8") as file:
            fieldnames = kevs[0].keys()
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(kevs)
    except Exception as e:
        log.error(f"Error saving KEV data: {e}")

def download_kevs():
    try:
        os.makedirs(STORAGE_LOCATION, exist_ok=True)
    except Exception as e:
        log.error(f"Failed to create file location: {e}")

    log.info("Downloading CISA KEV Catalog")
    data = fetch_kev_data()
    save_new_kevs(data)
    log.info(f"🚀 Saved {len(data)} new KEVs in {KEV_FILE}")

def load_seen_kevs():
    if not os.path.exists(KEV_FILE):
        log.warning(f"File {KEV_FILE} doesn't exist")
        return []
    try:
        with open(KEV_FILE, "r", newline="", encoding="utf-8") as file:
            return list(csv.DictReader(file))
    except Exception as e:
        log.error(f"Error loading previous KEV data: {e}")
        return []



# Main function
def main():
    previous_kevs = load_seen_kevs()
    if not previous_kevs:
        download_kevs()
        return
    latest_kevs = fetch_kev_data()

    previous_cve_ids = {kev["cveID"] for kev in previous_kevs}
    new_kevs = [kev for kev in latest_kevs if kev["cveID"] not in previous_cve_ids]
    if new_kevs:
        log.info(f"🚀 Found {len(new_kevs)} new KEVs")
        save_new_kevs(latest_kevs)
    else:
        log.info("✅ No new KEVs detected")

if __name__ == "__main__":
    main()

