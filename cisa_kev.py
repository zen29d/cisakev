import requests
import json
import os
from logger import init_logger

# CISA KEV API Endpoint
URL_CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
STORAGE_LOCATION = "local"
FILENAME = "cisa_kevs_catalog.json"
KEV_FILE = os.path.join(STORAGE_LOCATION,FILENAME)

# Initialize logging
LOG_DIR = "log"
LOG_FILE = "cisa_kev.log"
log = init_logger(LOG_DIR, LOG_FILE)

def fetch_kev_data():
    try:
        response = requests.get(URL_CISA_KEV_JSON, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data
        else:
            log.warning(f"Unexpected response status: {response.status_code}")
    except requests.RequestException as E:
        log.error(f"Failed to fetch CISA KEV data: {E}")
    return None

def transform_kevs(json_data):
    properties = {}
    kev_rows = []
    if json_data:
        properties = {
            'title': json_data.get('title', ''),
            'catalogVersion': json_data.get('catalogVersion', ''),
            'dateReleased': json_data.get('dateReleased', ''),
            'count': json_data.get('count', '')
        }
        kevs = json_data.get('vulnerabilities',[])

        fields = list(kevs[0].keys())
        for item in kevs:
            row = {field: item.get(field, '') for field in fields}
            kev_rows.append(row)
        
    return [properties, kev_rows]


def save_kevs(json_data):
    try:
        with open(KEV_FILE, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)
    except Exception as E:
        log.error(f"Error saving KEV JSON data: {E}")


def download_kevs(is_update = False):
    try:
        os.makedirs(STORAGE_LOCATION, exist_ok=True)
    except Exception as E:
        log.error(f"❌ Failed to create storage directory: {E}")
        return

    action = "Updating" if is_update else "Downloading"
    log.info(f"{action} CISA KEV Catalog...")

    json_data = fetch_kev_data()
    if not json_data:
        log.warning("No KEV data fetched from CISA")
        return
    
    save_kevs(json_data)


def load_seen_kevs():
    if not os.path.exists(KEV_FILE):
        log.warning(f"File {KEV_FILE} doesn't exist")
        return []
    try:
        with open(KEV_FILE, "r", newline="", encoding="utf-8") as file:
            return json.load(file)
    except Exception as E:
        log.error(f"Error loading previous KEV data: {E}")
        return []


# Main Test function
def main():
    log.info(f"Test Start: {__name__}")
    download_kevs()
    log.info(f"Loading downloaded KEVs data from {KEV_FILE}")
    json_data = load_seen_kevs()
    properties, kevs = transform_kevs(json_data)
    print(properties)
    log.info(f"Test End: {__name__}")

if __name__ == "__main__":
    main()