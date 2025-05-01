import os
import sys
import requests
import json
import hashlib

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import Base
from cisakev import logger
import cisakev.dbmanager as dbm

URL_CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

log = logger.init_logger()


def fetch_catalog_data(url=URL_CISA_KEV_JSON):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.json()
        else:
            log.warning(f"Unexpected response status: {response.status_code}")
    except requests.RequestException as E:
        log.error(f"Failed to fetch CISA KEV data: {E}")
    return None


def transform_catalog(json_data):
    properties = {}
    kev_rows = []
    if json_data:
        properties = {
            'title': json_data.get('title', ''),
            'catalogVersion': json_data.get('catalogVersion', ''),
            'dateReleased': json_data.get('dateReleased', ''),
            'count': json_data.get('count', '')
        }
        kevs = json_data.get('vulnerabilities', [])

        if kevs:
            fields = list(kevs[0].keys())
            for item in kevs:
                row = {field: item.get(field, '') for field in fields}
                kev_rows.append(row)

    return [properties, kev_rows]


def save_catalog(json_data, catalog_file=Base.CATALOG_FILE):
    try:
        with open(catalog_file, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)
    except Exception as E:
        log.error(f"Error saving KEV JSON data: {E}")


def load_seen_catalog(catalog_file=Base.CATALOG_FILE):
    if not os.path.exists(catalog_file):
        log.warning(f"File {catalog_file} doesn't exist")
        return []
    try:
        with open(catalog_file, "r", newline="", encoding="utf-8") as file:
            return json.load(file)
    except Exception as E:
        log.error(f"Error loading previous KEV data: {E}")
        return []


def get_file_catalog_ver():
    json_data = load_seen_catalog()
    if json_data:
        version = json_data.get('catalogVersion', '')
        return version
    return None


def get_file_hash(file):
    sha = hashlib.sha256()
    try:
        with open(file, "rb") as f:
            while chunk := f.read(8192):
                sha.update(chunk)
        return sha.hexdigest()
    except Exception as E:
        log.error(f"Failed to hash file {file}: {E}")
        return None


def download_catalog():
    try:
        os.makedirs(Base.LOCAL_DIR, exist_ok=True)
    except Exception as e:
        log.error(f"Failed to create storage directory: {e}")
        return

    json_data = fetch_catalog_data()
    if not json_data:
        log.warning("No KEV data fetched from CISA")
        return

    new_version = json_data.get("catalogVersion")
    if not new_version:
        log.warning("No catalogVersion found in KEV data.")
        return

    # Only init DB if it doesjmn't exist
    if not dbm.db_exists(Base.DB_FILE):
        dbm.init_db(Base.DB_FILE)

    file_version = get_file_catalog_ver()
    db_version = dbm.get_db_catalog_ver(Base.DB_FILE)

    # Check version matches
    if new_version == file_version and new_version == db_version:
        log.info(f"KEV data is already up-to-date (version: {new_version})")
        return

    log.info(f"Downloading CISA KEV Catalog (version: {new_version})...")

    save_catalog(json_data)
    props, kevs = transform_catalog(json_data)
    props['catalog_hash'] = get_file_hash(Base.CATALOG_FILE)
    dbm.insert_kevs_to_db(Base.DB_FILE, kevs)
    dbm.insert_properties(Base.DB_FILE, props)

    log.info(f"KEVs data written to DB (version: {new_version})")


def test_cisa_catalog():
    log.info(f"Test Start...")
    download_catalog()
    log.info(f"Loading KEVs data from {Base.CATALOG_FILE}")
    json_data = load_seen_catalog()
    properties, _ = transform_catalog(json_data)
    for key,value in properties.items():
        print(f"  {key}: {value}")
    log.info(f"Test End...")


if __name__ == "__main__":
    test_cisa_catalog()
