from datetime import datetime

from Base import SQLITE_DB
from cisa_kev import fetch_catalog_data, save_catalog, download_catalog, load_seen_catalog, transform_catalog
import webhook_push as whook
import cisa_kev_db as kev_db

from logger import init_logger

log = init_logger()

def is_new_release(prev_date, latest_date):
    try:
        prev = datetime.fromisoformat(prev_date.replace("Z", "+00:00"))
        latest = datetime.fromisoformat(latest_date.replace("Z", "+00:00"))
        return latest > prev
    except Exception as E:
        log.error(f"Date comparison failed: {E}")
        return False

def check_new_kev():
    previous_props, previous_kevs = transform_catalog(load_seen_catalog())
    if not previous_kevs:
        download_catalog()
        return None

    latest_json = fetch_catalog_data()
    if not latest_json:
        log.warning("No KEV data fetched")
        return None

    latest_props, latest_kevs = transform_catalog(latest_json)

    if is_new_release(previous_props['dateReleased'], latest_props['dateReleased']):
        previous_ids = {kev["cveID"] for kev in previous_kevs}
        new_items = [kev for kev in latest_kevs if kev["cveID"] not in previous_ids]
        log.info(f"🚨 Found {len(new_items)} new KEVs")
        save_catalog(latest_json)
        kev_db.insert_kevs_to_db(SQLITE_DB, new_items)
        return new_items

    return []

def alert_new_kev():
    webhooks = whook.load_webhook()
    new_kevs = check_new_kev()
    if new_kevs is None:
        return
    elif new_kevs:
        whook.send_notification(new_kevs, webhooks)
    else:
        log.info(f"No new KEVs detected")

if __name__ == "__main__":
    alert_new_kev()