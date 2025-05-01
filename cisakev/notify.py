import os
import sys
import time
import signal
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import Base
from cisakev import kev, whook, logger
from cisakev import dbmanager as dbm

log = logger.init_logger()


def is_new_release(prev_date, latest_date):
    try:
        prev = datetime.fromisoformat(prev_date.replace("Z", "+00:00"))
        latest = datetime.fromisoformat(latest_date.replace("Z", "+00:00"))
        return latest > prev
    except Exception as E:
        log.error(f"Date comparison failed: {E}")
        return False


def check_new_kev(db_file=Base.DB_FILE):
    previous_props, previous_kevs = kev.transform_catalog(kev.load_seen_catalog())
    if not previous_kevs:
        kev.download_catalog()
        return None

    latest_json = kev.fetch_catalog_data()
    if not latest_json:
        log.warning("No KEV data fetched")
        return None

    latest_props, latest_kevs = kev.transform_catalog(latest_json)

    if is_new_release(previous_props['dateReleased'], latest_props['dateReleased']):
        previous_ids = {kev["cveID"] for kev in previous_kevs}
        new_items = [kev for kev in latest_kevs if kev["cveID"] not in previous_ids]
        log.info(f"🚨 Found {len(new_items)} new KEVs")
        kev.save_catalog(latest_json)
        dbm.insert_kevs_to_db(db_file, new_items)
        dbm.insert_properties(db_file, latest_props)
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


def watcher(interval=3600):  # default hourly
    print(f"Starting CISA KEV watcher daemon with interval: {interval} seconds")
    running = True

    def signal_handler(sig, frame):
        nonlocal running
        print("\nStopping daemon...")
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    while running:
        try:
            alert_new_kev()
        except Exception as e:
            print(f"Error in alert_new_kev: {e}")
        if running:
            time.sleep(interval)

    print("Daemon stopped")
    sys.exit(0)


if __name__ == "__main__":
    alert_new_kev()