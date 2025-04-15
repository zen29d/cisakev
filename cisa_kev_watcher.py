from cisa_kev import *
from webhook_push import *
from logger import init_logger
from datetime import datetime

# Initialize logging
log = init_logger()


def is_new_release(prev_date, latest_date):
    try:
        prev = datetime.fromisoformat(prev_date.replace("Z", "+00:00"))
        latest = datetime.fromisoformat(latest_date.replace("Z", "+00:00"))
        is_new_flag = latest > prev
        return is_new_flag
    except Exception as E:
        log.error(f"Date comparison failed: {E}")
        return False


def check_new_kevs():
    previous_props, previous_kevs = transform_kevs(load_seen_kevs())
    if not previous_kevs:
        download_kevs()
        return None

    latest_props, latest_kevs = transform_kevs(fetch_kev_data())
    if not latest_kevs:
        log.warning("⚠️ No KEV data fetched")
        return None

    is_new = is_new_release(previous_props['dateReleased'], latest_props['dateReleased'])
    if is_new:
        download_kevs(is_update=True)
        previous_ids = {kev["cveID"] for kev in previous_kevs}
        new_items = [kev for kev in latest_kevs if kev["cveID"] not in previous_ids]
        return new_items

    return []


def main():
    webhooks = load_webhooks()
    new_kevs = check_new_kevs()
    if new_kevs is None:
        return
    elif new_kevs:
        log.info(f"🚨 Found {len(new_kevs)} new KEVs")
        send_notifications(new_kevs, webhooks)
    else:
        log.info("✅ No new KEVs detected")


if __name__ == "__main__":
    main()