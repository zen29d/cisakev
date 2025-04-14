from cisa_kev import *
from webhook_push import *
from logger import init_logger

# Initialize logging
log = init_logger()


def main():
    previous_kevs = load_seen_kevs()
    if not previous_kevs:
        download_kevs()
        return
    latest_kevs = fetch_kev_data()
    webhooks = load_webhooks()

    previous_cve_ids = {kev["cveID"] for kev in previous_kevs}
    new_kevs = [kev for kev in latest_kevs if kev["cveID"] not in previous_cve_ids]
    
    if new_kevs:
        log.info(f"🚀 Found {len(new_kevs)} new KEVs")
        send_notifications(new_kevs, webhooks)
        save_new_kevs(latest_kevs)
    else:
        log.info("✅ No new KEVs detected")

if __name__ == "__main__":
    main()