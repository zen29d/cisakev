import os
import sys
import requests

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import Base
from cisakev import logger

log  = logger.init_logger()


def load_webhook(webhook_file=Base.WEBHOOK_CONFIG_FILE):
    webhooks = {}    
    if not os.path.exists(webhook_file):
        log.warning(f"Webhook config file not found: {webhook_file}")
        print(f"Missing webhook configuration file. Create: {webhook_file}")
        print("format: appname:webhook_url")
        print("eg:")
        print("teams=https://your-teams-webhook-url")
        print("slack=https://your-slack-webhook-url")
        return webhooks
    
    with open(Base.WEBHOOK_CONFIG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line or "=" not in line or line.startswith("#"):
                continue  # Skip empty lines or malformed
            
            parts = line.split("=", 1)
            if len(parts) != 2:
                log.warning(f"Skipping malformed webhook entry: {line}")
                continue
            
            app, url = parts
            app, url = app.strip(), url.strip()

            if not url.startswith("http"):
                log.warning(f"Invalid webhook URL in config: {line}")
                continue
            
            webhooks[app] = url

    if not webhooks:
        log.warning("No valid webhook URLs found in configuration")

    return webhooks


def send_notification(new_kevs, webhooks):
    if not new_kevs:
        log.info("No new KEVs to notify")
        return
    
    message = "*🚨 New CISA KEVs Added! 🚨*\n\n" + "\n\n".join(
        f"*{kev['cveID']}*: {kev['vendorProject']} {kev['product']} - {kev['vulnerabilityName']}\n"
        f"*Description:* {kev['shortDescription']}\n"
        f"*Added:* {kev['dateAdded']}\n"
        f"*More Info:* {kev['notes']}"
        for kev in new_kevs
    )
    
    payload = {"text": message}
    
    for app, webhook in webhooks.items():            
        try:
            response = requests.post(webhook, json=payload)
            if response.status_code == 200:
                log.info(f"🔔 Notification sent successfully to {app}")
            else:
                log.warning(f"Failed to send notification to {app}: {response.status_code}")
        except requests.RequestException as E:
            log.error(f"Error sending notification to {app}: {E}")