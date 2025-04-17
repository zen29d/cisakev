import os
import requests
from logger import init_logger

log  = init_logger()

CONFIG_DIR = "config"
WEBHOOK_CONFIG_FILE = os.path.join(CONFIG_DIR, "webhook.conf")


def load_webhook():
    webhooks = {}
    os.makedirs(CONFIG_DIR, exist_ok=True)
    
    if not os.path.exists(WEBHOOK_CONFIG_FILE):
        log.warning(f"Webhook config file not found: {WEBHOOK_CONFIG_FILE}")
        print(f"Missing webhook configuration file. Create: {WEBHOOK_CONFIG_FILE}")
        print("format: appname:webhook_url")
        print("eg:")
        print("teams=https://your-teams-webhook-url")
        print("slack=https://your-slack-webhook-url")
        return webhooks
    
    with open(WEBHOOK_CONFIG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line or "=" not in line or line.startswith("#"):
                continue  # Skip empty lines or malformed entries or commented
            
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
    
    message = "*🚨 New CISA KEVs Added! 🚨*\n"
    for kev in new_kevs:
        message += f"  *{kev['cveID']}*: {kev['vendorProject']} - {kev['product']} ({kev['vulnerabilityName']})\n"
        message += f"  *Description:* {kev['shortDescription']}\n"
        message += f"  *Added:* {kev['dateAdded']}\n"
        message += f"  *More Info:* {kev['notes']}\n\n"
    
    payload = {"text": message}
    
    for app, webhook in webhooks.items():            
        try:
            response = requests.post(webhook, json=payload)
            if response.status_code == 200:
                log.info(f"🔔 Notification sent successfully to {app}")
            else:
                log.warning(f"Failed to send notification to {app}: {response.status_code}")
        except requests.RequestException as e:
            log.error(f"Error sending notification to {app}: {e}")