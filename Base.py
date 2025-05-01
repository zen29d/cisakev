import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Sub-directories
LOCAL_DIR = os.path.join(BASE_DIR, "local")
LOG_DIR = os.path.join(BASE_DIR, "log")
CONFIG_DIR = os.path.join(BASE_DIR, "config")

for subdir in [LOCAL_DIR, LOG_DIR, CONFIG_DIR]:
    os.makedirs(subdir, exist_ok=True)

# Filenames
CATALOG_FILENAME = "cisa_kev_catalog.json"
DB_FILENAME = "kev_data.db"
SIMPLE_KEV_FILENAME = "kev_seen.csv"
WEBHOOK_FILENAME = "webhook.conf"
ASSETS_FILENAME = "product_blacklist.txt"
LOG_FILENAME = "cisa_kev.log"
CWE_FILENAME = "cwes.csv"

# Full Paths
CATALOG_FILE = os.path.join(LOCAL_DIR, CATALOG_FILENAME)
DB_FILE = os.path.join(LOCAL_DIR, DB_FILENAME)
SIMPLE_KEV_FILE = os.path.join(LOCAL_DIR, SIMPLE_KEV_FILENAME)
WEBHOOK_CONFIG_FILE = os.path.join(CONFIG_DIR, WEBHOOK_FILENAME)
ASSETS_FILE = os.path.join(CONFIG_DIR, ASSETS_FILENAME)
LOG_FILE = os.path.join(LOG_DIR, LOG_FILENAME)
CWE_FILE = os.path.join(LOCAL_DIR, CWE_FILENAME)