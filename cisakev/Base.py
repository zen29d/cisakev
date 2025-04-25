import os

# Storage folder
LOCAL = "local"

# JSON catalog and DB path
CATALOG_FILENAME = "cisa_kev_catalog.json"
CATALOG_FILE = os.path.join(LOCAL, CATALOG_FILENAME)
DB_FILE = os.path.join(LOCAL, "kev_data.db")

# Logging config
LOG_DIR = "log"
LOG_FILENAME = "cisa_kev.log"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = log_path = os.path.join(LOG_DIR, LOG_FILENAME)