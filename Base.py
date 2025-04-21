import os

# Storage folder
STORAGE_LOCATION = "local"

# JSON catalog and DB path
CATALOG_FILENAME = "cisa_kev_catalog.json"
CATALOG_FILE = os.path.join(STORAGE_LOCATION, CATALOG_FILENAME)
SQLITE_DB = os.path.join(STORAGE_LOCATION, "kev_data.db")

# Logging config
LOG_DIR = "log"
LOG_FILENAME = "cisa_kev.log"
LOG_FILE = log_path = os.path.join(LOG_DIR, LOG_FILENAME)