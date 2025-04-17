import sqlite3
from logger import init_logger

log = init_logger()

# Schema definitions
SCHEMA_CVES = '''
CREATE TABLE IF NOT EXISTS catalog_kevs (
    cveID TEXT PRIMARY KEY,
    vendorProject TEXT,
    product TEXT,
    vulnerabilityName TEXT,
    dateAdded DATETIME,
    shortDescription TEXT,
    requiredAction TEXT,
    dueDate DATETIME,
    knownRansomwareCampaignUse TEXT,
    notes TEXT,
    cwes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
'''

SCHEMA_PROPERTIES = '''
CREATE TABLE IF NOT EXISTS catalog_properties (
    title TEXT,
    catalogVersion TEXT,
    dateReleased TEXT,
    count INT,
    catalog_hash TEXT
)
'''

def init_db(db_path):
    with sqlite3.connect(db_path) as con:
        cursor = con.cursor()
        cursor.execute(SCHEMA_CVES)
        cursor.execute(SCHEMA_PROPERTIES)
        con.commit()

def insert_kevs_to_db(db_path, kevs):
    with sqlite3.connect(db_path) as con:
        cursor = con.cursor()
        for kev in kevs:
            try:
                cursor.execute('''
                    INSERT OR IGNORE INTO catalog_kevs (
                        cveID, vendorProject, product, vulnerabilityName,
                        dateAdded, shortDescription, requiredAction, dueDate,
                        knownRansomwareCampaignUse, notes, cwes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    kev.get("cveID"),
                    kev.get("vendorProject"),
                    kev.get("product"),
                    kev.get("vulnerabilityName"),
                    kev.get("dateAdded"),
                    kev.get("shortDescription"),
                    kev.get("requiredAction"),
                    kev.get("dueDate"),
                    kev.get("knownRansomwareCampaignUse"),
                    kev.get("notes"),
                    ", ".join(kev.get("cwes", []))
                ))
            except Exception as e:
                log.debug(f"Error inserting KEV {kev.get('cveID')}: {e}")
        con.commit()
    return True

def insert_properties(db_path, properties):
    with sqlite3.connect(db_path) as con:
        cursor = con.cursor()
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO catalog_properties (
                    title, catalogVersion, dateReleased, count, catalog_hash
                ) VALUES (?, ?, ?, ?, ?)
            ''', (
                properties.get("title"),
                properties.get("catalogVersion"),
                properties.get("dateReleased"),
                properties.get("count"),
                properties.get("catalog_hash", "")
            ))
            con.commit()
        except Exception as e:
            log.error(f"Failed to update properties: {e}")
    return True

def load_kevs_from_db(db_path):
    with sqlite3.connect(db_path) as con:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM catalog_kevs")
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
    return [dict(zip(columns, row)) for row in rows]

def load_properties_from_db(db_path):
    with sqlite3.connect(db_path) as con:
        cursor = con.cursor()
        cursor.execute("SELECT * FROM catalog_properties")
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        meta = [dict(zip(columns, row)) for row in rows]
    return meta[0]