import os
import sqlite3
from logger import init_logger

# Initialize logging
log = init_logger()

# Data Schema
schema_cves = '''
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
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP )
    '''
schema_properties = '''
    CREATE TABLE IF NOT EXISTS catalog_properties (
        title TEXT,
        catalogVersion TEXT,
        dateReleased TEXT,
        count INT,
        catalog_hash TEXT)
    '''

# SQLite Functions
def init_db(SQLITE_DB):
    with sqlite3.connect(SQLITE_DB) as conn:
        cursor = conn.cursor()
        cursor.execute(schema_cves)
        cursor.execute(schema_properties)
        conn.commit()

def insert_kevs_to_db(SQLITE_DB,kevs):
    with sqlite3.connect(SQLITE_DB) as conn:
        cursor = conn.cursor()
        for kev in kevs:
            try:
                cursor.execute('''   
                    INSERT OR IGNORE INTO catalog_kevs (
                        cveID, vendorProject, product, vulnerabilityName, dateAdded,
                        shortDescription, requiredAction, dueDate,
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
                log.debug(f"Error inserting KEV {kev.get('cveID')} into DB: {e}")
        conn.commit()
        return True

def update_properties(SQLITE_DB, properties):
    with sqlite3.connect(SQLITE_DB) as conn:
        cursor = conn.cursor()
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
        except Exception as e:
                log.error(f"Error inserting {properties.get('catalogVersion')} into DB: {e}")
        conn.commit()
        return True


def load_kevs_from_db(SQLITE_DB):
    with sqlite3.connect(SQLITE_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM catalog_kevs")
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in rows]



