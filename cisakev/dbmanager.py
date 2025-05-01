import os
import sys
import sqlite3
import hashlib
from contextlib import contextmanager

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cisakev import logger
from cisakev.dbschema import schemas

log = logger.init_logger()


def db_exists(db_path):
    if os.path.exists(db_path):
        return True
    log.warning("DB does not exist at %s", db_path)
    return False


def init_db(db_path):
    try:
        with sqlite3.connect(db_path) as con:
            cursor = con.cursor()
            for schema in schemas:
                cursor.execute(schema)
            con.commit()
        log.info("Database initialized")
    except Exception as E:
        log.error(f"Failed to initialize DB: {E}")


@contextmanager
def db_connection(db_path):
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def insert_kevs_to_db(db_path, kevs):
    try:
        with db_connection(db_path) as con:
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
                except Exception as E:
                    log.debug(f"Error inserting KEV {kev.get('cveID')}: {E}")
        return True
    except Exception as E:
        log.error(f"Failed to insert KEVs: {E}")
        return False


def insert_properties(db_path, properties):
    try:
        with db_connection(db_path) as con:
            cursor = con.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO catalog_properties (
                    id, title, catalogVersion, dateReleased, count, catalog_hash, db_hash
                ) VALUES (1, ?, ?, ?, ?, ?, ?)
            ''', (
                properties.get("title"),
                properties.get("catalogVersion"),
                properties.get("dateReleased"),
                properties.get("count"),
                properties.get("catalog_hash", ""),
                properties.get("db_hash", "")
            ))
        return True
    except Exception as E:
        log.error(f"Failed to insert properties: {E}")
        return False


def load_kevs_from_db(db_path):
    if not db_exists(db_path):
        return []
    try:
        with db_connection(db_path) as con:
            cursor = con.cursor()
            cursor.execute("SELECT * FROM catalog_kevs")
            return [dict(row) for row in cursor.fetchall()]
    except Exception as E:
        log.error(f"Failed to load KEVs: {E}")
        return []


def load_properties_from_db(db_path):
    if not db_exists(db_path):
        return {}
    try:
        with db_connection(db_path) as con:
            cursor = con.cursor()
            cursor.execute("SELECT * FROM catalog_properties")
            rows = cursor.fetchall()
            return dict(rows[0]) if rows else {}
    except Exception as E:
        log.error(f"Failed to load properties: {E}")
        return {}


def get_db_catalog_ver(db_path):
    props = load_properties_from_db(db_path)
    return props.get('catalogVersion') if props else None


def get_db_kevs_hash(db_path):
    try:
        with db_connection(db_path) as con:
            cursor = con.cursor()
            cursor.execute("SELECT cveID FROM catalog_kevs ORDER BY cveID")
            data = ''.join(row[0] for row in cursor.fetchall())
            return hashlib.sha256(data.encode()).hexdigest()
    except Exception as E:
        log.error(f"Failed to hash DB content: {E}")
        return None
