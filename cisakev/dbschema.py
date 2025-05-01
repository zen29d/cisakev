# All schema definitions in Database

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
    id INTEGER PRIMARY KEY CHECK (id = 1),
    title TEXT,
    catalogVersion TEXT,
    dateReleased TEXT,
    count INT,
    catalog_hash TEXT,
    db_hash TEXT
)
'''

SCHEMA_CWES = '''
CREATE TABLE IF NOT EXISTS cwe_mapping (
    cweID TEXT PRIMARY KEY,
    cweName Text
)
'''

SCHEMA_WIKI = '''
CREATE TABLE IF NOT EXISTS cve_wiki (
    cveID TEXT PRIMARY KEY,
    cvss_score INT,
    epss_score INT,
    attack_vector TEXT,
    explain_ref TEXT,
    article_ref TEXT,
    impacted_ver TEXT,
    tags TEXT,
    last_updated TEXT
)
'''

SCHEMA_XDB = '''
CREATE TABLE IF NOT EXISTS cve_xdb (
    cveID TEXT PRIMARY KEY,
    exploit_ref TEXT,
    platform TEXT,
    api_ref TEXT,
    malware TEXT,
    comment TEXT,
    tags TEXT,
    last_updated TEXT
)
'''

SCHEMA_APP_BLOCK = '''
CREATE TABLE IF NOT EXISTS catalog_properties (
    cveID TEXT PRIMARY KEY,
    api_ref TEXT,
    app_path TEXT,
    exp_file TEXT,
    tags TEXT,
    last_updated TEXT
)
'''

schemas = [SCHEMA_CVES, SCHEMA_PROPERTIES, SCHEMA_CWES, SCHEMA_WIKI, SCHEMA_XDB, SCHEMA_APP_BLOCK]
