import sqlite3
import re
from tabulate import tabulate
from rich.table import Table
from rich.console import Console

console = Console()

DEFAULT_FIELDS = ["cveID", "vulnerabilityName", "dateAdded"]
DISP_FIELDS = ["CVE ID", "Vulnerability Name", "KEV Added Date"]

def query_kevs(SQLITE_DB, cve_id=None, vendor=None, since_date=None, until_date=None, limit=10):
    query = "SELECT * FROM catalog_kevs"
    conditions = []
    params = []

    if cve_id:
        conditions.append("UPPER(cveID) LIKE ?")
        params.append(f"%{cve_id.upper().strip()}%")

    if vendor:
        conditions.append("vendorProject LIKE ?")
        params.append(f"%{vendor}%")

    if since_date:
        conditions.append("dateAdded >= ?")
        params.append(since_date)

    if until_date:
        conditions.append("dateAdded <= ?")
        params.append(until_date)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY dateAdded DESC"

    if limit is not None:
        query += " LIMIT ?"
        params.append(limit)

    # print(f"Query: {query} \nParameters: {params}")   # Debug SQL Query 
    with sqlite3.connect(SQLITE_DB) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]


def convert_year(year_arg):
    if not year_arg:
        return None, None

    if re.fullmatch(r"\d{4}", year_arg):
        return f"{year_arg}-01-01", f"{year_arg}-12-31"
    elif re.fullmatch(r"(\d{4})-", year_arg):
        year = re.match(r"(\d{4})-", year_arg).group(1)
        return "1999-01-01", f"{year}-12-31"
    elif re.fullmatch(r"(\d{4})\+", year_arg):
        year = re.match(r"(\d{4})\+", year_arg).group(1)
        return f"{year}-01-01", None
    elif re.fullmatch(r"(\d{4})-(\d{4})", year_arg):
        match = re.match(r"(\d{4})-(\d{4})", year_arg)
        return f"{match.group(1)}-01-01", f"{match.group(2)}-12-31"
    return None, None


def convert_wildcard(string):
    if string:
        string = string.replace("*", "%")
    return string


# def pretty_print_kevs(kevs, fields):
#     if not kevs:
#         print("No KEVs found.")
#         return
#     table_data = [[kev.get(field, "") for field in fields] for kev in kevs]
#     print(tabulate(table_data, headers=fields, tablefmt="grid"))


def pretty_print_kevs(kevs, fields=DEFAULT_FIELDS):
    if not kevs:
        print("No KEVs found")
        return
    table = Table(show_header=True, header_style="bold magenta")
    for disp_field in DISP_FIELDS:
        table.add_column(disp_field)

    for kev in kevs:
        row = [str(kev.get(field, "")) for field in fields]
        table.add_row(*row)
    console.print(table)
