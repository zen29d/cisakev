from flask import Flask, redirect, url_for, request, render_template
import sqlite3
import os
import re
import sys
 
basedir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.join(basedir, ".."))

from cisakev import Base
 
app = Flask(__name__)
path = os.path.join("..",Base.DB_FILE)
 
def get_db_connection():
    print(Base.DB_FILE)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn
 
key_map = {
    "cve": "cveID",
    "vendor": "vendorProject",
    "product": "product",
    "vname": "vulnerabilityName",
    "dateadded": "dateAdded",
    "desc": "shortDescription",
    "action": "requiredAction",
    "duedate": "dueDate",
    "campaign": "knownRansomwareCampaignUse",
    "notes": "notes",
    "cwes": "cwes",
    "createdate": "created_at"
}
 
def convert_to_sql(query_str):
    base_sql = "SELECT * FROM catalog_kevs"  
    if not query_str.strip():
        return base_sql + ";", []
 
    tokens = re.findall(r'\(|\)|\w+:[^()\s]+|and|or', query_str, re.IGNORECASE)
    index = 0
 
    def parse_expression():
        nonlocal index
        expr = parse_term()
        while index < len(tokens) and tokens[index].lower() == 'or':
            index += 1
            right = parse_term()
            expr = ('OR', expr, right)
        return expr
 
    def parse_term():
        nonlocal index
        expr = parse_factor()
        while index < len(tokens) and tokens[index].lower() == 'and':
            index += 1
            right = parse_factor()
            expr = ('AND', expr, right)
        return expr
 
    def parse_factor():
        nonlocal index
        if index >= len(tokens):
            raise ValueError("Unexpected end of input")
 
        token = tokens[index]
 
        if token == '(':
            index += 1
            expr = parse_expression()
            if index >= len(tokens) or tokens[index] != ')':
                raise ValueError("Unmatched '('")
            index += 1
            return expr
        elif ':' in token:
            index += 1
            key, value = token.split(':', 1)
            key = key.strip().lower()
            value = value.strip()
            if key not in key_map:
                raise ValueError(f"Invalid key: '{key}'")
            return ('COND', key_map[key], value)
        else:
            raise ValueError(f"Unexpected token: '{token}'")
 
    def to_sql(node):
        if node[0] in ('AND', 'OR'):
            left_sql, left_params = to_sql(node[1])
            right_sql, right_params = to_sql(node[2])
            return f"({left_sql} {node[0]} {right_sql})", left_params + right_params
        elif node[0] == 'COND':
            column, value = node[1], node[2]
            if '..' in value:
                start, end = value.split('..', 1)
                return f"{column} BETWEEN ? AND ?", [start.strip(), end.strip()]
            elif '*' in value:
                return f"{column} LIKE ?", [value.replace('*', '%')]
            else:
                return f"{column} = ?", [value]
        else:
            raise ValueError("Invalid parse tree")
 
    try:
        tree = parse_expression()
        if index != len(tokens):
            raise ValueError("Unmatched parentheses or unexpected tokens")
        where_sql, parameters = to_sql(tree)
        return f"{base_sql} WHERE {where_sql}", parameters
    except ValueError as e:
        return f"Invalid query: {e}", []
 
@app.route('/')
def index():
    return redirect(url_for('home'))
 
@app.route('/home', methods = ['POST', 'GET'])
def home():
    sql_query = ""
    params = []
    error = ""
    results = []
    results_count = 0
    query_text = ""
 
    if request.method == 'POST':
        query_text = request.form.get('query', '')
        sql_query, params = convert_to_sql(query_text)
 
        if sql_query.startswith("Invalid query"):
            error = sql_query
        else:
            try:
                conn = get_db_connection()
                cursor = conn.execute(sql_query, params)
                results = cursor.fetchall()
                results_count = len(results)
                conn.close()
            except Exception as e:
                error = f"Database error: {str(e)}"
    else:
        try:
            conn = get_db_connection()
            cursor = conn.execute('SELECT * FROM catalog_kevs ORDER BY created_at DESC LIMIT 50')
            results = cursor.fetchall()
            conn.close()
        except Exception as e:
            error = f"Database error: {str(e)}"
 
    return render_template(
        'home.html',
        error=error,
        catalog_kevs=results,
        query_text=query_text,
        results_count=results_count
    )
 
if __name__ == '__main__':
    app.run(host='localhost', port=5005)