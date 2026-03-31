# =============================================================================
# SAST TEST FILE — SQL INJECTION PATTERNS (GENERAL)
# Purpose : Validate that your SAST tool detects common SQLi anti-patterns
# Usage   : Run your SAST scanner against this file; every function below
#           should trigger at least one finding.
# NOTE    : This file contains INTENTIONALLY VULNERABLE code for SAST testing.
#           Do NOT deploy or execute in any real environment.
# =============================================================================

import sqlite3
import os

DB_PATH = "test.db"

# ── CWE-89 ── String concatenation — most basic pattern ──────────────────────
def login_concat(username, password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # SAST SHOULD FLAG: direct string concatenation into SQL
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()


# ── CWE-89 ── f-string interpolation ─────────────────────────────────────────
def get_user_by_id(user_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # SAST SHOULD FLAG: f-string interpolation into SQL
    query = f"SELECT id, name, email FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()


# ── CWE-89 ── %-style string formatting ──────────────────────────────────────
def search_products(keyword):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # SAST SHOULD FLAG: %-style formatting into SQL
    query = "SELECT * FROM products WHERE name LIKE '%%%s%%'" % keyword
    cursor.execute(query)
    return cursor.fetchall()


# ── CWE-89 ── .format() interpolation ────────────────────────────────────────
def get_orders_by_status(status):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # SAST SHOULD FLAG: .format() interpolation into SQL
    query = "SELECT * FROM orders WHERE status = '{}'".format(status)
    cursor.execute(query)
    return cursor.fetchall()


# ── CWE-89 ── Dynamic ORDER BY (cannot use parameterised queries here) ────────
def get_sorted_users(order_column):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # SAST SHOULD FLAG: unsanitised column name injected into ORDER BY
    query = "SELECT * FROM users ORDER BY " + order_column
    cursor.execute(query)
    return cursor.fetchall()


# ── CWE-89 ── Stored procedure with concatenation ────────────────────────────
def call_stored_proc(dept_name):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # SAST SHOULD FLAG: concatenation into EXEC / CALL
    query = "EXEC get_employees_by_dept '" + dept_name + "'"
    cursor.execute(query)
    return cursor.fetchall()


# ── CWE-89 ── Second-order injection (value from DB reused unsafely) ──────────
def update_email_by_username(old_username):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # First query fetches a value that originated from user input
    cursor.execute("SELECT username FROM users WHERE id = 1")
    stored_username = cursor.fetchone()[0]          # tainted value from DB
    # SAST SHOULD FLAG: tainted DB value reused unsafely in new query
    query = "UPDATE users SET last_login = NOW() WHERE username = '" + stored_username + "'"
    cursor.execute(query)
    conn.commit()


# ── CWE-89 ── UNION-based probe pattern ──────────────────────────────────────
def get_item(item_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # SAST SHOULD FLAG: attacker could append UNION SELECT to extract schema
    query = "SELECT name, price FROM items WHERE id = " + str(item_id)
    cursor.execute(query)
    return cursor.fetchone()


# ── CWE-89 ── Blind boolean-based SQLi surface ───────────────────────────────
def check_user_exists(username):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # SAST SHOULD FLAG: boolean-based injection surface
    query = "SELECT COUNT(*) FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()[0] > 0


# ── CWE-89 ── Time-based blind SQLi surface ───────────────────────────────────
def get_record_delayed(record_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # SAST SHOULD FLAG: attacker can inject WAITFOR/pg_sleep style payloads
    query = "SELECT * FROM records WHERE id = " + record_id
    cursor.execute(query)
    return cursor.fetchone()


# ── SAFE REFERENCE ── Parameterised query (SAST should NOT flag this) ─────────
def safe_login(username, password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # SAFE: uses parameterised placeholder — no injection possible
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    return cursor.fetchone()


# ── SAFE REFERENCE ── Allow-list validation (SAST should NOT flag this) ───────
ALLOWED_COLUMNS = {"id", "name", "email", "created_at"}

def safe_sorted_users(order_column):
    if order_column not in ALLOWED_COLUMNS:
        raise ValueError("Invalid column name")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # SAFE: column name validated against allow-list before interpolation
    query = "SELECT * FROM users ORDER BY " + order_column
    cursor.execute(query)
    return cursor.fetchall()
