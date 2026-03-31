# =============================================================================
# SAST TEST FILE — POSTGRES SQLi + HARDCODED SECRETS PATTERNS
# Purpose : Validate that your SAST tool detects:
#             1. SQLi patterns specific to PostgreSQL (psycopg2 / asyncpg)
#             2. Hardcoded credentials / secrets (CWE-798, CWE-259)
#             3. Cloud DB connection strings with embedded secrets
#             4. Secret leakage via env vars read unsafely
# Usage   : Run your SAST scanner against this file; every marked block
#           should produce a finding.
# NOTE    : INTENTIONALLY VULNERABLE — for SAST validation only.
#           Do NOT deploy, execute, or commit real secrets.
# =============================================================================

import psycopg2
import os
import asyncpg   # async postgres driver


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 1 — HARDCODED SECRETS (CWE-798 / CWE-259)                     ║
# ║  SAST should flag every assignment below as a secret exposure finding   ║
# ╚══════════════════════════════════════════════════════════════════════════╝

# SAST SHOULD FLAG: hardcoded Postgres password
DB_PASSWORD = "Sup3rS3cr3tP@ssw0rd!"

# SAST SHOULD FLAG: hardcoded DB username
DB_USER = "admin"

# SAST SHOULD FLAG: hardcoded cloud Postgres host (RDS / Cloud SQL / Supabase)
DB_HOST = "prod-postgres.cluster-abc123.us-east-1.rds.amazonaws.com"

# SAST SHOULD FLAG: hardcoded connection string with embedded credentials
DATABASE_URL = "postgresql://admin:Sup3rS3cr3tP@ssw0rd!@prod-postgres.cluster-abc123.us-east-1.rds.amazonaws.com:5432/appdb"

# SAST SHOULD FLAG: hardcoded API / service secret key
SECRET_KEY = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"   # GitHub PAT pattern

# SAST SHOULD FLAG: hardcoded AWS credentials
AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# SAST SHOULD FLAG: hardcoded JWT secret
JWT_SECRET = "my_very_secret_jwt_signing_key_do_not_share"

# SAST SHOULD FLAG: hardcoded Stripe secret key (recognisable prefix)
STRIPE_SECRET = "sk_live_51HqXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 2 — POSTGRES CONNECTION WITH HARDCODED CREDS                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def get_db_connection_hardcoded():
    # SAST SHOULD FLAG: password / user / host all hardcoded in call site
    conn = psycopg2.connect(
        host     = "prod-postgres.cluster-abc123.us-east-1.rds.amazonaws.com",
        port     = 5432,
        dbname   = "appdb",
        user     = "admin",
        password = "Sup3rS3cr3tP@ssw0rd!",
        sslmode  = "require"
    )
    return conn


def get_db_connection_from_hardcoded_url():
    # SAST SHOULD FLAG: DSN string literal contains embedded credentials
    conn = psycopg2.connect(
        "host=prod-postgres.cluster-abc123.us-east-1.rds.amazonaws.com "
        "port=5432 dbname=appdb user=admin password=Sup3rS3cr3tP@ssw0rd! sslmode=require"
    )
    return conn


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 3 — POSTGRES SQLi PATTERNS (CWE-89)                           ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def fetch_user_by_username(username):
    conn = get_db_connection_hardcoded()
    cursor = conn.cursor()
    # SAST SHOULD FLAG: f-string into psycopg2 execute — bypasses driver safety
    query = f"SELECT id, username, email, password_hash FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()


def fetch_user_by_id(user_id):
    conn = get_db_connection_hardcoded()
    cursor = conn.cursor()
    # SAST SHOULD FLAG: concatenation — exposes password_hash column
    query = "SELECT id, username, email, password_hash FROM users WHERE id = " + str(user_id)
    cursor.execute(query)
    return cursor.fetchone()


def search_users_by_email_domain(domain):
    conn = get_db_connection_hardcoded()
    cursor = conn.cursor()
    # SAST SHOULD FLAG: LIKE clause with interpolated domain — UNION probe possible
    query = "SELECT username, email FROM users WHERE email LIKE '%" + domain + "'"
    cursor.execute(query)
    return cursor.fetchall()


def get_user_roles(username):
    conn = get_db_connection_hardcoded()
    cursor = conn.cursor()
    # SAST SHOULD FLAG: JOIN across sensitive tables with injectable predicate
    query = (
        "SELECT u.username, r.role_name, r.permissions "
        "FROM users u JOIN roles r ON u.role_id = r.id "
        "WHERE u.username = '" + username + "'"
    )
    cursor.execute(query)
    return cursor.fetchall()


def admin_lookup_by_filter(filter_col, filter_val):
    conn = get_db_connection_hardcoded()
    cursor = conn.cursor()
    # SAST SHOULD FLAG: both column name AND value are injectable
    query = f"SELECT * FROM admin_users WHERE {filter_col} = '{filter_val}'"
    cursor.execute(query)
    return cursor.fetchall()


# ── Postgres-specific: pg_catalog / information_schema probe surface ──────────
def get_schema_info(table_name):
    conn = get_db_connection_hardcoded()
    cursor = conn.cursor()
    # SAST SHOULD FLAG: attacker can inject to query information_schema.columns
    query = (
        "SELECT column_name, data_type "
        "FROM information_schema.columns "
        "WHERE table_name = '" + table_name + "'"
    )
    cursor.execute(query)
    return cursor.fetchall()


# ── Postgres COPY TO — file exfiltration surface ──────────────────────────────
def export_table_to_csv(table_name, output_path):
    conn = get_db_connection_hardcoded()
    cursor = conn.cursor()
    # SAST SHOULD FLAG: COPY TO with injectable table_name — can exfiltrate files
    query = f"COPY {table_name} TO '{output_path}' CSV HEADER"
    cursor.execute(query)
    conn.commit()


# ── asyncpg variant ───────────────────────────────────────────────────────────
async def async_fetch_user(username):
    # SAST SHOULD FLAG: hardcoded DSN with credentials AND f-string SQLi
    conn = await asyncpg.connect(
        "postgresql://admin:Sup3rS3cr3tP@ssw0rd!@prod-postgres.cluster-abc123.us-east-1.rds.amazonaws.com/appdb"
    )
    # SAST SHOULD FLAG: asyncpg execute with f-string (not $1 placeholder)
    query = f"SELECT id, username, api_key FROM users WHERE username = '{username}'"
    row = await conn.fetchrow(query)
    return row


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 4 — SECRET LEAKAGE VIA LOGGING / PRINT                        ║
# ╚══════════════════════════════════════════════════════════════════════════╝

import logging
logger = logging.getLogger(__name__)

def authenticate_user(username, password):
    conn = get_db_connection_hardcoded()
    cursor = conn.cursor()
    # SAST SHOULD FLAG: password logged in plaintext
    logger.debug(f"Authenticating user={username} password={password}")
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    result = cursor.fetchone()
    if not result:
        # SAST SHOULD FLAG: failed auth attempt logs the attempted password
        print(f"[AUTH FAIL] username={username} attempted_password={password}")
    return result


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  SECTION 5 — SAFE REFERENCE IMPLEMENTATIONS                            ║
# ║  SAST should NOT flag these patterns                                    ║
# ╚══════════════════════════════════════════════════════════════════════════╝

def safe_get_db_connection():
    # SAFE: all credentials sourced from environment variables
    conn = psycopg2.connect(
        host     = os.environ["DB_HOST"],
        port     = int(os.environ.get("DB_PORT", "5432")),
        dbname   = os.environ["DB_NAME"],
        user     = os.environ["DB_USER"],
        password = os.environ["DB_PASSWORD"],
        sslmode  = "require"
    )
    return conn


def safe_fetch_user_by_username(username):
    conn = safe_get_db_connection()
    cursor = conn.cursor()
    # SAFE: psycopg2 %s placeholder — driver handles escaping
    query = "SELECT id, username, email FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    return cursor.fetchone()


def safe_fetch_user_by_id(user_id):
    conn = safe_get_db_connection()
    cursor = conn.cursor()
    # SAFE: parameterised with type-cast validation
    if not isinstance(user_id, int):
        raise TypeError("user_id must be an integer")
    query = "SELECT id, username, email FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()


async def safe_async_fetch_user(username):
    # SAFE: DSN from env var, query uses asyncpg $1 positional parameter
    conn = await asyncpg.connect(os.environ["DATABASE_URL"])
    row = await conn.fetchrow(
        "SELECT id, username FROM users WHERE username = $1",
        username
    )
    return row
