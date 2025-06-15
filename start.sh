#!/usr/bin/env bash
# --------------------------------------------------------------------------
#  Render start‑up script for Loan‑App
# --------------------------------------------------------------------------
set -eo pipefail            # stop on error, fail on pipeline errors
export FLASK_ENV=production
export FLASK_APP=app:app    # gunicorn entry‑point
echo "🚀  Starting deployment script…"

# --------------------------------------------------------------------------
# 0. Required secrets
# --------------------------------------------------------------------------
if [[ -z "${ADMIN_EMAIL:-}" || -z "${ADMIN_PASSWORD:-}" ]]; then
  echo "❌  ADMIN_EMAIL and ADMIN_PASSWORD must be set" >&2
  exit 1
fi

# --------------------------------------------------------------------------
# 1. Critical column checks / hot‑patches  (works on free tier)
# --------------------------------------------------------------------------
echo "🛠  Checking critical columns…"

python - <<'PY'
import os, psycopg2, sys

def ensure_columns(table, needed):
    cur.execute("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = %s
    """, (table,))
    present = {r[0] for r in cur.fetchall()}
    for col, ddl in needed.items():
        if col in present:
            print(f" ✅ {table}.{col} ok")
        else:
            print(f" ➕ adding {table}.{col}")
            try:
                cur.execute(f'ALTER TABLE {table} ADD COLUMN {col} {ddl}')
            except Exception as e:
                print(f"   ⚠️  could not add {table}.{col}: {e}")

url = os.environ["DATABASE_URL"].replace("postgres://", "postgresql://", 1)
conn = psycopg2.connect(url, sslmode="require")
conn.autocommit = True
cur  = conn.cursor()

ensure_columns("loan_applications", {
    "current_balance"     : "NUMERIC(12,2) DEFAULT 0.0",
    "top_up_balance"      : "NUMERIC(12,2) DEFAULT 0.0",
    "settlement_balance"  : "NUMERIC(12,2) DEFAULT 0.0",
    "settlement_type"     : "VARCHAR(50)",
    "settling_institution": "VARCHAR(255)",
    "settlement_reason"   : "TEXT",
    "parent_loan_id"      : "INTEGER"
})

# 🔥 NEW: add missing column that caused 500 error
ensure_columns("payment_allocations", {
    "settlement_interest" : "NUMERIC(12,2) DEFAULT 0.0"
})

cur.close()
conn.close()
PY
echo "✅  Column check complete"

# --------------------------------------------------------------------------
# 2. Reconcile Alembic version   (idempotent)
# --------------------------------------------------------------------------
echo "📚  Reconciling Alembic…"
HEAD_REV=$(alembic heads | awk 'NR==1{print $1}')
[[ -z "$HEAD_REV" ]] && { echo "❌  Could not read alembic heads"; exit 1; }

python - <<PY
import os
from sqlalchemy import create_engine, text
url = os.environ["DATABASE_URL"].replace("postgres://", "postgresql://", 1)
eng = create_engine(url, isolation_level="AUTOCOMMIT")
with eng.connect() as c:
    c.execute(text("""
        CREATE TABLE IF NOT EXISTS alembic_version (
            version_num VARCHAR(32) PRIMARY KEY
        )
    """))
    c.execute(text("DELETE FROM alembic_version"))
    c.execute(text("INSERT INTO alembic_version (version_num) VALUES (:v)"),
              {"v": "$HEAD_REV"})
    print(f"   → stamped DB to $HEAD_REV")
PY

# safe upgrade – will be a no‑op most of the time
if flask db upgrade; then
    echo "✅  Alembic up‑to‑date"
else
    echo "⚠️  Upgrade failed – stamping head and continuing"
    flask db stamp head
fi

# --------------------------------------------------------------------------
# 3. Seed RBAC + admin
# --------------------------------------------------------------------------
echo "👥  Seeding roles / permissions…"
python - <<'PY'
from app import app, initialize_roles_permissions
with app.app_context():
    initialize_roles_permissions()
    print("   → RBAC ok")
PY

echo "👑  Ensuring admin account…"
python - <<'PY'
import os, time
from werkzeug.security import generate_password_hash
from app import app, db, User
email    = os.environ["ADMIN_EMAIL"]
password = os.environ["ADMIN_PASSWORD"]

with app.app_context():
    admin = User.query.filter_by(email=email).first()
    if admin:
        print("   → admin exists")
    else:
        uname = "admin"
        if User.query.filter_by(username=uname).first():
            uname = f"admin_{int(time.time())}"
        db.session.add(User(username=uname,
                            email=email,
                            password_hash=generate_password_hash(password)))
        db.session.commit()
        print(f"   → created admin {email} ({uname})")
PY

# --------------------------------------------------------------------------
# 4. Launch Gunicorn
# --------------------------------------------------------------------------
echo "🚀  Launching Gunicorn…"
exec gunicorn --workers 4 --bind 0.0.0.0:${PORT:-8000} app:app
