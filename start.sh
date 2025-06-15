#!/usr/bin/env bash
set -euo pipefail

export FLASK_ENV=production
echo "🚀  Starting deployment script…"

###############################################################################
# 0. Sanity‑check required secrets
###############################################################################
if [[ -z "${ADMIN_EMAIL:-}" || -z "${ADMIN_PASSWORD:-}" ]]; then
  echo "❌  ADMIN_EMAIL and ADMIN_PASSWORD must be set" >&2
  exit 1
fi

###############################################################################
# 1. Ensure critical columns exist
###############################################################################
echo "🆘  Ensuring critical columns exist…"

python - <<'PY'
from sqlalchemy import create_engine, inspect, text
import os, sys

url = os.environ["DATABASE_URL"].replace("postgres://", "postgresql://", 1)
engine = create_engine(url, isolation_level="AUTOCOMMIT")

NEEDED = {
    "current_balance"     : "NUMERIC(12,2) DEFAULT 0.0",
    "top_up_balance"      : "NUMERIC(12,2) DEFAULT 0.0",
    "settlement_balance"  : "NUMERIC(12,2) DEFAULT 0.0",
    "settlement_type"     : "VARCHAR(50)",
    "settling_institution": "VARCHAR(255)",
    "settlement_reason"   : "TEXT",
    "parent_loan_id"      : "INTEGER",
}

with engine.connect() as c:
    cols = {c["name"] for c in inspect(c).get_columns("loan_applications")}
    for col, ddl in NEEDED.items():
        if col in cols:
            print(f" ✅ {col} ok")
        else:
            print(f" ➕ add {col}")
            try:
                c.execute(text(f'ALTER TABLE loan_applications ADD COLUMN {col} {ddl}'))
            except Exception as e:
                print(f"   ⚠️  {e}")
PY

echo "✅  Column check complete"

###############################################################################
# 2. Bring Alembic in‑sync with reality (no more duplicate‑table crashes)
###############################################################################
echo "🗄️  Reconciling Alembic version…"

REPO_HEAD=$(alembic heads | awk 'NR==1{print $1}')
echo "🔎  Repo head is $REPO_HEAD"

python - <<PY
import os, sys
from sqlalchemy import create_engine, inspect, text

url = os.environ["DATABASE_URL"].replace("postgres://", "postgresql://", 1)
e   = create_engine(url, isolation_level="AUTOCOMMIT")

with e.connect() as c:
    c.execute(text("""
      CREATE TABLE IF NOT EXISTS alembic_version (
        version_num VARCHAR(32) NOT NULL
      )
    """))

    current = c.execute(text("SELECT version_num FROM alembic_version LIMIT 1")).scalar()
    have_tables = 'customers' in inspect(c).get_table_names()

    if current == None and have_tables:
        # Production DB already has schema – fast‑forward
        c.execute(text("INSERT INTO alembic_version VALUES (:v)"), {'v': "$REPO_HEAD"})
        print("📌  Existing tables detected, stamped directly to HEAD")
        sys.exit(0)

    if current == "$REPO_HEAD":
        print("✅  DB already at head")
        sys.exit(0)

    if have_tables and current and current.startswith("0001"):
        # Old baseline but schema exists – bump straight to head
        c.execute(text("UPDATE alembic_version SET version_num=:v"), {'v': "$REPO_HEAD"})
        print("🪄  Baseline bumped to HEAD")
        sys.exit(0)

    # Otherwise run real upgrade
    sys.exit(1)
PY
NEEDS_UPGRADE=$?

if [[ $NEEDS_UPGRADE -eq 1 ]]; then
  echo "⏫  Running flask db upgrade…"
  flask db upgrade
  echo "✅  Alembic upgrade complete"
fi

###############################################################################
# 3. Seed roles / permissions
###############################################################################
echo "👥  Seeding RBAC data…"
python - <<'PY'
from app import app, initialize_roles_permissions
with app.app_context():
    initialize_roles_permissions()
    print("✅  RBAC initialised")
PY

###############################################################################
# 4. Ensure admin user exists
###############################################################################
echo "👑  Checking admin account…"
python - <<'PY'
from app import app, db, User
from werkzeug.security import generate_password_hash
import os, time
email, pwd = os.environ["ADMIN_EMAIL"], os.environ["ADMIN_PASSWORD"]

with app.app_context():
    u = User.query.filter_by(email=email).first()
    if u:
        print("✅  Admin present")
    else:
        uname = "admin"
        if User.query.filter_by(username=uname).first():
            uname = f"admin_{int(time.time())}"
        db.session.add(User(username=uname, email=email,
                            password_hash=generate_password_hash(pwd)))
        db.session.commit()
        print(f"✅  Created admin {email} ({uname})")
PY

###############################################################################
# 5. Launch Gunicorn
###############################################################################
echo "🚀  Launching Gunicorn…"
exec gunicorn --workers 4 --bind "0.0.0.0:${PORT:-8000}" app:app
